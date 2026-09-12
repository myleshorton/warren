"""Run the three isolated implementations sequentially after building/installing."""
import argparse
import csv
import io
import json
import os
import datetime
import hashlib
import platform
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--trials', type=int, default=12, choices=range(1, 17))
parser.add_argument('--controlled', action='store_true')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
commands = {
    'warren': [str(root / 'target/release/examples/compare_dht')],
    'hyperdht': ['node', str(root / 'tools/dht-compare/hyperdht.mjs')],
    'libtorrent': [str(root / 'tools/dht-compare/.venv/bin/python'), str(root / 'tools/dht-compare/libtorrent_bench.py')],
}
if args.controlled:
    commands = {
        'warren-shared-3': commands['warren'],
        'warren-shared': commands['warren'],
        'warren-dedicated': commands['warren'],
        'hyperdht-dedicated': ['node', str(root / 'tools/dht-compare/hyperdht_controlled.mjs')],
        'libtorrent': commands['libtorrent'],
    }
metadata = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'controlled': args.controlled, 'platform': platform.platform(), 'machine': platform.machine(), 'trials': args.trials, 'commands': []}
sources = {Path(__file__).resolve(), root / 'Cargo.toml', root / 'Cargo.lock'}
for manifest in (root / 'crates').glob('*/Cargo.toml'):
    sources.add(manifest)
    sources.update(manifest.parent.rglob('*.rs'))
for name in ('hyperdht.mjs', 'hyperdht_controlled.mjs', 'libtorrent_bench.py',
             'package.json', 'package-lock.json', 'requirements.txt'):
    sources.add(root / 'tools/dht-compare' / name)
metadata['source_sha256'] = {
    str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(sources)
}
metadata['runtime_versions'] = {
    'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
    'node': subprocess.check_output(['node', '--version'], text=True).strip(),
    'libtorrent': subprocess.check_output(
        [str(root / 'tools/dht-compare/.venv/bin/python'), '-c',
         'import libtorrent; print(libtorrent.__version__)'], text=True).strip(),
}
metadata['warren_binary_sha256'] = hashlib.sha256((root / 'target/release/examples/compare_dht').read_bytes()).hexdigest()
args.output.parent.mkdir(parents=True, exist_ok=True)
with args.output.open('w') as output:
    writer = None
    for nodes in ((9, 33) if args.controlled else (8, 32)):
        for backend, command in commands.items():
            argv = command + [str(nodes), str(args.trials)]
            print(f'Running {backend}, {nodes} routing nodes', file=sys.stderr, flush=True)
            env = os.environ.copy()
            for key in ('DHT_CONTROLLED', 'DHT_REPLICAS', 'DHT_DEDICATED'):
                env.pop(key, None)
            overrides = {}
            if args.controlled:
                overrides = {'DHT_CONTROLLED': '1', 'DHT_REPLICAS': '3' if backend.endswith('-3') else '8'}
                if backend == 'warren-dedicated':
                    overrides['DHT_DEDICATED'] = '1'
            env.update(overrides)
            metadata['commands'].append({'argv': argv, 'env': overrides})
            result = subprocess.run(argv, env=env, cwd=root, capture_output=True, text=True, timeout=180)
            if result.returncode:
                print(result.stdout, file=sys.stderr)
                print(result.stderr, file=sys.stderr)
                result.check_returncode()
            reader = csv.DictReader(io.StringIO(result.stdout))
            rows = list(reader)
            if len(rows) != args.trials * (3 if args.controlled else 2) or any(row['success'] != 'true' for row in rows):
                raise RuntimeError(f'{backend} incomplete or unsuccessful: {result.stdout}')
            if args.controlled:
                expected = '3' if backend.endswith('-3') else '8'
                for row in rows:
                    if row['operation'] == 'immutable_put' and row['replica_contacts'] != expected:
                        raise RuntimeError(f'{backend}: unexpected replica count: {row}')
                    row['backend'] = backend
            if writer is None:
                writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
                writer.writeheader()
            writer.writerows(rows)
            output.flush()
args.output.with_suffix('.json').write_text(json.dumps(metadata, indent=2) + '\n')
