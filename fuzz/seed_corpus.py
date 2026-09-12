"""Seed fuzzers from protocol vectors and lifecycle regressions; corpora stay local."""
import ast
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for vector in (root / 'crates/dht-next/tests/vectors').glob('*.hex'):
    packet = bytes.fromhex(vector.read_text())
    target = root / 'fuzz/corpus/packet' / vector.stem
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(packet)
    if vector.name.startswith('v6'):
        # Fixed signed header ends with the exchange length at byte 142.
        target = root / 'fuzz/corpus/signed-body' / vector.stem
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(packet[143 + packet[142]:-64])

for regression in (root / 'fuzz/regressions').glob('*.hex'):
    target = root / 'fuzz/corpus/signed-body' / regression.stem
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(bytes.fromhex(regression.read_text()))

lifecycle = root / 'fuzz/corpus/lifecycle'
lifecycle.mkdir(parents=True, exist_ok=True)
for regression in (root / 'crates/dht-next/tests/lifecycle').glob('*.hex'):
    (lifecycle / regression.stem).write_bytes(bytes.fromhex(regression.read_text()))
for offset in range(16):
    (lifecycle / f'matrix-{offset}').write_bytes(bytes(
        value for i in range(32)
        for value in ((i + offset) % 256, i % 4, (i * 17) % 256, 7)
    ))
regressions = root / 'crates/dht-next/proptest-regressions/testing/lifecycle.txt'
for line in regressions.read_text().splitlines():
    if line.startswith('cc ') and 'input = ' in line:
        seed = line.split()[1]
        values = ast.literal_eval(line.split('input = ', 1)[1])
        (lifecycle / f'regression-{seed}').write_bytes(bytes(values))
