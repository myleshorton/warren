"""Seed both fuzzers from checked-in protocol vectors; generated corpora stay local."""
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
