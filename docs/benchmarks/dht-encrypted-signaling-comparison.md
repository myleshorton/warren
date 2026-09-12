# End-to-end encrypted signaling: measured results

Offers and answers now encrypt candidate payloads end to end, including when cold
or recovery RPCs travel in signed cleartext envelopes. DHT coordinators continue
verifying signatures and routing metadata without receiving the plaintext.

## Reproduce

```sh
cargo run --release -p dht-next --example compare_dht -- 100 > docs/benchmarks/dht-encrypted-signaling-comparison.csv
```

[Raw results](dht-encrypted-signaling-comparison.csv) ·
[Harness](../../crates/dht-next/examples/compare_dht.rs) ·
[Prior peer-session phase](dht-session-comparison.md) ·
[Protocol and limitations](../dht-next.md#signaling-flow)

The unchanged 100-seed harness produces 2,200 runs across both Warren cores. All
legacy network measurements reproduce the prior phase. Every replacement trial
preserves its prior success/failure, latency, packet count, and discovery time.
A separate seed-zero run reproduces all 22 rows’ network metrics. Cryptographic
keys/ciphertext use OS randomness; host execution time is not a deterministic metric.

## Paired signaling results

P50 is calculated over successful operations; mean bytes include all attempts.
Both phases have identical success counts and latency on these trials.

| Scenario | Success (both) | P50 ms | Before mean bytes | Encrypted mean bytes | Increase |
| --- | ---: | ---: | ---: | ---: | ---: |
| healthy_40ms | 100/100 | 200 | 3,522 | 3,874 | 10.0% |
| wan_200ms | 100/100 | 1,000 | 3,522 | 3,874 | 10.0% |
| slow_800ms | 100/100 | 4,000 | 6,532 | 7,140 | 9.3% |
| loss_10pct | 100/100 | 400 | 4,159 | 4,583 | 10.2% |
| loss_30pct | 70/100 | 1,900 | 5,089 | 5,609 | 10.2% |

## Interpretation and limits

- Each provider record adds a signed 32-byte signaling public key. Each offer and
  answer adds 48 bytes for Noise NK. No extra handshake round trip is introduced.
- Lookup-only trials contain no provider records and remain byte-for-byte equal
  in their aggregate traffic totals. Provider discovery responses with records
  are larger; the signaling workload includes that cost.
- Setup/registration costs are excluded, as in the previous reports. Packet loss
  is independent of length, and CPU/queueing costs are not isolated.
- The benchmark compares two Warren implementations on small simulated networks.
  It does not establish parity with actual HyperDHT or libtorrent implementations.
- Encryption hides candidate payloads, not identities, routing metadata, lengths,
  or timing. Initial offers lack forward secrecy against later compromise of the
  provider’s process-lifetime signaling key. Rotation and security review remain.
