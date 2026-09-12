# Compact peer sessions: measured results

Compact Noise transport reduces warm RPC overhead while preserving independently signed
provider records and DHT-forwarded offers/answers. A warm Probe falls from 207 to 119
bytes (42.5%). Healthy signaling uses 19.9% fewer bytes; cold-heavy lookup uses 8.7%
more bytes because its one-shot peers pay for ephemeral key exchange. This phase is
a tradeoff, not a uniform performance improvement.

## Historical snapshot

These measurements precede end-to-end signaling encryption. The current harness
includes that next phase and produces different signaling byte counts. See the
[encrypted-signaling report](dht-encrypted-signaling-comparison.md).

## Original command

```sh
cargo run --release -p dht-next --example compare_core -- 100 > docs/benchmarks/dht-session-comparison.csv
```

[Harness](../../crates/dht-next/examples/compare_core.rs) ·
[Raw results](dht-session-comparison.csv) ·
[Prior phase](dht-adaptive-comparison.md) ·
[Protocol and limitations](../dht-next.md#compact-peer-sessions)

The same 100 seeds and 11 workload/scenario combinations produce 2,200 runs across
both Warren implementations. Every legacy network metric exactly matches the prior
phase. For the replacement, every trial preserves success/failure, elapsed time,
packet count, and provider-discovery time; only bytes and host execution time change.
A separate seed-zero rerun reproduces all 22 rows’ network metrics. Noise ephemeral
keys use fresh OS randomness, so ciphertext bytes themselves are not deterministic.
Host execution time includes simulator overhead and is excluded from these claims.

Topology, loss model, setup, and measurement definitions are unchanged. Setup is
excluded: initial contacts have warm sessions, while newly discovered contacts are
cold. These are small simulated Warren networks, not measurements of HyperDHT,
libtorrent, public-network scale, or real NAT traversal. Packet loss is independent
of length; bandwidth/queueing effects of larger packets are not modeled.

## Paired results

P50/P95 are for successful operations only; bytes are means across all attempts.
Success counts and latency are identical before and after on these trials.

| Workload | Scenario | Success (both) | P50 ms | P95 ms | Before mean bytes | After mean bytes | Change |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| lookup | healthy_40ms | 100/100 | 520 | 600 | 20,538 | 22,322 | +8.7% |
| signaling | healthy_40ms | 100/100 | 200 | 200 | 4,398 | 3,522 | -19.9% |
| lookup | wan_200ms | 100/100 | 2,600 | 3,000 | 20,538 | 22,322 | +8.7% |
| signaling | wan_200ms | 100/100 | 1,000 | 1,000 | 4,398 | 3,522 | -19.9% |
| lookup | slow_800ms | 100/100 | 8,700 | 8,700 | 32,422 | 34,496 | +6.4% |
| signaling | slow_800ms | 100/100 | 4,000 | 4,000 | 8,044 | 6,532 | -18.8% |
| lookup | loss_10pct | 100/100 | 2,180 | 4,600 | 24,204 | 26,348 | +8.9% |
| signaling | loss_10pct | 100/100 | 400 | 2,200 | 5,118 | 4,159 | -18.7% |
| lookup | loss_30pct | 83/100 | 8,520 | 12,600 | 34,754 | 38,045 | +9.5% |
| signaling | loss_30pct | 70/100 | 1,900 | 6,000 | 5,930 | 5,089 | -14.2% |
| lookup | dead_30pct | 86/100 | 8,280 | 8,780 | 21,000 | 22,996 | +9.5% |

## What changed and what remains

- The two-message Noise exchange rides inside existing signed RPCs. It introduces
  no extra handshake round trip, but adds bytes to cold exchanges.
- Confirmed sessions use a compact encrypted envelope, directional counters, a
  bounded replay window, endpoint binding, and five-minute monotonic expiry.
- The responder waits for proof that the initiator obtained the new keys before
  choosing them for outbound traffic. A lost handshake reply preserves the existing
  confirmed session; a regression test covers this ordering requirement.
- RPC retries preserve the operation nonce and use fresh transport counters.
  Cached results prevent duplicate effects; signed handshake replies are replayed
  exactly. A bounded signed-handshake retry recovers a restarted peer.
- Encryption is opportunistic and hop-by-hop. Cold RPCs, cookie-refresh retries,
  and recovery may be signed cleartext; coordinators can read signaling payloads.
  Mandatory encryption and end-to-end encrypted signaling are unfinished.
- The next measurement should include repeated lookups and explicit cold-start
  costs to establish when session setup amortizes. Authentication CPU savings have
  not been isolated here.
