# Adaptive timing and reusable validation: measured results

The first performance phase adds explicit monotonic timing, smoothed RTT/variation,
exponential retry backoff, bounded speculative queries, and reusable endpoint-bound
address-validation grants. It preserves DHT-based offer/answer signaling, ownership
signatures, and per-request replay protection. Datagram signatures are still used;
this phase does **not** implement symmetric encrypted peer sessions, routing-ID
separation, or automatic coordinator failover.

## Historical snapshot

These results precede compact peer sessions. The current harness includes that newer
phase, so the command below now produces different replacement-core measurements.
See the [peer-session comparison](dht-session-comparison.md) for current results.

## Original command

```sh
cargo run --release -p dht-next --example compare_dht -- 100 > docs/benchmarks/dht-adaptive-comparison.csv
```

[Harness](../../crates/dht-next/examples/compare_dht.rs) ·
[Raw results](dht-adaptive-comparison.csv) ·
[Original baseline](dht-comparison.md)

100 seeds per scenario produce 2,200 runs across both cores. The first 20 seeds
match the original sample; the remaining 80 were not used for the initial tuning.
The unchanged legacy control reproduces every original network metric on those
first 20 seeds. Host execution time is excluded from this equality check.

Topology, targets, packet-loss model, and measurement definitions follow the original
report. The replacement now receives `Time::new(simulated_ms, unix_seconds)` and
10 ms scheduler ticks, rather than whole-second ticks. Its peer-grant cache is warm
for setup contacts, but newly discovered peers still need initial validation. Cached
grants expire after 30 seconds. No network-wide bootstrap or registration costs are
included. These are modest simulated networks, not measurements of libtorrent,
HyperDHT, a large public DHT, or real NAT traversal.

P50 and P95 are for **successful operations only**; bytes are mean datagram bytes
across **all attempts**. Always read success counts alongside latency.

## Paired change on the original 20 seeds

| Workload | Scenario | Before success | After success | Before P50 ms | After P50 ms | Before mean bytes | After mean bytes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| lookup | healthy_40ms | 20/20 | 20/20 | 560 | 520 | 21,472 | 20,580 |
| signaling | healthy_40ms | 20/20 | 20/20 | 320 | 200 | 6,219 | 4,398 |
| lookup | wan_200ms | 20/20 | 20/20 | 2,800 | 2,600 | 23,556 | 20,580 |
| signaling | wan_200ms | 20/20 | 20/20 | 1,600 | 1,000 | 6,819 | 4,398 |
| lookup | slow_800ms | 20/20 | 20/20 | 11,200 | 8,700 | 36,762 | 32,347 |
| signaling | slow_800ms | 20/20 | 20/20 | 6,400 | 4,000 | 10,792 | 8,044 |
| lookup | loss_10pct | 20/20 | 20/20 | 4,020 | 2,110 | 24,909 | 23,973 |
| signaling | loss_10pct | 19/20 | 20/20 | 2,080 | 400 | 7,278 | 5,285 |
| lookup | loss_30pct | 16/20 | 16/20 | 16,080 | 8,700 | 35,335 | 34,418 |
| signaling | loss_30pct | 10/20 | 15/20 | 5,580 | 2,300 | 6,600 | 5,956 |
| lookup | dead_30pct | 17/20 | 17/20 | 12,000 | 8,280 | 21,937 | 21,216 |

## Full 100-seed comparison

| Workload | Scenario | Core | Success | P50 ms | P95 ms | Mean bytes |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| lookup | healthy_40ms | legacy | 100/100 | 280 | 320 | 5,307 |
| lookup | healthy_40ms | next | 100/100 | 520 | 600 | 20,538 |
| signaling | healthy_40ms | legacy | 100/100 | 120 | 120 | 607 |
| signaling | healthy_40ms | next | 100/100 | 200 | 200 | 4,398 |
| lookup | wan_200ms | legacy | 100/100 | 1,400 | 1,600 | 5,307 |
| lookup | wan_200ms | next | 100/100 | 2,600 | 3,000 | 20,538 |
| signaling | wan_200ms | legacy | 100/100 | 600 | 600 | 607 |
| signaling | wan_200ms | next | 100/100 | 1,000 | 1,000 | 4,398 |
| lookup | slow_800ms | legacy | 0/100 | — | — | 520 |
| lookup | slow_800ms | next | 100/100 | 8,700 | 8,700 | 32,422 |
| signaling | slow_800ms | legacy | 0/100 | — | — | 143 |
| signaling | slow_800ms | next | 100/100 | 4,000 | 4,000 | 8,044 |
| lookup | loss_10pct | legacy | 78/100 | 1,040 | 1,660 | 4,812 |
| lookup | loss_10pct | next | 100/100 | 2,180 | 4,600 | 24,204 |
| signaling | loss_10pct | legacy | 52/100 | 120 | 120 | 452 |
| signaling | loss_10pct | next | 100/100 | 400 | 2,200 | 5,118 |
| lookup | loss_30pct | legacy | 28/100 | 1,700 | 2,200 | 2,807 |
| lookup | loss_30pct | next | 83/100 | 8,520 | 12,600 | 34,754 |
| signaling | loss_30pct | legacy | 18/100 | 120 | 120 | 277 |
| signaling | loss_30pct | next | 70/100 | 1,900 | 6,000 | 5,930 |
| lookup | dead_30pct | legacy | 85/100 | 1,240 | 1,740 | 3,823 |
| lookup | dead_30pct | next | 86/100 | 8,280 | 8,780 | 21,000 |

## What changed, and what remains

- At 10% loss, the revised core completes all 100 sampled lookups and signaling
  exchanges. The legacy control completes 78 and 52 respectively. This is evidence
  for this model/sample, not a claim of universal reliability.
- At 30% loss, revised lookup success is 83/100 and signaling is 70/100. Remaining
  failures need further diagnosis; independent packet loss does not represent all
  cellular/Internet loss behavior.
- On the paired 20 seeds, signaling median at 10% loss falls from 2080 to 400 ms;
  at 30% loss, success rises from 10/20 to 15/20 and median falls from 5580 to 2300 ms.
- Dead-peer lookup improves from 12000 to 8280 ms on the paired sample, but remains
  much slower than legacy. Unknown peers retain conservative timeouts, and completing
  a closest-node search still waits for uncertain candidates. Provider discovery can
  stream earlier; those are distinct application contracts.
- Healthy lookup moves only from 560 to 520 ms, because the client still validates
  each newly discovered peer. Healthy signaling falls from 320 to 200 ms, benefiting
  more from repeated contact with the same coordinator.
- Healthy signaling bytes fall from 6219 to 4398, still far above legacy's 607.
  Fresh nonces, signatures, and full record envelopes remain. The next authentication
  phase should measure compact authenticated sessions rather than weaken signature
  checks or drop replay protection to improve these figures.

Tests cover reusable grants, expiry, receiver restart, stolen grants, request
signatures, replayed signaling, monotonic timing under wall-clock jumps, bounded
query concurrency, clean versus ambiguous RTT samples, and real-UDP signaling.
No wire compatibility is required; the envelope version is now `WRD2` + byte 2.
