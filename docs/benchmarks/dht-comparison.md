# DHT comparison: initial paired benchmark

The replacement improves success under packet loss and high RTT, but is slower and
more expensive on healthy links. It is not yet a general performance upgrade.
These are deterministic simulation results, not public-internet measurements.

## Historical baseline command

```sh
cargo run --release -p dht-next --example compare_core -- 20 > docs/benchmarks/dht-comparison.csv
```

These results were captured before the adaptive scheduler and reusable grants.
The current command runs the updated core; it will not regenerate this historical
CSV. See the [new results](dht-adaptive-comparison.md) for the current command and
paired comparison. The original data is retained unchanged.

Harness: [`compare_core.rs`](../../crates/dht-next/examples/compare_core.rs).
Raw results: [`dht-comparison.csv`](dht-comparison.csv).
The trial-count argument selects seeds `0..count`; default 20. No real network
traffic is generated. The benchmark does not change either implementation.

## Method

- 20 paired seeds per workload/scenario: 440 runs total across both implementations.
- Both implementations use the same generated identities, addresses, initial routing
  graph, target, and network parameters. Setup asserts equal initial routing-table
  sizes against the prescribed graph before measurement.
- Lookup: 24 routing servers connected by a symmetric ring with offsets ±1 and ±3,
  plus one non-routing client seeded with two servers. Success means that a completed
  lookup contains the known, live target server. This does not measure full closest-K
  recall or exhaustive provider enumeration.
- Signaling: two non-routing clients and one DHT coordinator. The provider registers
  before measurement. Time includes caller discovery plus coordinator-mediated
  offer/answer completion; no data transfer or actual NAT punching is measured.
  Legacy uses `connect`/`accept_connect`; replacement uses `lookup`/`signal`/`answer`.
  The exchanged candidate payloads are small, but formats and authentication differ.
- Setup is loss-free, with 40 ms RTT, and excluded from the results. All setup traffic
  drains before measurement. Measurements are independent trials, not repeated
  requests over an application connection; registration/bootstrap costs are excluded.
- The same virtual clock drives both cores. Link delay is half the named RTT in each
  direction, with no jitter; delivery advances in 10 ms steps. Legacy gets millisecond
  timeouts, replacement receives its existing whole-second clock and one-second ticks.
  Existing protocol defaults remain unchanged, including different timeout budgets.
- Packet loss is a seeded independent draw for each directed link/packet ordinal.
  Both cores use the same loss rule; different packet sequences mean these are not
  identical dropped logical messages. No burst-loss model is included.
- Dead-peer scenario: each server independently has a 30% chance of becoming silent
  after setup, except the target, which stays live. Exact dead peers are paired across
  cores. The topology then stays fixed. Signaling is omitted for this scenario because
  its single-coordinator topology would only test whether that coordinator disappeared.
- Packets and bytes count **all directions**, including challenges, replies, retries,
  and packets sent toward dead peers, from operation start until completion/failure.
  They count application datagram bytes, excluding IP/UDP/link headers. Pending traffic
  after operation completion is excluded. Trials have a 45-second maximum horizon.
- P50/P95 latency includes **successful trials only**. P50 is the median; P95 is the
  nearest-rank percentile. Mean traffic includes **all attempts**, including failures.
  Always read success count alongside latency: quick failure is not a latency win.
- `discovery_ms` in raw data is new-core first-provider time versus legacy's reported
  lookup-phase duration; these have different completion semantics. `host_us` includes
  simulator execution and cryptography, not just DHT CPU, so neither field is used
  for the headline comparison. With only 20 seeds, percentages are coarse estimates,
  not fleet reliability predictions or statistical-significance claims.

## Results

### Lookup

| Scenario | Core | Success | P50 ms | P95 ms | Mean packets | Mean bytes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| healthy_40ms | legacy | 20/20 | 280 | 320 | 40.9 | 5,317 |
| healthy_40ms | next | 20/20 | 560 | 640 | 81.8 | 21,472 |
| wan_200ms | legacy | 20/20 | 1,400 | 1,600 | 40.9 | 5,317 |
| wan_200ms | next | 20/20 | 2,800 | 3,200 | 88.7 | 23,556 |
| slow_800ms | legacy | 0/20 | — | — | 4.0 | 520 |
| slow_800ms | next | 20/20 | 11,200 | 12,800 | 139.1 | 36,762 |
| loss_10pct | legacy | 15/20 | 860 | 1,620 | 37.4 | 4,749 |
| loss_10pct | next | 20/20 | 4,020 | 5,040 | 95.4 | 24,909 |
| loss_30pct | legacy | 6/20 | 1,720 | 2,240 | 25.3 | 3,024 |
| loss_30pct | next | 16/20 | 16,080 | 19,000 | 138.2 | 35,335 |
| dead_30pct | legacy | 17/20 | 1,540 | 1,780 | 32.1 | 3,811 |
| dead_30pct | next | 17/20 | 12,000 | 12,080 | 85.9 | 21,937 |

### DHT-mediated signaling

| Scenario | Core | Success | P50 ms | P95 ms | Mean packets | Mean bytes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| healthy_40ms | legacy | 20/20 | 120 | 120 | 6.0 | 607 |
| healthy_40ms | next | 20/20 | 320 | 320 | 20.0 | 6,219 |
| wan_200ms | legacy | 20/20 | 600 | 600 | 6.0 | 607 |
| wan_200ms | next | 20/20 | 1,600 | 1,600 | 22.0 | 6,819 |
| slow_800ms | legacy | 0/20 | — | — | 2.0 | 143 |
| slow_800ms | next | 20/20 | 6,400 | 6,400 | 34.0 | 10,792 |
| loss_10pct | legacy | 9/20 | 120 | 120 | 4.5 | 435 |
| loss_10pct | next | 19/20 | 2,080 | 8,020 | 23.1 | 7,278 |
| loss_30pct | legacy | 3/20 | 120 | 120 | 3.0 | 271 |
| loss_30pct | next | 10/20 | 5,580 | 9,060 | 20.4 | 6,600 |

## Interpretation and next experiments

1. **Healthy-path overhead is substantial.** At 40 ms RTT, median lookup rises from
   280 to 560 ms, with mean bytes rising from 5,317 to 21,472. Signaling rises from
   120 to 320 ms and 607 to 6,219 bytes. The new per-RPC challenge exchange, signatures,
   and larger signaling envelopes buy stronger validation, but their cost is visible.
2. **Retries improve lossy-path completion.** At 10% loss, lookup succeeds 15/20 versus
   20/20 and signaling 9/20 versus 19/20. At 30% loss, those counts are 6/20 versus
   16/20 and 3/20 versus 10/20. The new core still fails frequently at high loss;
   it should not be described as robust across arbitrary networks.
3. **Fixed timeouts explain the high-RTT cliff.** Legacy's 500 ms request timeout
   expires before an 800 ms RTT response can arrive. The new four-second deadline
   completes all sampled operations at that RTT, but costs time when peers are dead.
4. **The broader dead-peer sample does not show a success advantage.** Both find the
   target in 17/20 trials. Among successful runs, median time is 1,540 versus 12,000 ms.
   The separate `lookup_fallback` example demonstrates one specific legacy failure;
   that should not be generalized into a broad churn-performance claim.

Next: measure an adaptive, millisecond-resolution deadline policy; evaluate whether
validated-peer sessions can amortize repeated address challenges while preserving
replay protection; then add larger/random topologies, ongoing churn, burst loss,
multiple-coordinator signaling failover, and real-network trials. Keep the measured
protocols unchanged in this baseline so future changes have an honest comparison.
