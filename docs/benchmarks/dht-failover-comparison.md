# Automatic coordinator failover: measured results

`signal_via` starts one encrypted call across up to three supplied DHT coordinator
registrations. It adds paths when no provider answer arrives, reuses the signed
ciphertext, deduplicates application offers, and replays a cached answer through
new verified return paths. `signal` remains the single-coordinator convenience API.

## Reproduce

```sh
cargo run --release -p dht-next --example compare_core -- failover 100 > docs/benchmarks/dht-failover-comparison.csv
```

[Harness](../../crates/dht-next/examples/compare_core.rs) ·
[Raw results](dht-failover-comparison.csv) · [Protocol](../dht-next.md#signaling-flow)

## Method

This is a new paired experiment comparing single-path and automatic two-path calls
in the current replacement core. Each four-node network contains a caller, provider,
and two coordinators. Provider registrations and caller probes finish before the
measurement. All links have 40 ms RTT; a 10 ms simulated timer drives each core.
The measured interval starts with an offer and ends at the answer or call timeout.
Unlike earlier discovery-plus-signaling reports, this experiment excludes lookup,
bootstrap, and registration costs; its latency should not be compared directly to them.

There are three path conditions, three loss rates (0%, 10%, 30%), 100 seeds, and two
modes: 1,800 runs. Loss is independently determined by seed, source, destination,
and per-direction packet ordinal. The same law is used for both modes, though added
paths change packet sequences. A dead first coordinator drops all its traffic; a
broken first return path drops its packets to the caller while allowing it to receive
and forward the offer. The second coordinator remains reachable but also experiences
random loss. The first coordinator is preferred in both modes. Setup is loss-free.

No trial delivered more than one application offer. A separate seed-zero rerun
reproduces all 18 rows exactly. These are small deterministic network simulations,
not public-DHT, NAT traversal, HyperDHT, or libtorrent measurements. Byte-dependent
loss, CPU scheduling, queueing, correlated outages, and operator diversity are not modeled.

## Results

Latency medians include successful calls only; byte means include all calls.
A dash indicates no successful calls. Read success counts alongside latency.

| Path condition | Loss | Single success | Failover success | Single P50 ms | Failover P50 ms | Single mean bytes | Failover mean bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| healthy | 0% | 100/100 | 100/100 | 160 | 160 | 3,685 | 3,685 |
| healthy | 10% | 100/100 | 100/100 | 360 | 360 | 4,306 | 4,835 |
| healthy | 30% | 76/100 | 97/100 | 1,260 | 1,460 | 5,507 | 7,920 |
| first_dead | 0% | 0/100 | 100/100 | — | 960 | 2,482 | 5,486 |
| first_dead | 10% | 0/100 | 99/100 | — | 1,160 | 2,482 | 6,252 |
| first_dead | 30% | 0/100 | 81/100 | — | 2,060 | 2,482 | 7,925 |
| first_return_broken | 0% | 0/100 | 100/100 | — | 960 | 6,496 | 8,433 |
| first_return_broken | 10% | 0/100 | 99/100 | — | 1,160 | 6,893 | 9,534 |
| first_return_broken | 30% | 0/100 | 81/100 | — | 2,360 | 7,320 | 11,728 |

## Interpretation

- Healthy loss-free calls complete at the same 160 ms median without launching
  another path. With 30% loss, completion improves from 76/100 to 97/100, at higher
  traffic cost. Successful-call medians also represent different survivor sets.
- A dead first coordinator or broken first return path recovers in all 100
  loss-free trials, at a 960 ms median. At 30% loss the remaining alternate yields
  81/100 successes; this is resilience, not a delivery guarantee.
- A provider answers once. Alternate delivery after an answer reuses its cached
  encrypted answer instead of notifying the application again.
- The caller must already have matching registrations. Automatic discovery,
  registration renewal, operator/network diversity, and signaling-key rotation
  remain unfinished. Failover keeps the original expiry and never extends a call.
