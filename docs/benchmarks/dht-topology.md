# DHT topology, admission policy, and signaling evaluation

Date: 2026-09-11. These are deterministic virtual-network runs of Warren's new
signed protocol, including its real packet codecs and cryptography. They compare
admission configurations within Warren, not HyperDHT or libtorrent.

## Workload

Each network has 64, 256, or 1,024 routing nodes plus a provider and caller. Routing
setup connects a ring and seven random peers per node. Optional join rounds perform
an own-ID iterative lookup at every routing node. The provider registers with three
nodes near its topic before measurement. Those coordinators deliberately survive
churn, isolating discovery/routing; coordinator failure is covered separately by
[failover tests](dht-failover-comparison.md) and the dual-stack driver integration test.

The matrix includes one or sixteen peers per prefix, no loss/churn or 10% datagram
loss plus 30% routing-node churn, and one or three caller bootstrap hints. Dead seeds
are not replaced behind the caller's back. Links have seeded directional latency
between 20 and 199 ms. Background maintenance is disabled; explicit join rounds
control the initial routing state. Each successful lookup attempts an encrypted
DHT-mediated offer and answer. Packet/byte counts include measured lookup and
signaling, not network setup. `signal_ms` is total time since lookup began.

The harness records first useful provider latency, complete lookup latency, closest-20
recall, packets, bytes, peak pending RPCs, and success. Success means provider discovery
and completed encrypted signaling, not merely a lookup completion event.

## Results

| Routing setup | Size | Diverse success | Unrestricted success |
| --- | ---: | ---: | ---: |
| Sparse probes, old lookup limits | 64 | 30/40 | 38/40 |
| Sparse probes, old lookup limits | 256 | 12/40 | 36/40 |
| Sparse probes, revised lookup limits | 64 | 38/40 | 38/40 |
| Sparse probes, revised lookup limits | 256 | 36/40 | 36/40 |
| Sparse probes, revised lookup limits | 1,024 | 24/40 | 22/40 |
| Two join rounds, revised limits | 64 | 24/24 | 24/24 |
| Two join rounds, revised limits | 256 | 20/24 | 20/24 |
| Two join rounds, revised limits | 1,024 | 22/24 | 22/24 |

The old lookup policy admitted only two candidates per prefix and sixteen per
bootstrap origin, with first-come candidate retention. The revised policy admits
eight per prefix and sixty-four per origin, and replaces only unqueried candidates
when closer referrals arrive. In-flight/completed/failed candidates stay pinned.
Per-prefix ingress limits were added in the same revision, so this is a combined
revision comparison, not an isolated attribution to one constant.

Sparse 1,024-node graphs still failed with live bootstrap seeds under both policies.
After two join rounds, **all measured trials with at least one live bootstrap seed
succeeded**, under both policies. The remaining joined-network failures had no live
bootstrap hints. Every successful provider lookup also completed encrypted signaling.
The 64-node joined rows occur in both joined files; do not count those duplicates as
independent trials. Three seeds per condition is a small sample, not an availability
SLA or evidence of Internet-wide robustness.


### Successful joined-network latency

Default diversity policy, pooling prefix layouts and bootstrap counts from the
64/1,024-node run. Values are virtual milliseconds; p95 uses nearest rank. Failures
are excluded here and remain in the success table above. Small samples make tail
quantiles descriptive only.

| Nodes | Loss/churn | Successful trials | First provider p50 / p95 | Through signaling p50 / p95 | Median packets | Median bytes | Peak pending |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 | 0% / 0% | 12 | 605 / 1136 | 3284 / 4854 | 73 | 24362 | 3 |
| 64 | 10% / 30% | 12 | 803 / 1973 | 7614 / 14474 | 80 | 25532 | 6 |
| 1024 | 0% / 0% | 12 | 1191 / 2350 | 5548 / 6436 | 127 | 42210 | 3 |
| 1024 | 10% / 30% | 10 | 2186 / 2790 | 14612 / 28437 | 180 | 57236 | 6 |

## Reproduction and raw data

```sh
cargo run --release -p dht-next --example topology -- 5 256 0
cargo run --release -p dht-next --example topology -- 5 1024 0
cargo run --release -p dht-next --example topology -- 3 256 2
cargo run --release -p dht-next --example topology -- 3 1024 2
```

Arguments are trials per condition, maximum node count, and join rounds. The current
command reproduces the revised implementation. The old-limit baseline is a captured
historical run; no old-policy runtime switch is provided.

- [Old-limit sparse baseline](dht-topology-baseline.csv), 160 rows.
- [Revised sparse 64/256](dht-topology-revised.csv), 160 rows.
- [Revised sparse 64/1,024](dht-topology-large.csv), 160 rows.
- [Joined 64/256](dht-topology-joined.csv), 96 rows.
- [Joined 64/1,024](dht-topology-joined-large.csv), 96 rows.

Older CSV captures lack the later `live_bootstrap` and/or `join_rounds` columns.
Setup is specified above rather than retroactively inventing missing observations.
These measurements justify the current tuning and join API; they do not establish
Sybil resistance, coordinator independence, NAT reachability, or deployment readiness.
