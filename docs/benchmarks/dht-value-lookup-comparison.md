# Integrated DHT value lookup

Date: 2026-09-11. Warren wire v6 retrieves values during iterative lookup. This report
compares it with the previous wire-v5 driver and actual HyperDHT/libtorrent libraries.
The [original baseline](dht-external-comparison.md) remains a historical artifact.

## Change

Previously, `fetch` completed a routing lookup and then issued up to three GetValue
RPCs. The new traversal uses FindValue requests; each ValueNodes reply contains
referrals plus an optional value. There is no separate read phase. Immutable reads
finish on their first verified content match and cancel remaining lookup RPCs.
Mutable reads continue the eligible frontier, compare signed sequences, reject a
fork at the highest observed sequence, and return explicit coverage/timeout status.

Content keys, signatures, size, and expiry are verified before accepting the response
or its referrals. The scheduler retains its normal diversity, provenance, retry,
hedging, concurrency, candidate, and deadline bounds. Value-bearing replies carry
at most four contacts; empty replies carry eight. The maximum signed mutable value
with IPv6 referrals and a Noise handshake fits the 1,200-byte datagram limit.

The changed response uses protocol v6. V5 packets are rejected; the value and signaling
signature domains remain unchanged. Single-replica get/put and three-replica stores
remain available. General discovery, publication, and DHT signaling keep their APIs.

## Measurement

The old release executable was preserved before rebuilding. Its SHA-256 is
`b17997b40c4c075d0cd69214125d81ee9fecd9f9d9c3db2c69d0870c96950cb9`.
It is a captured historical build, not reproducible from the current source alone.
Both old and new runs use fresh private networks with 8 or 32 routing nodes, including
the writer, plus a separate nonrouting reader. Each writes and reads twelve distinct
256-byte immutable values, with 1.1 seconds between trials. Setup and spacing are
excluded; trial zero is included. Backends run sequentially after verification.

HyperDHT is pinned to 6.34.0; libtorrent's wheel is 2.1.1 (runtime version 2.1.1.0).
Host: Apple M4 Pro, macOS arm64, Rust 1.97.0, Node.js 24.2.0. The
[pinned runners](../../tools/dht-compare/README.md) document private-loopback settings,
notification handling, and the separate libtorrent read-only-writer diagnostic.

## Results

All 96 puts returned positive results and all 96 reads returned exact payloads,
including the repeated v5 baseline. Times are milliseconds across twelve trials per
operation/size/backend. p95 uses nearest rank (the maximum with twelve samples).

| Routing nodes | Old Warren read median / p95 | Integrated read median / p95 | Median reduction |
| ---: | ---: | ---: | ---: |
| 8 | 6.793 / 8.732 | 2.269 / 2.662 | 66.6% (3.0× faster) |
| 32 | 13.587 / 34.382 | 2.894 / 10.164 | 78.7% (4.7× faster) |

### Fresh external-library comparison

| Routing nodes | Backend | Put median / p95 | Get median / p95 | Put count |
| ---: | --- | ---: | ---: | ---: |
| 8 | warren | 9.584 / 12.338 | 2.269 / 2.662 | 3 |
| 8 | hyperdht | 16.716 / 20.029 | 3.659 / 5.552 | 7 |
| 8 | libtorrent | 9.787 / 13.263 | 1.097 / 2.167 | 8 |
| 32 | warren | 20.182 / 39.286 | 2.894 / 10.164 | 3 |
| 32 | hyperdht | 43.722 / 51.010 | 4.596 / 8.360 | 20 |
| 32 | libtorrent | 12.274 / 17.847 | 1.219 / 2.181 | 8 |

## Interpretation limits

The immutable read completion criterion changes intentionally: the old path waited
for up to three replicas; the new path returns after one content-hash-verified value.
This is not a three-replica read quorum. Mutable reads retain sequence comparison and
may query more nodes than the previous three-replica phase. This workload does not
measure mutable-read latency or attribute gains separately to early completion and
combining traversal with retrieval.

Writes still have different replication counts across implementations. Warren get
`replica_contacts` now counts validated traversal responses, including misses; old
Warren counts responses from its separate read phase. HyperDHT's put count is its
closest-node list length and libtorrent's is its successful-put count. None is proof
of durable storage. Use the raw CSVs to inspect these distinct metrics.

These small loopback samples measure idle API latency, not throughput, WAN behavior,
NAT traversal, adversarial robustness, or deployment readiness. Network membership
and runtime scheduling are not controlled identically across implementations.
The [topology suite](dht-topology.md) and security/deployment limitations remain
applicable. No overall state-of-the-art or complete Pear SDK parity claim is made.

## Artifacts and reproduction

- [Repeated old-driver measurements](dht-value-lookup-baseline.csv).
- [V6 and external-library measurements](dht-value-lookup-comparison.csv).
- [Platform and commands](dht-value-lookup-comparison.json).

For current-code results, build/install using the runner README, then run:

```sh
python3 tools/dht-compare/run.py --trials 12 --output docs/benchmarks/dht-value-lookup-comparison.csv
```

The old executable is a session-local snapshot; current commands produce v6, not the
old baseline. Do not overwrite the historical v5 report to imply it used this code.

## Validation

`make verify` passed formatting, Clippy, 504 tests (one ignored), and warning-free
Rust documentation. `PROPTEST_CASES=10000 cargo test -p dht-next --lib attacks::`
passed 50 adversarial/property tests. The mutable-value property now also round-trips
combined value/referral responses. Focused tests cover multi-hop content retrieval,
first-match cancellation without disturbing other operations, forged values and
signatures, highest-sequence forks and supersession, absence, timeouts, expiry,
maximum IPv6 datagrams, v5 rejection, v6 golden vectors, and real-UDP fetch behavior.

A [controlled follow-up](dht-controlled-comparison.md) tests equal replication and
per-node event loops, with a separate cold/warm core profile. Use that report when
interpreting the remaining libtorrent latency gap; this report retains the original
unequal-replication experiment.
