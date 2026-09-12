# Controlled DHT read comparison and cold/warm profile

With eight verified replicas and one event loop per node, Warren's median first
read was 2.32 ms versus libtorrent's 2.53 ms at nine routing nodes, and 1.80 ms
versus 2.22 ms at 33. The earlier libtorrent lead did not persist in this run.
These small samples establish neither a universal winner nor WAN performance.

This follow-up separates replication and execution-layout effects from transport
startup costs. It uses Warren wire v6, HyperDHT 6.34.0, and libtorrent 2.1.1.0 on
Apple Silicon macOS. These are private loopback API measurements, not WAN,
throughput, signaling, attack-resistance, or feature-parity results.

## Method

The [runner and reproduction instructions](../../tools/dht-compare/README.md#controlled-replication-and-execution-experiment)
describe the full setup. There are 9 or 33 routing nodes including the writer,
plus one nonrouting reader. Nine permits eight remote replicas when an
implementation excludes its own writer. Each network runs 12 trials with distinct
256-byte values. Every put is checked by reading possible holders outside the timed
interval; all must contain exactly the expected number of copies and exact bytes.

Warren's shared-thread three-copy run is the replication control. All other runs
use eight copies. The per-node configurations give each Warren node its own Tokio
runtime thread, each HyperDHT node its own JS worker, and each libtorrent session
its native network thread. This controls event-loop allocation, not identical CPU
usage, memory footprint, routing-table contents, or process isolation. The protocols
use different identifiers and native routing/lookup policies.

First reads follow verification and a 1.1-second idle pause. Repeats immediately
follow first reads. Neither is labeled cold/warm transport: bootstrap and previous
trials can establish sessions, while repeats can also benefit from CPU/cache wakeup.
Both use native value lookup without injecting holder addresses. HyperDHT worker
startup/controller IPC is excluded; Warren's command/event channels and libtorrent's
Python alert delivery are included. These remain different API boundaries.

Put timings are retained only as setup diagnostics. HyperDHT is given the eight
nearest known remote IDs, while the other put paths perform native discovery.
Read verification, idle pauses, and network setup are excluded from read timings.
Backends run sequentially in a fixed order after builds and tests finish. Each
configuration uses one fresh network with 12 reads sharing its evolving state;
these are not 12 independent network replications. Trial zero is retained.
Twelve samples per cell on one host are insufficient for a broad ranking or small
performance claims. Nearest-rank p95 is the maximum with this sample count.

## Network measurements

All times below are milliseconds. Each cell contains 12 observations.

| Routers | Configuration | First median | First p95 | Repeat median | Repeat p95 |
|---:|---|---:|---:|---:|---:|
| 9 | Warren, shared thread, 3 copies | 4.429 | 5.584 | 2.585 | 5.453 |
| 9 | Warren, shared thread, 8 copies | 3.865 | 5.827 | 2.366 | 4.862 |
| 9 | Warren, per-node threads, 8 copies | 2.322 | 5.268 | 1.707 | 2.614 |
| 9 | HyperDHT, per-node workers, 8 copies | 6.178 | 7.254 | 3.341 | 5.293 |
| 9 | Libtorrent, per-node threads, 8 copies | 2.526 | 19.814 | 1.731 | 9.136 |
| 33 | Warren, shared thread, 3 copies | 3.869 | 10.915 | 2.366 | 4.476 |
| 33 | Warren, shared thread, 8 copies | 3.136 | 11.766 | 2.145 | 3.296 |
| 33 | Warren, per-node threads, 8 copies | 1.796 | 5.875 | 1.340 | 5.157 |
| 33 | HyperDHT, per-node workers, 8 copies | 10.435 | 17.054 | 7.127 | 11.133 |
| 33 | Libtorrent, per-node threads, 8 copies | 2.215 | 5.501 | 1.815 | 3.206 |

All 120 puts and 240 reads succeeded; every stored copy was verified outside the
timed interval. [Raw network CSV](dht-controlled-comparison.csv) and
[commands, platform, and source/binary hashes](dht-controlled-comparison.json) are
preserved. The previous experiment remains in the
[integrated-lookup report](dht-value-lookup-comparison.md).

Within Warren, increasing replication from three to eight reduced first-read
medians by 13% at nine nodes and 19% at 33. Giving each node its own event loop
then reduced the eight-copy medians by another 40% and 43%. This is evidence that
the original shared-thread benchmark was a material confound; it is not a claim
that a deployed node needs a thread for every peer. The configured node IDs and
value keys are fixed across Warren variants, but asynchronous routing state and
OS scheduling are not identical.

HyperDHT's worker configuration was slower in this experiment. That does not show
that normal Pear applications are slower, or isolate a cause inside HyperDHT.
Its worker layout, native lookup choices, runtime footprint and API boundaries
remain part of the measurement. Similarly, the observed Warren/libtorrent median
differences are too small and variable to establish a general ranking. At 33 nodes,
Warren's first-read p95 was slightly worse than libtorrent's despite its lower median.
The experiment does not support saying that libtorrent is intrinsically faster
because it is C++.

## One-peer cold/warm core profile

The separate probe pre-stores a 256-byte immutable value through another writer,
then reads it from a fresh reader and immediately reads it again. Every pair uses
fresh core instances. The reader knows exactly one holder; there is no discovery,
loss, socket, modeled network delay or driver scheduler. All reads are validated.
Packet legs are delivered sequentially; the probe asserts four cold and two warm.
The first/second network reads above are deliberately not substituted for this test.

| Measurement | Cold | Warm |
|---|---:|---:|
| Sequential round trips | 2 | 1 |
| Signed datagrams | 4 | 0 |
| Compact encrypted datagrams | 0 | 2 |
| Total DHT datagram bytes, excluding UDP/IP | 1,269 | 531 |
| Combined processing median, uninstrumented | 236.188 µs | 7.583 µs |
| Combined processing median, instrumented | 241.334 µs | 7.625 µs |
| Envelope signing: median total | 47.251 µs / 4 calls | 0 |
| Envelope verification: median total | 95.562 µs / 4 calls | 0 |
| Peer Noise setup/completion: median total | 81.249 µs / 3 calls | 0 |
| AEAD encryption: median total | 0 | 1.251 µs / 2 calls |
| AEAD decryption: median total | 0 | 1.250 µs / 2 calls |
| Value-key generation: median total | 0.500 µs | 0.500 µs |

Each build ran 100 pairs. The core elapsed measurement includes both endpoints
and the tiny in-process delivery harness. Region timings are wall-clock spans;
Noise spans include session installation, and key generation includes encoding
plus hashing. Combined elapsed time includes additional core/harness work and
profiling overhead. The instrumented and uninstrumented medians differed by about
2% cold and less than 1% warm in this calibration, not an overhead guarantee.
The six region rows repeat each operation's total time in the
[instrumented CSV](dht-value-core-profile.csv); do not sum those repeated totals.
The [uninstrumented CSV](dht-value-core-uninstrumented.csv) has one row per operation.

The cookie challenge accounts for the extra cold round trip; peer Noise messages
are piggybacked on the signed RPC exchange. Signing, verification, and Noise
account for roughly 93% of the measured cold processing time. Warm reads avoid all
of those operations, and their combined AEAD work is about 2.5 µs. Removing warm
packet encryption therefore offers little headroom in this one-peer profile.
On a WAN, an extra cookie round trip can matter much more than the roughly 0.24 ms
of cold processing measured here.

These measurements narrow the earlier explanation: authentication is a real cold
cost, while replication and execution layout demonstrably change the loopback
comparison. They do not directly measure the UDP driver's command-queue residence,
per-RPC network wait, or scheduler wakeup latency. Subtracting this best-case
one-peer profile from a multi-peer UDP lookup would not isolate those costs.
A subsequent driver trace would be needed to attribute the remaining time to
specific queues, hops or wakeups before changing scheduling policy.

## Implementation and validation

The comparison runner adds explicit replication/thread controls without changing
the normal three-replica store API. HyperDHT's controlled runner uses JS workers;
libtorrent verifies native eight-copy placement using read-only BEP 44 queries.
The opt-in `dht-next/diagnostics` feature records aggregate thread-local spans
without payloads. Normal builds retain a clock-free core. All measured network
runs used an uninstrumented release binary.

`make verify` passed formatting, warning-free Clippy/docs, and 504 workspace tests
(one ignored). Diagnostics-enabled Clippy/docs and 102 DHT tests passed. The
uninstrumented profile example passed targeted Clippy, both profile builds
completed 100 cold/warm pairs, and JS/Python syntax checks passed. Smoke runs
covered both network sizes and the original Warren/libtorrent eight-node modes.
