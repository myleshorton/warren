# Warren, HyperDHT, and libtorrent: initial direct comparison

This is a historical snapshot. For current scope and validation, see the
[DHT completion audit](../dht-completion.md); transfer integration and
coverage-guided fuzz tooling have since been implemented.

Historical wire-v5 baseline. The current driver uses [integrated value retrieval](dht-value-lookup-comparison.md); current runner commands produce v6 results.

Date: 2026-09-11. This compares actual implementations over private loopback UDP,
not reimplementations of their algorithms. It is an API-latency baseline for the
completed experimental Warren DHT scope, not an Internet-scale performance ranking.

Host: Apple M4 Pro, macOS arm64; Rust 1.97.0 and Node.js 24.2.0.

Versions: Warren wire v5 (release Rust build), HyperDHT 6.34.0 (npm lockfile), and
libtorrent Python wheel 2.1.1 (`lt.__version__ == 2.1.1.0`).

## Measured workload

Each backend runs separately with 8 or 32 routing nodes, including the writer,
and one separate nonrouting reader.
Twelve distinct 256-byte immutable values are written by one client and read by the
other. Every read must return exactly the original bytes. Setup and 1.1-second
inter-trial spacing are excluded from elapsed times. Trial zero remains in the raw
results and includes initial storage-operation cache warming after bootstrap.

Warren uses its high-level three-replica `store`/`fetch` API. HyperDHT uses
`immutablePut`/`immutableGet`. Libtorrent uses its immutable item API and alert
notifications through Python using nonblocking `set_alert_fd`. The clients use each implementation's normal lookup
and replication behavior, so these operations are not identical work.

All bootstrap endpoints are explicitly local. Warren routing diversity and
libtorrent IP/search/node-ID restrictions are disabled for this single-IP private
network. Warren's packet and storage quotas remain enabled. HyperDHT routing nodes
are explicitly persistent. Libtorrent’s per-IP flood threshold is raised to 1,000
packets/second and verbose packet-log alerts are disabled. Its default 8,000-byte/s
DHT upload limit remains in place. No public network traffic is required by these runners.

## Results

All 72 puts returned a positive result and all 72 reads returned the exact payload.
Times below are milliseconds over all 12 trials, including trial zero. p95 uses
nearest rank (with this sample size, the maximum). Replica counts are observed put
counts; their semantics differ as described below.

| Routing nodes | Backend | Put median / p95 | Get median / p95 | Put replica count |
| ---: | --- | ---: | ---: | ---: |
| 8 | warren | 12.911 / 15.479 | 8.385 / 25.021 | 3 |
| 8 | hyperdht | 16.505 / 22.965 | 3.757 / 5.425 | 7 |
| 8 | libtorrent | 10.867 / 11.959 | 1.190 / 1.768 | 8 |
| 32 | warren | 18.409 / 37.520 | 12.904 / 50.639 | 3 |
| 32 | hyperdht | 40.217 / 53.619 | 3.689 / 11.343 | 20 |
| 32 | libtorrent | 11.514 / 18.601 | 0.980 / 4.668 | 8 |

Warren's median reads were slower than both other implementations in this workload.
Its driver performs a complete routing lookup before the value RPCs, then waits for
up to three responses. Integrating value retrieval into traversal is a concrete next
optimization target, though this run does not isolate how much latency each stage
contributes. Warren's lower put median than HyperDHT is not equivalent work: it wrote
three replicas versus seven or twenty returned HyperDHT contacts. These results do
not establish performance parity.

## What this comparison does and does not establish

Replica counts matter: Warren puts report verified RPC acknowledgements from up to
three nodes, HyperDHT reports the returned closest-node list, and libtorrent reports
its put alert's successful-node count. HyperDHT's list is not an equivalent durable
storage acknowledgement. Warren reads wait for up to three responses; the external
immutable read APIs may complete after their first useful result. All measurements
include language/runtime/binding overhead.

The gap between trials deliberately avoids repeatedly saturating Warren's per-prefix
input budget. The trial limit avoids its per-owner value cap. Therefore these numbers
measure idle API latency, not sustainable throughput or overload behavior. There is
one fresh network per backend/size, a small sample, and no controlled WAN delay,
packet loss, NAT, churn, hostile peers, or process restart during measurement.

Do not infer overall superiority, equivalent replication durability, or complete
Pear SDK parity from this workload. The [Warren topology suite](dht-topology.md)
separately exercises clustered networks, loss, churn, provider discovery, and encrypted
signaling; those simulations have not yet been reproduced against the other backends.

## Read-only writer compatibility finding

A separate eight-router libtorrent run used a nonrouting writer and reader. The
first put completed in milliseconds, while the next two took about 15 seconds each.
Packet logs showed the writer subsequently querying its own read-only endpoint and
waiting for it to time out. In the [pinned node implementation](https://github.com/arvidn/libtorrent/blob/v2.1.1/src/kademlia/node.cpp),
ordinary request admission checks `read_only`, but successful `put` handling calls
`m_table.node_seen` unconditionally. A read-only node drops incoming queries.
This explains the observed referral/admission behavior in this isolated workload;
it is not a claim about all libtorrent deployments.

Raising the flood threshold did not remove that delay. The latency baseline therefore
uses a routing-capable writer consistently in all three implementations. The
[read-only diagnostic measurements](libtorrent-readonly-diagnostic.csv) are separate
and excluded from the baseline statistics. An earlier callback-based runner also
stalled: the [official Python documentation](https://www.libtorrent.org/python_binding.html#set-alert-notify)
warns that `set_alert_notify` can deadlock on the GIL. The final runner uses its
recommended file-descriptor API; no callback-stall timings are reported.

## Capability comparison

| Capability | Warren replacement | HyperDHT | libtorrent DHT |
| --- | --- | --- | --- |
| Topic/peer discovery | Signed provider records, managed publication and pagination | Topic lookup and signed announce | Mainline get_peers/announce_peer |
| Immutable values | Content-addressed, 512-byte payload limit | Immutable put/get API | Arbitrary immutable item store |
| Signed mutable values | Salt, sequence, per-replica CAS, signed expiry | Signed mutable put/get and sequence selection | Signed mutable items, salt, sequence and CAS |
| DHT-mediated connection setup | E2E encrypted offers/answers, up to three coordinator paths | DHT-assisted hole punching and encrypted stream connection API | Application connection signaling is outside the listed DHT APIs |
| Data-plane integration | Explicit UDP DHT adapter; legacy punching/transfer migration remains | Integrated encrypted P2P stream interface | BitTorrent transport lives outside DHT item/discovery RPCs |
| Protocol interoperability | Custom signed wire v5 | HyperDHT protocol | Mainline/BEP DHT ecosystem |

External capability descriptions come from the pinned [HyperDHT API documentation](https://github.com/holepunchto/hyperdht/blob/v6.34.0/README.md),
[libtorrent DHT extensions](https://www.libtorrent.org/dht_extensions.html), and
[libtorrent item-store specification](https://www.libtorrent.org/dht_store.html).
The libtorrent signaling entry describes the boundary of those documented DHT APIs;
it does not imply that libtorrent lacks other peer-transport functionality.

## Reproduction

Use [the pinned runners and setup commands](../../tools/dht-compare/README.md).
[Raw measurements](dht-external-comparison.csv) and
[platform/command metadata](dht-external-comparison.json) accompany this report.
Run timed backends sequentially after CPU-intensive builds and checks finish.

Warren's current DHT scope is implemented: bounded routing/maintenance, provider
publication/discovery, encrypted coordinator signaling, immutable/mutable storage,
wire validation, source quotas, and a real UDP adapter. Remaining work before public
deployment includes independent protocol/security review, sustained coverage-guided
fuzzing, independent-region/NAT measurements, stronger operator-diversity policy,
and integration with the existing data plane. These remain explicit limitations.

## Warren validation

`make verify` passed formatting, Clippy, 499 tests (one ignored), and warning-free
Rust documentation. `PROPTEST_CASES=10000 cargo test -p dht-next attacks::` passed
46 adversarial/property tests, including 10,000 cases each for arbitrary packets,
signed malformed bodies, and mutable-value sequence binding. The real-UDP driver
suite also checks that successful client writes do not make the client a router.
