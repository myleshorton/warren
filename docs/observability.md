# Operation observations

`driver::next::Node::diagnostics()` returns a collector-independent observer.
Subscribe immediately after binding. `Network::diagnostics()` and
`Link::observation()` default to disabled observers for existing implementations;
the v6 network and authenticated links propagate the active observer.

The broadcast buffer holds 512 completion events. Consumers must report
`RecvError::Lagged(n)` as lost observations. Exporting must run outside the
network actor. No network operation waits for a collector. Individual events
have at most 16 fields, with static names and string values, counts, or flags.
There are no payloads, keys, peer addresses, or arbitrary error messages.

Each operation has an ID, optional parent ID, starting network generation,
monotonic elapsed microseconds, and `success`, `error`, or `cancelled` outcome.
IDs are unique only within one observer; collectors must also identify the
application launch. Dropping a pending future records cancellation. Empty error
code denotes success. A parent may fail after a successful stage; count the
parent once when computing an operation failure rate.

| Events | Interpretation |
| --- | --- |
| `connect.result` | A dial or dequeued inbound offer, including policy/capacity rejection. `initiator` distinguishes roles. |
| `connect.discovery`, `connect.signaling` | Outgoing discovery and signaling stages. |
| `nat.reflection`, `nat.punch`, `noise.handshake` | Candidate gathering, chosen punch strategy, and authenticated handshake. |
| `network.rebind` | Rebind duration and resulting translation/discovery mode and generation. |
| `dht.lookup` | Complete application provider/bootstrap lookup. |
| `dht.health` | 30-second routing, datagram, socket-error and translation snapshots. |
| `dht.command`, `dht.socket.*`, `dht.rpc.timeout`, `dht.signal` | Local command/socket failures and protocol timeouts. RPC timeout events are not a complete RPC denominator. |
| `dht.lookup.result`, `dht.providers`, `dht.registration`, `dht.value.*` | Core protocol notices; notice elapsed time is not RPC latency. |
| `storage.blob.write`, `feed.append`, `publish.result`, `publish.body` | Publication and persistence results. Append succeeds after `try_append`; durability depends on the configured feed store. |
| `feed.fetch`, `feed.download`, `feed.window`, `feed.subscribe`, `blob.download`, `blob.swarm`, `transfer.serve` | Fetch, verification, subscription and serving outcomes. Long-lived subscription cancellation is expected. |
| `transfer.transport` | Snapshot on transport scope exit, including cancellation: request retries, fragment/NACK attempts, malformed messages, RTT and congestion window. Not a successful-transfer denominator. |
| `connection.queue` | Cumulative application queue drops at connection close, linked by `connection_operation_id`. |

NAT mapping variation is observational evidence, not a proven NAT category.
Reflection can succeed using a local candidate even with unanswered reflectors;
inspect `observed_candidates` and `unanswered_reflectors`. Translation modes are
`ipv4`, `ipv6`, `dual_stack`, and `nat64`. Initial translation discovery precedes
subscription; applications should emit a bound snapshot, and periodic health
includes discovery status.

Transfer failures distinguish invalid head signatures, inclusion proofs,
manifest/chunk hashes, malformed encodings, limits, absent items, incomplete
downloads, timeouts and I/O errors. Intentional protocol drops are not all
individual error events. Rust panics and native crashes require a separate crash
reporting pipeline; this observer reports normal operation results.

Validation includes correlated real v6 connect/blob transfer, cancellation and
observer overrun, and failed blob persistence without an append event. Murmur
adds collector admission/rejection tests and an explicit live SigNoz probe.
