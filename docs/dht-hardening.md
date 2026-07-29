# DHT hardening plan and baseline

**Status:** active design and implementation plan (2026-07-28).

`swarm` is a Kademlia-style discovery protocol. Its protocol state machine is
sans-I/O; `driver` is the production Tokio/UDP adapter, and Murmur creates a
`driver::Node`, bootstraps it from configured and cached peers, announces its
topics, and uses it for peer connections. The DHT is therefore on the live path;
this work strengthens its routing and record-security properties rather than
adding its first socket implementation.

## Current guarantees

- Node IDs use 256-bit XOR distance, with 20-contact buckets and three
  concurrent iterative queries.
- A response is accepted only when its request ID, node ID, and UDP endpoint
  match the outstanding request.
- NATed clients are excluded from routing tables unless reachability evidence
  classifies them as servers. Provider announcements are lease-bounded and the
  store has a topic cap.
- The core has deterministic tests for lookup convergence, packet loss, dead
  contacts, malformed packets, NAT classification, and punching. `driver` also
  has real loopback UDP tests.

## Current trust boundaries

- A packet source address proves only that the sender can receive at that UDP
  endpoint; it does not prove ownership of a node ID or a provider record.
- A routing slot is earned only by a correlated `FindNode` response from the
  exact ID and UDP endpoint queried; unsolicited packets and a peer's own
  `reachable` claim are not admission evidence. Full buckets probe their
  least-recently-seen member and retain bounded replacement candidates.
- Returned contacts and announcements are untrusted hints. They must never
  cause unbounded allocation, bypass routing admission, or be treated as an
  authenticated content identity.

## Measurable baseline and release gates

Before a public-network release, CI must record these under fixed simulator
seeds and packet-loss/churn profiles:

1. Lookup success, median/p95 latency, and packet count at 0%, 10%, and 30%
   one-way loss.
2. Routing-table occupancy and address-prefix concentration under honest churn
   and an eclipse attempt.
3. Maximum memory and outbound traffic under malformed packets, record floods,
   and repeated queries.
4. Recovery time after restart, bootstrap failure, and a network partition.

The immediate phase adds LRU ping-before-replace, bounded replacement caches,
and address-prefix diversity. Authentication of mutable/provider records and
signaling is deliberately a subsequent wire-protocol phase: it requires a
versioned signed-record format and must not be smuggled into routing changes.

## Non-goals of the first phase

This phase does not claim interoperability with BitTorrent Mainline or
HyperDHT, nor does it claim their operational maturity. It does not change the
existing wire format or replace Warren's UDP driver. Its success criterion is a
bounded routing table that resists simple same-network concentration while
retaining live contacts according to Kademlia's LRU rule.
