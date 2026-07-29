# DHT production roadmap and assessment

## Current assessment

Warren already has a useful sans-I/O Kademlia core, deterministic network
simulation, a Tokio UDP driver, NAT sampling, rendezvous signaling, and
hole-punch integration. It is not yet equivalent to a mature deployment such
as Mainline DHT or HyperDHT: the remaining work is operational hardening,
authenticated signaling, lifecycle/persistence, and adversarial validation.

The DHT core deliberately owns no socket or clock. Callers feed datagrams and
time into the state machine, drain outbound datagrams and events, and can use
the same behavior in deterministic simulations and real UDP.

## Landed on `feat/dht-hardening`

- Routing admission is evidence-based: unsolicited traffic does not earn a
  routing slot; a correlated lookup response or an active reachable lookup does.
- Full buckets retain bounded replacement candidates and ping the LRU incumbent
  before replacing it. Replacement probes use request-id correlation.
- Public-address diversity limits cap IPv4 `/24` and IPv6 `/64` concentration
  per bucket while preserving private/LAN simulation behavior.
- Provider-record primitives support Ed25519 owner binding, bounded expiry,
  sequence-based replay rejection, source-address binding, topic/provider caps,
  and recipient-scoped write capabilities.
- Bounded wire carriers exist for capability request/grant and signed provider
  records. An identity-backed sans-I/O path exercises request, correlated grant,
  and signed-record admission deterministically.

The real UDP driver intentionally remains on the established unsigned announce
path for now. Enabling the new record path there regressed real channel
discovery because the public `announce()` completion contract was reached while
the extra capability exchange was still in flight. Do not re-enable it until
the driver has an acknowledgement/commit protocol and multi-node tests prove
that an announce is discoverable before its future resolves.

## Next work, in order

1. Complete authenticated signaling. Define a canonical signed signal envelope
   covering initiator, target, candidate addresses, NAT declaration, direction,
   expiry, and replay nonce. Coordinators must only relay opaque signed bodies;
   both endpoints must verify them before punching.
2. Finish the provider-record driver rollout. Add capability request timeouts,
   explicit record-store acknowledgement, retry/backoff, and an announce
   completion event only after responsible peers acknowledge storage. Add real
   multi-process tests for announce, lookup, direct connect, and symmetric-NAT
   punching.
3. Strengthen query behavior. Add per-peer RTT/failure quality, bounded retry
   budgets, adaptive deadlines with conservative floors/ceilings, duplicate
   suppression, cancellation, periodic bucket refresh, and self-lookups.
4. Add production lifecycle. Persist safe routing/contact metadata, bound and
   rate-limit bootstrap management, retain IPv4/IPv6 coverage, and integrate
   NAT/rendezvous state without putting I/O in `swarm`.
5. Add adversarial validation. Fuzz packet and state-machine decoding; run
   deterministic churn, partition, eclipse, packet-loss, and malformed-traffic
   simulations; add soak and multi-process CI gates.

## Release gates

Do not claim Mainline/HyperDHT equivalence based on feature presence. A
production milestone needs measured evidence for:

- lookup success and tail latency under defined churn and packet-loss profiles;
- bounded memory, pending requests, token/grant state, and packet work under
  malicious traffic;
- resistance to same-prefix concentration and unauthenticated record/signaling
  injection;
- recovery after restart and bootstrap loss;
- real-UDP interoperability across IPv4, IPv6 where available, and NAT cases;
- reproducible fuzz, simulation, integration, and soak test gates in CI.

## Current verification

Before the driver rollback, the new `swarm` record/routing tests and strict
Clippy checks passed. The driver rollout exposed two real-channel regressions
(`Direct` and symmetric-NAT connection attempts timed out); the rollback
restored the existing driver channel test. Future driver rollout work must run
the whole workspace test suite and the channel integration tests before review.
