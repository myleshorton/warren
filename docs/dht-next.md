# Replacement DHT: discovery, storage, and decentralized signaling

Status: experimental Rust core in `crates/dht-next`, alongside the existing `swarm`
implementation. The legacy `driver::Node` uses `swarm::Dht`; `driver::next::Node` explicitly runs this core.
`transfer::next::Endpoint` integrates it with direct punching and authenticated feed/blob transfers. This is a working
opt-in replacement through the transfer layer; it is not the default backend or a
claim of HyperDHT/Pear SDK parity.

For a dual-stack wildcard bind with port zero, the adapter selects an IPv4 port
candidate and explicitly binds the IPv6 socket to that port, retrying address
conflicts at most 16 times. This avoids kernels that allocate IPv6 ephemeral ports
over an existing IPv4 listener, which can divert replies to the wrong socket.
Explicit caller-supplied ports are never silently changed. Rebind uses the same path.

The [completion audit](dht-completion.md) records current implementation scope,
validation results, and the remaining research/deployment boundaries.

## Architectural contract

DHT-based signaling is a first-class requirement. A provider registers with several
independent DHT nodes discovered near its identity/topic. A caller discovers those
signed registrations through iterative lookup, then exchanges an offer and answer
through one of those DHT nodes. A different registration supplies an independent
rendezvous path if a coordinator fails. No separate signaling service is required.

Coordinators forward only bounded control messages. The subsequent hole punch and
Noise-protected data connection belong to the existing puncher/transfer layers.
Routing servers must be reachable; NATed clients can register, discover, and signal
without becoming routing contacts. Cookie validation proves control of an endpoint
for this exchange, **not** that its NAT accepts arbitrary future inbound traffic.
The adapter must select the routing-server role using reachability policy.

The core consumes datagrams and caller-supplied time and returns `Action::Send` and
`Action::Event`. No network I/O or background tasks occur inside it. Wall-clock profiling reads are
added only by the opt-in `diagnostics` feature.
Noise handshakes obtain fresh ephemeral-key entropy through snow’s OS RNG.
The constructor requires a node identity and a fresh, secret 32-byte CSPRNG seed
on every start; tests inject deterministic seeds. Do not persist/reuse that seed.
Every operation takes `Time::new(monotonic_ms, unix_secs)`. Local deadlines,
cookie epochs, validation-cache expiry, routing expiry, and rate limits use the
monotonic clock; signatures over records and signals retain Unix-second expiry.
The caller must supply a nondecreasing monotonic clock. Wall-clock jumps do not
extend RPC deadlines or reset the input budget. Signed records still require a
reasonable shared wall clock; this is not a clock-synchronization protocol.

## Wire and trust boundaries

Packets are at most 1200 bytes. The encoding uses the existing `wire` primitives:

| Field | Encoding |
| --- | --- |
| Protocol/version | literal `WRD2`, then byte `6` |
| Sender | 32-byte Ed25519 public key |
| Destination | 32-byte BLAKE3 hash of recipient public key |
| Routing-server role | strict boolean byte |
| RPC nonce | 32 bytes, derived from the fresh local secret and a counter |
| Cookie epoch | little-endian u64 |
| Cookie | 32 bytes |
| Key exchange | u8 length (0, 32, or 48), then Noise handshake bytes |
| Body | tagged fields below |
| Signature | Ed25519 signature over every preceding byte |

Body tags are Probe (0), Find (1), Register (2), Offer (3), Forward (4), Answer (5),
Challenge (6), Ack (7), Nodes (8), GetProviders (9), ProviderPage (10), PutValue (11),
GetValue (12), ValueResult (13), ValueStored (14), FindValue (15), ValueNodes (16), Reflect (17), and Reflected (18). Socket addresses are family byte 4 or 6,
4 or 16 IP bytes, and a little-endian u16 port. IDs are fixed 32-byte fields;
counts are u8; signal payloads are length-delimited. Record/signal layouts and
signing domains are specified by `protocol.rs`. Unknown versions/tags, invalid
booleans, non-minimal length varints, oversized collections, invalid signatures, and trailing bytes fail closed.
This protocol is deliberately incompatible with legacy Warren datagrams.

Each RPC starts without a cookie. The receiver returns a signed challenge with a
keyed-BLAKE3 cookie bound to sender identity, observed address, and issuer-local
monotonic epoch (signing domain `warren:dht-next:cookie:v2`).
The sender re-signs the request with that cookie. The challenge is no larger than
the initial request and allocates no per-peer state. Cookies accept the current
or previous 30-second epoch. The caller caches the grant for at most 30 local
seconds and reuses it for that exact peer/endpoint, saving one round trip on warm
RPCs. A changed receiver secret or invalid grant triggers a bounded refresh.
Every request still has a fresh RPC nonce and either a verified Ed25519 envelope
or a session authentication tag: a stolen grant alone cannot authenticate a request.
Response packets must match the outstanding request's
identity, address, nonce, expected response kind, and deadline.

Only validated exchanges admit routing contacts; bootstrap/referral addresses stay
candidates until contacted. Full buckets can retain bounded authenticated alternatives
when routing maintenance is enabled. Client-role packets do not admit routing contacts.
A live routing entry is not silently moved to another address; expiry currently
allows replacement. More responsive authenticated migration is a follow-on.

For a new lookup, a caller-supplied seed takes precedence over a cached route with
the same identity. This lets a caller use a peer's fresh endpoint after a port or
network change. The seed remains an unverified candidate: it does not rewrite the
routing table, bypass identity authentication, or replace an in-flight candidate.

Accepted request nonces cache their response until their cookie can no longer be
accepted. Retries return the cached result without repeating side effects. Handshake
replies retain their exact bytes; compact replies are re-encrypted with a fresh
counter so a busy connection cannot age a cached ciphertext out of its replay window.
A full replay cache rejects new effects rather than evicting replay protection.

## Compact peer sessions

The signed request can carry the 32-byte first message of
`Noise_NN_25519_ChaChaPoly_BLAKE2s`. After cookie validation and replay-cache checks,
the responder includes the 48-byte second message in its signed reply. No additional
round trip is needed. Noise NN alone does **not** authenticate identities: this
composition relies on the verified Ed25519 signature over each handshake envelope.
The Noise prologue binds the domain `warren:dht-next:peer-session:v1`, initiator ID,
responder ID, and fresh RPC nonce, in that order. Session IDs are the first 16 bytes
of the completed Noise handshake hash. The construction needs independent security
review before deployment; the existing data-plane Noise XX implementation remains
separate. See the [Noise specification](https://noiseprotocol.org/noise.html).

Subsequent datagrams use `WRE3` plus version byte 1, a 16-byte session ID, an explicit
little-endian u64 counter, and Noise transport ciphertext with a 16-byte tag.
Encrypted content is the routing role, RPC nonce, cookie epoch/cookie, and original
body. Identity and destination come from session state; they need not be repeated
on the wire. A warm Probe is 119 bytes, versus 207 in signed protocol v2 (208 in v3
without handshake bytes). Records and signals retain their independent signatures.

Session keys are directional; counters never wrap or reset. A 1024-packet sliding
window accepts reordering once and advances only after successful authentication.
Sessions bind an exact endpoint and expire after five local monotonic minutes.
Parallel handshakes may coexist; installing one does not destroy another's keys.
Responders select new keys for sending only after receiving an authenticated transport
packet with those keys. A lost handshake reply cannot replace a confirmed session.
At most 5120 sessions are retained, with no eviction of live session state.
Receiver state is allocated only after a valid cookie. Session expiry is checked
on use as well as during pruning.

Retries preserve the RPC nonce but receive fresh transport counters. After two
unanswered transmissions (initial send plus first retry), the second retry attempts
a new signed handshake, allowing recovery when a peer has restarted. A lost signed
handshake reply is replayed exactly and does not regenerate keys or reset counters.

This is **opportunistic hop encryption**, not a confidentiality guarantee for every
RPC: initial requests/replies, cookie-refresh retries, and recovery use signed
cleartext envelopes. Peers without an available session can use signed RPCs.
Ordinary RPC envelopes do not have a blanket confidentiality guarantee. Signaling
payloads now have a separate, mandatory end-to-end encryption layer described below;
their ciphertext remains protected even inside a signed cleartext RPC.

## Routing admission diversity

`Dht::new` now uses `RoutingPolicy::Diverse`, independently of whether background
maintenance is enabled. Authenticated routing entries are limited to:

- One identity per IP address across the routing table, regardless of UDP port.
- Two contacts from an IPv4 /24 or IPv6 /64 per 20-contact XOR bucket.
- Eight contacts from that prefix across the entire routing table.

IPv4-mapped IPv6 addresses share the corresponding IPv4 quota; IPv6 interface IDs
and socket scope IDs do not create additional groups. These are local admission
limits, not a wire-format change. Known contacts can refresh their lifetime without
consuming another slot; an existing identity still cannot silently change endpoints.
Rejected routing admission does not reject otherwise valid RPCs or signaling.

When maintenance is enabled, its replacement cache has the same diversity limits,
counted separately from active routes, as well as its existing eight-per-bucket and
2048-total ceilings. A quota-blocked authenticated peer may enter this bounded cache.
Promotion requires available routing diversity capacity and a fresh authenticated
probe. Admission checks capacity again after the reply, so concurrent activity cannot
oversubscribe a prefix. Blocked candidates do not trigger repeated probes; normal
route expiry or removal can make them eligible later.

The initial two/eight limits deliberately allow limited subnet sharing and need
validation under realistic network distributions. A controlled private network can
use `Dht::with_routing_policy(..., RoutingPolicy::Unrestricted)` at construction;
normal identity/bucket/state limits still apply. Historical `compare_dht` and
`lookup_fallback` benchmark modes explicitly use that policy to preserve their original
concentrated topology.
Their published results do not measure the new default diversity policy. Deterministic
network tests use distinct synthetic prefixes; dedicated adversarial tests exercise
concentration, aliases, cache bounds, and promotion races under the default policy.

Libtorrent also enables IP/prefix routing restrictions by default, and separately
restricts search candidates; see its [settings reference](https://www.libtorrent.org/reference-Settings.html#dht_restrict_routing_ips).
Our policy covers routing, replacement admission, and lookup candidates. Session/replay allocation has separate per-identity and per-prefix bounds described
below. Bootstrap source selection and caller-supplied signaling coordinators still
need stronger operator-diversity policies. Prefixes do not establish
independent operators, and attackers with many prefixes can still mount Sybil attacks.

## Routing liveness and replacements

`maintain_routing(now)` enables bounded contact maintenance and returns any immediately
due probe actions. It is opt-in, so applications explicitly choose background traffic;
the existing benchmark modes retain their previous configuration. Continue driving
`poll_timeout` and `tick`. `stop_routing_maintenance()` cancels only maintenance-owned
probes and exploration lookups, and discards the replacement cache, preserving routing
entries and application/publication RPCs. Internal probes and exploration do not emit
application `Ready`, `RpcTimedOut`, `Providers`, or `LookupDone` events.

An authenticated contact still has a five-minute monotonic routing lifetime. When
maintenance is enabled, a quiet contact becomes due for a probe with three minutes
remaining—normally two minutes after its last authenticated activity. Other traffic
refreshes that lifetime, avoiding unnecessary probes of busy contacts. At most three
maintenance probes are active, within the shared 128-RPC limit. Due batches and local
capacity pressure retry scheduling no faster than once per second; the usual RPC
retries, adaptive timing, and handshake recovery still apply.

A failed probe removes a route only if no newer authenticated activity refreshed it.
A verified response advertising client-only mode can similarly retire the old route.
The lookup/lease layers cannot accidentally cancel maintenance probes, and stopping
maintenance cannot cancel their RPCs. An empty routing/replacement set contributes no
maintenance wakeup; pending probes retain their existing deadlines.

Full buckets keep their established contacts and retain at most eight authenticated
replacement candidates per bucket (2048 total). Unknown referrals do not enter this
cache. Candidates expire after five minutes; a changed address cannot silently replace
a live identity's endpoint. When a bucket has room, a cached candidate is probed and
must complete fresh authentication before normal routing admission. Cached identity
or historical liveness alone never grants immediate promotion. Normal 20-contact
bucket and 5120-contact global routing limits remain in force.

Maintenance also explores randomized targets in XOR distance buckets. The first lookup
is due after 60 seconds; subsequent lookups start 60–75 seconds after the previous
lookup completes. Only one exploration lookup runs at a time. It shares the normal
16-query/128-RPC budgets, up to six in-flight lookup requests, authenticated referral
admission, and 40-second lookup deadline. Capacity pressure defers exploration by
five seconds.

Targets rotate through the known distance range plus one bucket closer to the local
identity than the closest known contact. This explores gaps and expands the range as
closer contacts are learned, without scanning all 256 mostly empty prefixes. Targets
use secret-derived randomness within the selected bucket. Exploration starts from
live routing contacts; an empty table still requires caller-supplied bootstrap hints.

Admission enforces the prefix quotas above, but does not establish operator diversity
or solve Sybil/eclipsing attacks. The caller must run timers on time;
a suspended process can still let routing entries expire.

## Registration and lookup

A signed registration contains the provider's identity key, topic, 32-byte X25519
signaling public key, coordinator contact, and absolute expiry. The signaling key
follows the topic in the wire encoding and is covered by the provider signature. The provider signs these with domain
`warren:dht-next:record:v2`. A coordinator accepts it only from that provider's
validated endpoint and only when the named coordinator is itself. Leases last at
most five minutes. A renewal cannot shorten an existing lease; a still-valid old
record remains usable after a newer registration has refreshed the endpoint.

`lookup(topic, seeds, now)` iteratively queries candidates in XOR-distance order,
with three preferred RPCs in flight per lookup. When requests stall beyond their
retry threshold, up to three additional candidates can be queried, with a hard
ceiling of six outstanding requests per lookup. Failed candidates no longer occupy the
closest-20 search frontier, allowing farther live alternatives to be explored.
Verified provider records emit `Providers` events as they arrive, before
`LookupDone`. Referrals alone do not create routing-table entries.

Under the default `RoutingPolicy::Diverse`, each lookup admits at most one candidate
per IP and eight per IPv4 /24 or IPv6 /64, across the whole query rather than per XOR
bucket. Mapped IPv4 addresses share IPv4 quotas. The same admission path handles
initial live routes, caller-provided bootstrap hints, and signed responses containing
referrals. Each batch is ordered by XOR distance before applying quotas; unusable
endpoints and the local identity are discarded without consuming slots. The existing
128-candidate cap remains in force. Publication and exploration lookups inherit this
policy; `RoutingPolicy::Unrestricted` explicitly disables these address quotas too.

Failed candidates retain their address quota for the lifetime of that lookup. They
remain excluded from the closest-20 frontier, so other admitted networks can still
make progress, but repeated referrals cannot rotate fresh identities through the
same prefix budget. Duplicate IDs cannot reset candidate status or change endpoints.
Queries have independent budgets, and a new lookup can try that prefix again.

This favors prefix diversity over exhaustive search within a subnet: if all eight admitted
candidates from a prefix fail, further candidates from that prefix are skipped for
this lookup. Later, closer referrals can replace unqueried candidates, except for
explicitly supplied seeds admitted under the default policy. Those seeds remain
pinned alongside in-flight, completed and failed candidates, preserving independent
starting points, RPC ownership and budgets. A
referral's claimed address is still unverified until contacted, so these quotas do
not establish peer independence or prevent an attacker from supplying false addresses
across many prefixes.

Each candidate records its immediate referrer. Initial routing contacts and supplied
seeds have no referrer and are separate origins; descendants inherit that origin
through an immutable parent chain. Only a completed authenticated lookup response can
introduce descendants. Duplicate referrals cannot change ancestry, reset status, or
create cycles. Provenance lives inside the bounded candidate collection and is dropped
when the query completes or is canceled; it is not a persistent trust score.

The default policy admits at most 64 candidates per origin, **including the initial
seed**, across all descendant identities and prefixes. Failed descendants continue to
count, so a responder cannot evade the quota by introducing successive intermediaries.
For each scheduling slot, the lookup prefers the eligible origin with the fewest
requests already in flight, breaking ties by XOR distance. New selections count toward
that origin immediately. Eligibility uses the closest 20 nonfailed candidates plus
unqueried, explicitly supplied seeds admitted under the default policy. A target-near
referral set cannot cause normal completion to skip those seeds or evict them with
closer address aliases. Cached routing contacts alone do not receive this protection.
Seed protection does not bypass initial address/prefix/candidate admission limits.
The query deadline and early success on verified immutable content still apply.

This can add requests when a caller supplies many seeds (at most 128 admitted
candidates total). Existing RPC concurrency and query deadlines remain unchanged;
ordinary cached-route lookups retain their nearest-20 completion frontier.
A single available chain can use spare slots. `RoutingPolicy::Unrestricted` retains
provenance but disables this origin quota and uses the historical distance-only order.

This is bounded influence and scheduling fairness, not disjoint-path lookup or proof
of independent operators. A single-seed lookup can examine at most 64 candidates,
even if more honest referrals exist. Different origins can be controlled by the same
operator, earlier lookups can populate future seed sets, and duplicate referrals keep
their first ancestry rather than becoming corroboration votes. Multiple malicious
origins can still dominate a search. The [topology evaluation](benchmarks/dht-topology.md) exercises these limits under
clustered prefixes, loss, and churn. Stronger bootstrap diversity and independently
validated search paths remain follow-on work.

For bounded initial responses, Nodes carries at most eight contacts and two records.
Initial lookup replies return a subset. `providers_page(coordinator, topic, after,
now)` enumerates a coordinator's records in provider-ID order, two at a time. Pass
`None` initially and the returned cursor to continue until `next: None`. The core
emits `ProviderPage` with the request nonce, coordinator, topic, records, and cursor.
Pages validate every signature, expiry, topic, coordinator, strict ordering, and cursor
progress before completing the RPC. Cursors require no server state and tolerate
expiry between pages; enumeration is not a snapshot during concurrent writes.
Applications choose whether to paginate; normal lookups do not fetch every provider.
A provider can call `register` for a one-shot lease or `maintain_registration` to
keep a selected coordinator registered automatically. A signaling caller can pass
up to three matching records to `signal_via` for automatic path failover.

## Automatic publication and coordinator discovery

`publish(topic, seeds, now)` discovers coordinators near the topic and maintains
up to three registration leases. It accepts at most eight bootstrap hints and uses
existing routing contacts too; no fixed coordinator list or central registry is
introduced. Empty seeds are allowed: a disconnected node backs off until it learns
routes or the application supplies updated seeds. Repeating `publish` is idempotent
for unchanged seeds; changed seeds schedule fresh discovery without duplicating an
in-flight lookup.

Publication uses the existing iterative lookup and admits only returned contacts
that also have an authenticated, live routing entry. It prefers distinct IPv4 /24
or IPv6 /64 networks, breaking ties by XOR distance, and selects at most one endpoint
per canonical IP address (IPv4-mapped IPv6 aliases share an IP). If fewer networks
are available it uses additional distinct IPs from the available networks. It then
starts normal managed registration RPCs. `Event::Registered` still means a coordinator acknowledged a lease, not merely
that discovery selected a candidate. Internal publication lookups do not emit public
`Providers` or `LookupDone` events; application-initiated lookups are unchanged.

A selected set is reconsidered every 30–35 monotonic seconds, with per-topic jitter.
The previous selected endpoints remain additional bootstrap hints. Candidates absent
from the next completed lookup, or with two failed registration RPCs, lose their
automatic renewal and enter a two-minute selection cooldown. Existing acknowledged
leases/authorizations expire naturally, preserving their remaining useful lifetime.
Other responsive candidates can take their places. Discovery plus RPC timeout adds
to recovery latency; this is not immediate outage detection or guaranteed redundancy.

A shortfall relative to the distinct IPs in supplied hints, previous coordinators,
and current lookup results (capped at three) retries after 2, 4, 8, 16, 32, then
at most 60 seconds. This includes an empty selected set: one successful bootstrap
path no longer postpones recovery of another known path until normal refresh.
Hints affect retry timing only; they do not bypass authenticated selection.
Reaching that target resets backoff and restores the normal refresh interval. Query-capacity pressure defers discovery by five seconds. There is one
internal lookup per publication, at most 16 publications, three owned renewals per
topic, and at most 128 cooldown entries per publication. All lookup, pending-RPC,
registration, signature, and datagram bounds continue to apply. Retired leases still
occupy their authorization slots until expiry, so sustained churn can temporarily
exhaust the shared registration budget. All scheduling uses `poll_timeout`/`tick`.

`unpublish(topic)` cancels that publication's query and only the managed renewals it
owns. Existing manual renewals are excluded from automatic selection. Calling
`maintain_registration` explicitly on an automatically created lease transfers that
lease to manual management, so subsequent `unpublish` preserves it. Remote leases
are not revoked. To stop automatic recreation of a lease, stop publication rather
than stopping just one of its renewals.

Distinct IP addresses are only a basic duplicate-host guard. This does not enforce
network-prefix or operator diversity, prevent Sybil identities, or authenticate
bootstrap hints without contacting them. Signaling callers still perform lookup,
collect compatible records, and pass them to `signal_via`; publication automates
the provider side. Routing liveness and bucket exploration are a separate opt-in;
the explicit UDP adapter is `driver::next::Node`.

## Managed registration leases

`maintain_registration(coordinator, topic, now)` sends the initial registration and
retains a bounded renewal intent for that topic/coordinator pair. Repeating the call
for the same endpoint is idempotent: it does not send another RPC or reset its timer.
Changing that pair's endpoint requires stopping the old intent first. Registration
still requires the normal authenticated cookie exchange and coordinator acknowledgment.
`Event::Registered` reports each acknowledged lease, including renewals.

After an acknowledgment, renewal is scheduled with approximately 90–105 seconds of
lease life remaining. The 0–15 second jitter comes from the fresh RPC nonce, spreading
renewals across providers/coordinators. The schedule uses caller-supplied monotonic
milliseconds; lease signatures keep Unix-second expiry. A late successful ACK leaves
less time before renewal, rather than starting an unconditional fresh five-minute
local timer. Expired ACKs do not claim success, and older ACKs cannot overwrite a
newer authorization.

Each managed pair owns at most one registration RPC at a time. RPC failures retain
the intent and schedule another attempt after 2, 4, 8, 16, then at most 30 seconds.
Local capacity pressure defers an attempt by one second. Neither failure extends the
last acknowledged lease. On a tick observing that lease's wall-clock expiry, the
next attempt becomes due immediately once no RPC is in flight. Other coordinators
continue on their own schedules; a recovered endpoint can rejoin without restarting
the intent. This retries selected endpoints, not discovery of replacement operators.

`poll_timeout()` includes renewal and retry deadlines. Callers must execute returned
actions and drive `tick(Time)` at the indicated deadlines. No background task or new
wire protocol is introduced. Wall-clock jumps can invalidate signed leases; this
is not a clock-synchronization or guaranteed-availability mechanism.

The shared registration budget counts distinct topic/coordinator pairs across
acknowledged authorizations, pending registrations, and managed intents, with a
maximum of 256. Renewing an existing pair consumes no additional registration slot,
so a full table can still renew. The separate 128-RPC ceiling still applies. An
unreachable managed pair retains its reservation until explicitly stopped.

`stop_renewing(topic, coordinator_id)` removes the intent and cancels only its pending
RPC. It does not revoke an already-issued remote lease or an existing local signaling
authorization; those expire naturally. A late acknowledgment for the canceled RPC
cannot restart renewal. The ordinary one-shot `register` API remains available.

## Signaling flow

1. Provider P registers with coordinators C1 and C2 through validated DHT RPCs.
2. Caller A looks up P's topic and receives provider-signed coordinator records.
3. A sends C1 an Offer: a registration plus an end-to-end signed signal naming P,
   a fresh session ID, expiry, offer/answer flag, and encrypted payload.
4. C1 verifies the record, caller signature, and registration, saves A's validated
   return endpoint, and forwards the offer to P's registered endpoint.
5. P verifies A's signature and that C1 is one of P's acknowledged coordinators,
   decrypts the offer, and emits `Incoming` once for this session. Identical offers
   arriving through other authorized coordinators add bounded return paths.
6. P signs an encrypted answer naming A and the same session/expiry, then sends
   the same ciphertext through every verified return path. A later duplicate offer
   on a new authorized path receives the cached answer without another app event.
7. Each coordinator checks the expected target endpoint and pending session, then
   forwards only to the saved return endpoint. No caller-supplied address is honored.
8. A accepts an answer only from an attempted coordinator, checks P's signature,
   session, recipient and expiry, decrypts it, emits `Answered` once, and cancels
   remaining offer RPCs. Later answers cannot produce another completion.

Signals expire within 20 seconds and carry at most 256 application bytes, encoded
as 48–304 bytes of Noise ciphertext. Offers and answers use the distinct signing
domain `warren:dht-next:signal:v2`. Coordinators verify signed ciphertext and routing
metadata, but cannot decrypt the candidate payloads. This protection also applies
when the outer RPC uses cleartext signed transport during startup or recovery.

The provider generates a rotating X25519 signaling key using OS entropy and
publishes its public half in each signed registration. The caller verifies that
registration and uses `Noise_NK_25519_ChaChaPoly_BLAKE2s`: message one encrypts the
offer to the published key, and message two encrypts the answer to the caller's
fresh ephemeral exchange. There is no extra key-discovery service or network round
trip. The Noise prologue is `warren:dht-next:encrypted-signal:v1`, followed by caller
ID, provider ID, session ID, and little-endian u64 expiry. Existing endpoint checks,
expiry checks, signatures, and replay protection remain mandatory; Noise NK does
not authenticate the caller identity on its own.

`Event::Incoming` and `Event::Answered` now carry `ReceivedSignal`. Its `payload` is
application plaintext; its `envelope` is the unchanged signed ciphertext with
session/author metadata and a still-verifiable signature. Decryption failure emits
no application event. Only the application can trigger `answer`. Capacity for all
known return paths is checked before consuming the Noise response state, so capacity
failure leaves the answer retryable. Once sealed, answer ciphertext is cached and
reused; it is never re-encrypted by resetting the Noise state.

This protects payload confidentiality, not anonymity. Coordinators still see
identities, session IDs, expiries, ciphertext lengths, observed endpoints, and
traffic timing. Provider-key compromise can expose recorded initial offers; these
one-message offers do not provide forward secrecy against that compromise. Before issuing a registration, a provider rotates a key that has been advertised
for at least five monotonic minutes. `rotate_signaling_key(now)` also permits explicit
rotation. Up to three previous keys remain for a five-minute lease grace period;
retirement contributes a timer even after publication stops. Old keys and the current
key on core destruction use `zeroize`; this does not protect keys while the process
is compromised. Existing live records continue to decrypt during grace. Restarting
a provider changes its signaling key, so it must republish registrations; callers holding old records
may fail until they discover fresh ones. The separate data-plane Noise XX channel
is unchanged. This new protocol composition requires independent security review.

`signal(record, payload, now)` remains the single-path convenience API.
`signal_via(&records, payload, now)` accepts one to three preference-ordered,
provider-signed registrations naming the same provider, topic, and signaling key.
Duplicate coordinator IDs or endpoints are rejected. Distinct identities/endpoints
are not proof of independent operators or networks; caller-supplied coordinator sets
are not subject to routing-table prefix quotas.

The first offer starts immediately. If no valid provider answer arrives, another
path starts after four times the cached coordinator retransmission interval,
clamped to 500–2000 ms (2000 ms with no estimate). Coordinator acknowledgments do
not disable failover. The original signal/ciphertext/session ID is reused across
all paths. Expiry is the earliest of 20 seconds or any supplied registration expiry;
there is one monotonic deadline and at most one `SignalTimedOut` event for the call.
Outstanding offer RPCs are removed on answer or timeout.

`poll_timeout` includes the next path-launch deadline, even after an offer RPC is
acknowledged. RPC-capacity pressure defers launch by 200 ms without consuming the
alternate or extending the total call deadline. Active paths keep their existing
bounded RPC retries. The provider stores at most three authorized return paths and
requires duplicate offers to match the entire signed envelope. A conflicting offer
cannot replace the first one. Late answers are ignored after completion; remote
forward RPCs may consequently finish their bounded retry budget.

Gathering records from streaming lookup remains a signaling-caller responsibility.
Providers can use automatic publication or explicitly manage selected coordinators;
operator independence still requires policy beyond distinct IP addresses.
Automatic failover starts
only after the caller supplies records; it does not discover fresh ones mid-call.
Application data is never relayed by this protocol.

## Immutable and signed mutable storage

`Value::Immutable(bytes)` addresses content with domain-separated BLAKE3. Mutable
values use a stable key derived from publisher identity and salt; the publisher
signs the salt, sequence, payload, and absolute expiry. Construct them with
`MutableValue::sign(...)` and `Value::from(record)`. Values are capped at 512 bytes
and salts at 32 bytes so signed, encrypted IPv6 exchanges stay below the datagram
ceiling. These custom keys and signatures are not BEP 44 wire compatible.

`put_value(coordinator, value, cas, now)` writes one replica; `get_value` reads one.
Mutable writes reject lower sequences and same-sequence forks. An optional CAS
requires an existing record at exactly that sequence. Repeating an identical write
is allowed, but replaying a signed mutable record cannot extend its monotonic expiry.
Immutable records expire one hour after the latest accepted write; mutable records
expire at their signed deadline, at most one hour away. Storage is memory-only.
Applications can opt into `driver::next::Node::publish_value(value, signer, seeds,
config)` to keep values available. The returned `ManagedValue` owns the background
worker; dropping it stops renewal, and `close().await` waits for that stop. Remote
copies expire naturally. Each node admits at most 16 distinct managed keys.

By default each worker refreshes publications every five minutes and audits between
refreshes at a nominal 60-second interval, randomized by ±20%. Each cycle has a
60-second budget and rediscovers up to 20 responding candidates. Every cycle additionally
rechecks up to three remembered holders that have fallen outside those results,
for at most 23 candidates. These bounded hints survive failed cycles and local
network changes, but count only after fresh readback. Newly verified holders take
priority when updating the hints; lookup results supply the current address when
a remembered identity reappears. Full refreshes also check remembered holders for
newer signed values or equal-sequence forks before any writes, but choose replica
destinations only from the nearest 20 lookup candidates.
Preflight reads
run with at most three RPCs in flight. Each completion opens another slot, so a
silent peer does not serialize checks of healthy alternatives. Responses are
matched by request ID and restored to candidate order before replica selection
(lookup distance order followed by any additional remembered holders).
All preflight checks complete or time out before writes begin; a newer signed
value or equal-sequence conflict stops the cycle, including one found beyond the
first batch. Discovery, preflight, writes, and post-write readbacks reserve a
cleanup command slot before starting work. Ending a phase, including cancellation, timeout, or
conflict, removes its remaining lookup/read/write RPCs without penalizing the peers or
canceling unrelated work. Discovery cleanup also releases its query slot; it
cannot cancel internal routing maintenance or coordinator publication lookups.
Packets already sent cannot be recalled: canceling a write stops local retries
but does not undo remote storage or establish whether the peer accepted it.
Only a completed exact readback counts toward the verified replica target.
Existing cycle deadlines and per-node RPC capacity still apply.
An audit first reuses exact, validated copies already found by preflight, preferring
network diversity among those existing copies. If three are available, it performs
no writes even when closer empty peers have appeared. Only a shortfall triggers
replacement writes. Full refreshes still reconsider placement across all eligible
candidates and renew storage leases. Mutable expiry renewal occurs before choosing
reusable copies, so an audit that signs a new deadline writes and verifies the new
version instead of counting old signatures.
A write counts toward the three-replica target only after an exact, validated
readback from that holder. Missing, stale or timed-out readbacks cause the worker
to try replacement candidates. Exhausted candidates leave an explicit shortfall.

Local query/RPC capacity errors use a separate exponential retry delay starting
at one second, with ±20% jitter and a hard 30-second maximum. They do not consume
a due full refresh or assign a peer cooldown; the retry still performs the
pending refresh once capacity returns. A cycle without a capacity error or a
local network change resets this retry delay. Cancellation remains available
while waiting, and persistent saturation cannot cause a tight retry loop.

Failed preflight RPCs, rejected/timed-out writes, and failed readbacks trigger a
per-publication cooldown keyed by peer identity. Delays rise through 30, 60, 120,
240 and 300 seconds; successful verification resets that identity's history. The
worker skips storage reads and writes to those identities during cooldown, while
ordinary DHT lookup traffic may still contact them. An initially missing value is
not a failure. Other replacements remain eligible; the replica target is not
relaxed when all candidates are cooling down.

At most 64 identities are remembered per publication, evicting the earliest retry
deadline on overflow. This is bounded retry state, not shared reputation or a
permanent ban. Local network-generation changes clear it and force refresh,
including when an audit timer becomes ready at the same time. A recovered remote
peer becomes eligible after its delay; merely changing its endpoint does not bypass
the identity's cooldown. Skipped peers may hold newer data not observed this cycle,
so these reads still do not establish global freshness.

Each next holder is chosen relative to already verified copies: prefer an IP not
already represented, then the least represented IPv4 /24 or IPv6 /64 network,
then XOR distance. Failed attempts do not consume a network slot. If no more diverse
candidates remain, additional holders on existing networks are allowed so small
networks can still replicate. IPv4-mapped IPv6 addresses share the native IPv4 group.
This changes selection within the discovered candidates, not the lookup frontier.

`ValuePublicationConfig::audit_interval` controls the nominal audit delay (50 ms
to ten minutes). Delays follow completed cycles and are capped by the next scheduled
refresh; audits do not postpone refreshes. Network changes wake a full refresh.
Immutable writes refresh storage TTLs. Mutable
publications require the publisher's signing key: within 15 minutes of expiry the
worker increments the sequence and signs a new one-hour deadline. Retries retain
those exact signed bytes. Existing mutable holders receive a compare-and-swap
write against their observed sequence. A newer signed value or same-sequence fork
stops the worker before that cycle's writes if found during preflight, or before
any further writes if found during readback; the application must resolve it.
These checks do not provide multi-writer consensus or atomic replication.

`ManagedValue::status()` exposes the current signed value, completed `rounds`, the
subset counted as `audits`, and errors. `acknowledged` records successful write
claims from the latest completed cycle; `verified` records exact validated reads
of the published value. An audit may report three verified copies with no writes,
or a repair may report four acknowledgements but only three verified copies. Only
`verified` satisfies the replica target. `verified_networks` counts distinct /24
or /64 networks among those readbacks, exposing concentration even when three
copies verify. It does not count independent operators. `backed_off` lists peers
whose storage operations are temporarily suppressed as of that status update.
Failed/incomplete cycles
clear both lists and reset the network count;
these fields are observations, not cumulative history or durable storage proofs.
Renewed bytes become visible before writes begin.
Applications should persist the latest signed value for restart; the watch channel
is not a durable checkpoint or a persistence barrier. A stale restart encountering
a newer remote version stops instead of overwriting it. Network-generation changes
wake repair immediately. Acknowledgements are claims, not durability proofs, and
outages, malicious holders or process shutdown can still make content unavailable.
A holder can answer the publisher's audits while withholding data from other clients,
or discard data after a successful read. Readback does not prove future retention.

Worker-level loopback UDP tests exercise immediate discard, missing/stale/silent
readbacks, later selective withholding, replacement repair, and newer-value conflicts.
The core's `test-support` feature enables explicit storage fault injection for these
tests; it is a driver dev-dependency and is absent from normal default builds.

Responses are checked against the requested content key and signature before they
complete an RPC. Each node retains at most 1,024 values, with at most 16 per owning
identity and 64 per source prefix. Mutable ownership follows the signed publisher;
immutable ownership follows the first writer. Updates preserve original quota
ownership and source accounting. Remote acknowledgements are claims, not proof of
durability or future availability.

## Explicit UDP driver

`driver::next::Node` drives this core with Tokio UDP, real monotonic/wall clocks,
automatic routing maintenance, and bounded command/event channels. IPv6 sockets are
dual-stack; IPv4-mapped endpoints are canonicalized before RPC matching. Use `bind`
with the default diversity policy, select the routing-server role explicitly, and
supply bootstrap contacts with known identities. `bootstrap` performs an own-ID
lookup. A wildcard bound address must be replaced by a reachable address when giving
contacts to another node.

Subscribe before starting low-level operations. `Notice::Dht` carries core events;
slow consumers receive explicit broadcast lag errors. Command capacity is 128 and
event capacity is 256. Dropping the final handle aborts the actor; `shutdown` waits
until its socket is released. Oversized datagrams are rejected by the core.

The driver exposes publication, pagination, encrypted offer/answer, key rotation,
and single-replica value operations. `store(value, cas, seeds)` looks up the key and
writes up to three responsive replicas, preferring different IPs and networks with
XOR distance as the tie breaker. It reports acknowledgements, rejections and timeouts
separately. Unlike managed publication, this one-shot API does not perform readback. CAS is evaluated independently at each replica, not as a
global transaction. `fetch(key, seeds)` uses the integrated value traversal described
below. Immutable reads return the first verified match; mutable reads compare the
responding traversal frontier. A fork at the highest observed sequence produces an
explicit error. Partial coverage does not prove global absence or latestness.

This adapter is independently usable; legacy `driver::Node` and the existing
puncher/transfer integration still use the old DHT. Connecting the new signaling
API to that data plane is a separate integration milestone, not completed Pear SDK
parity.

## Integrated value traversal

`lookup_value(key, seeds, now)` shares the routing lookup scheduler, diversity and
origin policies, retry/hedging logic, 128-candidate ceiling, and 40-second deadline.
It sends FindValue instead of Find. ValueNodes responses contain a locally stored
value, if any, and nearby contacts, so every traversal hop can retrieve content.
There is no second GetValue phase. Single-replica `get_value` remains available.

Absent-value replies carry up to eight contacts. Replies with a value carry up to
four, keeping maximum-size signed mutable values, IPv6 contacts, and the 48-byte
Noise handshake within 1,200 bytes. Both limits are enforced during decoding.
The new messages use wire v6; signed v5 packets are rejected. Signing domains for
stored values, records, and signals are unchanged. Historical v5 fixtures remain
alongside the active v6 golden vectors.

A reply's value must match the requested key, signature, size, and expiry before
its RPC completes or its referrals are admitted. Invalid content leaves the request
pending, allowing another valid response or normal timeout. Referrals follow the
same authenticated-referrer and pinned-candidate rules as ordinary lookup.

An immutable content match finishes immediately and cancels only this query's
outstanding RPCs. Late replies cannot complete it twice. Mutable retrieval finishes
the eligible closest-20 frontier or reaches the deadline, selecting the highest
verified sequence observed. Equal-sequence conflicting records mark a fork; a later
higher sequence supersedes that lower-sequence conflict. The selected value is
rechecked at completion and dropped if expired. No global freshness claim is made.

`Event::ValueLookupDone` carries the query ID, key, and `ValueLookupResult`:
`value`, `conflicting`, `responses`, `attempted`, and `timed_out`. Responses count
validated value-search replies, including misses; attempts count issued RPCs,
including later cancellations, but not retransmissions. `timed_out` indicates the
whole-query deadline; individual failed RPCs appear as missing responses. An empty
seed/routing set completes with zero attempts. Value queries do not emit application
provider-discovery events or become publication/maintenance-owned queries.

The UDP driver's `FetchResult` exposes value, response/attempt counts, and query
timeout status. It reports `NoPeers` for an empty traversal, `TimedOut` when no peer
responds (or an unstarted traversal reaches its deadline), and `ConflictingValues`
for a fork at the selected sequence. It waits up to 45 seconds for core completion.
The [integrated-read comparison](benchmarks/dht-value-lookup-comparison.md) measures
this change against the previous implementation and the real external libraries.
The [controlled follow-up](benchmarks/dht-controlled-comparison.md) equalizes
replication, compares shared versus per-node event loops, and profiles cold/warm
read packets and cryptography. Profiling is opt-in through the `diagnostics`
feature; ordinary builds add no profiling clocks.

## Public-key connections and authenticated transfers

`transfer::next::Endpoint` is the opt-in connection service for this DHT. It owns
one identity and DHT actor. `listen(seeds)` publishes under the hash of its public
key, maintains that registration, and returns after the first acknowledged lease.
That first acknowledgement does not establish coordinator redundancy. Publication
continues discovering up to three coordinators on distinct IP addresses.

`connect(public_key, seeds)` looks up that public-key address and ignores records
signed by other providers, even if they published under the requested topic.
Generic lookup replies carry only two providers, so the service also seeks the
requested provider's exact sorted position using authenticated provider pagination
on the responding lookup frontier. Unrelated publishers cannot hide that record
merely by occupying the first page. It selects up to three distinct coordinators
sharing a signaling key. Lookup timeouts
with no records are reported as timeouts, not absence. Every returned connection
has completed the following path:

1. Bind a fresh data socket and obtain candidates through authenticated DHT
   reflection on that exact socket. A different DHT socket's NAT mapping is never
   advertised as the data mapping. Up to three reflectors run within a 750 ms
   budget. Concrete local candidates are retained; wildcard binds need a valid
   observation. IPv4-mapped addresses are normalized and IPv6 sockets are dual-stack.
2. Exchange versioned candidate offers and answers inside the existing end-to-end
   encrypted, signed DHT signaling. No separate STUN or signaling service is used.
   The listener retains its publication's alternate reflectors, so losing the
   forwarding coordinator need not prevent gathering the answer's candidates.
3. Probe candidates using `puncher::rendezvous_with_strategy`. A changed port on
   the same advertised IP can become a peer-reflexive candidate. If exactly one
   side advertises different ports on one IP, it opens up to 64 outbound socket
   mappings while the other searches ports. The initiator nominates one socket
   and path globally; all losing sockets close. Noise still authenticates identity.
4. Run Noise XX on the nominated socket. The dialer pins the requested identity;
   the responder pins the author of the signed offer before acknowledging the
   handshake. Both add the DHT signaling session to the Noise prologue, rejecting
   crossed sessions even when both involve the same pair of public keys.
5. Return an authenticated `Connection` implementing `transfer::Link`. Existing
   reliable feed/blob download and streaming APIs work directly over this link.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant D as DHT coordinators
    participant P as Provider
    P->>D: Publish signed public-key registration
    C->>D: Discover that public key
    D-->>C: Signed registrations and alternate coordinators
    C->>D: Reflect the fresh data socket
    D-->>C: Authenticated observed address
    C->>D: Encrypted candidate offer
    D->>P: Forward offer
    P->>D: Reflect fresh data socket; encrypted candidate answer
    D->>C: Forward answer (alternate coordinator on failure)
    C->>P: Probe and nominate a direct candidate path
    P-->>C: Confirm nomination
    C->>P: Noise XX, bound to signaling session and both identities
    P-->>C: Authenticated handshake completion
    C->>P: Encrypted feed/blob transfer
```

The candidate payload begins with `warren-connect` plus version byte 2, then a
role byte (offer=0, answer=1), count 1–4, and address entries containing family
byte 4/6, IP bytes, and a big-endian u16 port. It must consume the payload exactly.
Zero ports, unspecified/multicast/broadcast addresses, IPv6 link-local addresses,
and duplicate normalized candidates are rejected. LAN addresses remain valid.
The entire payload fits within the existing 256-byte encrypted signaling limit.

Reflection is an additive experimental-v6 extension: tag 17 has no body; tag 18
contains the observed socket address in the existing address encoding. Existing
v6 message encodings and golden vectors are unchanged; two reflection vectors are
added. Older v6 nodes reject the new tags and cannot provide reflection. A reply
must match the request nonce, reflector identity, endpoint, kind and deadline;
only usable addresses complete the RPC. Requests require the existing cookies and
signatures/session authentication, remain within normal quotas, and transient
client-role data sockets do not become routing nodes. An observation is a
candidate, not a guarantee that another endpoint can reach it.

Nomination packets are `WPN1`, the 32-byte signaling session, and one kind byte:
probe=0, acknowledgement=1, selection=2, confirmation=3. Only the dialer selects;
confirmation cannot establish a path before selection. These packets are not
identity proofs and expose the session identifier on the direct path. Noise is
mandatory before application data is exposed. `DirectChannel` keeps responding to
late nomination packets while Noise runs; a lost confirmation therefore does not
strand the dialer. The Noise prologue is `warren/noise/v1` followed by
`/dht-next-session/v1` and the session bytes. Legacy Noise APIs keep their original
prologue. A bounded receive task also drives Noise completion replay immediately,
so a lost completion acknowledgement recovers before application `recv` is called.

The API deliberately provides authenticated datagrams, not a general-purpose
ordered `AsyncRead`/`AsyncWrite` byte stream. Feed/blob reliability, fragmentation
and verification are supplied by the existing transfer engine. Its 1200-byte
fragment budget leaves 1174 application bytes after Noise overhead and the
connection frame byte. Version 2 candidate negotiation requires this framing;
older version 1 offers/answers are rejected rather than silently misinterpreted.
Within Noise, type 0 prefixes an application datagram (including an empty one),
type 1 is a one-byte heartbeat, and type 2 is its one-byte acknowledgement.
Heartbeats run every 15 seconds. After 90 seconds without a valid authenticated
frame, the receive side reports `TimedOut`. Punch controls cannot extend this
deadline. No transport keys or nonce counters are reused when reconnecting.

### Lifecycle, admission, and failure behavior

`Config::authorize` checks authenticated offer authors before queueing them and
again before allocating an accepted data socket; its default permits all authors.
Each endpoint permits 32 simultaneous connection attempts. Listener offer queues
and per-connection decrypted receive queues each hold 32 items. A full application
queue drops excess application datagrams while continuing to process heartbeats;
the existing reliable transfer protocol handles loss. Terminal receive errors are
queued after already-buffered data and retained until the application drains it.
Connection attempts have a configurable overall deadline (60 seconds by default,
maximum 120); direct punching also has its own bounded budget. Admission rejection
is silent on the wire, and a caller can time out rather than receive a denial.

A listener owns the public-key publication. Dropping it requests local cleanup;
`close().await` waits for renewal/discovery to stop. Existing remote leases expire
naturally rather than being immediately revoked. Canceling startup also releases
the listener slot. Canceling a connection releases its data socket and attempt
permit; any already-issued core RPC/signaling state retains the core's bounded
expiry. DHT shutdown interrupts pending connections. Established connections own
their data sockets, survive listener closure, and terminate their receive tasks
when dropped. Only one listener may be active per endpoint.

`DirectUnavailable` means the advertised direct candidates could not establish a
path. This service does not silently select a centralized or third-party relay.
One-sided birthday punching is bounded: at most 64 sockets, 8192 search datagrams,
and the configured punching deadline (5 seconds by default). Mapping sockets
probe no faster than every 250 ms; search sends 32 ports per distinct candidate IP
no faster than every 50 ms. Search covers ports 1024 through 65535. A varying port
is evidence for selecting a strategy, while absence of variation is not proof of
stable mapping. Both-varying mappings, missed collisions, privileged-port-only
mappings, and UDP-blocking networks can still fail explicitly. PCP/UPnP mapping
is opt-in through `transfer::next::Config::port_mapping`. Choose
`MappingGateway::Automatic` for SSDP discovery followed by PCP with UPnP fallback,
`Pcp(address)` for a known PCP gateway (including gateways without SSDP), or
`Upnp(location)` for an explicit IGD description URL. Mapping acquisition has an
eight-second budget and uses the actual data socket's port and gateway-facing IP.
A rejected mapping falls back to the ordinary candidates. A granted public mapping
is preferred and keeps punching on that socket instead of selecting a birthday
socket. Private/CGNAT grants are not advertised as public candidates.

The connection owns a finite mapping lease, requests ten minutes, and renews at
half the granted lifetime (at most five minutes). PCP renewals retain the nonce
and suggest the granted endpoint. Expiry or a changed external endpoint invalidates
the path so connection recovery can establish a fresh one. Dropping the mapping
requests PCP deletion or UPnP DeletePortMapping with a bounded cleanup budget;
cleanup is best effort, with lease expiry as the fallback. Tests use local fake
gateways; consumer-router and double-NAT validation remains outstanding. Data
relays remain unimplemented. Network-change recovery is
available through the explicit API or a platform notification adapter described below.

The deterministic harness exercises 72 ordinary nomination cases: open/stable/
endpoint-dependent mapping pairs, IPv4/IPv6, single/double NAT, and packet loss
with reordered delivery and dropped nomination confirmations. It verifies the
resulting bidirectional path. A separate full-port-space birthday simulation runs
32 fixed seeds per dialing role with restrictive filtering and the full search
budget; real UDP tests verify socket nomination and cleanup. These tests do not
measure Internet NAT success rates or establish whole-Endpoint behavior behind
real routers. Mixed-family connections have separate real-loopback tests.

The legacy birthday helper now also takes full peer endpoints and sends from
every bound socket. Its spray path preserves the socket advertised in signaling.
A regression test observes outbound traffic from all four test sockets before
acknowledging one; binding alone cannot satisfy it.

Run the isolated, bidirectional public-key connection example:

```sh
cargo run -p transfer --example dht_connect
```

Tests exercise a verified 200 KB blob transfer, wildcard IPv6 reflection,
concurrent dual-stack connections, failed coordinators before signaling and after
offer delivery, explicit direct-path failure, authorization, wrong-provider
records, crowded topics, identity/session pinning, cancellation/shutdown, and dropped nomination
and Noise completion acknowledgements. See `crates/transfer/src/next.rs`,
`crates/puncher/src/rendezvous.rs`, and the reflection tests in `dht-next`.

### Restart bootstrap state

`Node::bootstrap_state().await` exports at most 128 live routing contacts, sampled
across XOR buckets. `BootstrapState::encode()` returns a bounded `WBS1` binary
snapshot; the application owns filesystem storage and atomic replacement.
`BootstrapState::decode()` checks exact framing, version, count, usable addresses,
and duplicate IDs/endpoints. No identity secrets, cookies, Noise sessions, old
provider leases, or monotonic deadlines are persisted.

On a fresh node, subscribe and call `restore_bootstrap(&state).await`, then await
that query's `LookupDone`. Saved hints do not become trusted routes until normal
identity/reachability verification completes. Use additional configured seeds if
saved contacts are stale. The application must preserve its identity separately,
restart its listener/publications, and reconnect with fresh authenticated sessions;
this API does not transparently migrate an existing data socket.

### Network changes and resumable transfers

`Endpoint::network_changed(bind, seeds).await` replaces the DHT UDP socket while
keeping the actor and listener alive. Use port zero for a fresh socket. Binding
happens before replacement, so a bind failure preserves the existing endpoint.
Once committed, cancellation does not undo the replacement. A listener remains
published and the call waits for its first fresh registration acknowledgement;
that acknowledgement is not a redundancy guarantee. Calls through one endpoint
serialize, and the configured connection deadline bounds the acknowledgement wait.

The core clears old route reachability, endpoint cookies, outer transport sessions,
pending RPCs/lookups, and signaling exchanges. It uses fresh cookie entropy,
retains identity and signaling keys, preserves stored values with their existing
expiry, and restarts active topic publications from new seeds and previous hints.
Keeping the signaling key allows still-live discovery records to coexist with
renewed registrations during recovery. Query/nonce counters are not reset.
`Event::NetworkChanged(generation)` interrupts old operations; consumers should
retry on the new network. Existing remote routing caches still follow their
normal expiry policy; this is not immediate migration of a public routing server.

Data connections belong to the network generation in which their Noise handshake
completed. A local change aborts their receives/sends with `ConnectionAborted` and
stops their heartbeat tasks. A new connection performs discovery, encrypted DHT
signaling, nomination, and a fresh Noise handshake. No data-session counters or
keys are transplanted. Merely closing a listener or dropping the DHT handle does
not invalidate an otherwise healthy data connection.

For automatic handling, `Endpoint::watch_network(changes, seeds)` accepts a Tokio
watch receiver of bind addresses and returns a `NetworkMonitor`. The application
connects its OS network/resume notifications to this channel; this crate does not
install platform-specific interface watchers. The initial value is not applied.
Publishing the same address again requests recovery after sleep or NAT mapping
expiry. Notifications supersede pending recovery; failures retry with exponential
delays capped at 32 seconds. The monitor exposes Idle/Recovering/Ready/Failed status.
Dropping it cancels its task, while already-committed socket replacements remain.

`recover_blob(peer, seeds, &mut BlobDownload, transfer_config, policy)` reconnects
on transient connection/transport failures, retaining the verified manifest and
chunks in caller-owned state. `resume_blob` also exposes one-session continuation
without an automatic retry policy. Each replacement link starts fresh wire message
IDs. `recover_feed` tails from the replica's verified length and uses the replica's
feed-signing key, which need not equal the provider's connection identity.
Verification failures and identity-authentication failures are terminal. Network
failures during the Noise exchange may retry. `RecoveryConfig` bounds total
attempts and elapsed time; canceling leaves already-verified progress available.
The default total budget is eight attempts over five minutes, including healthy
feed streaming time. Applications wanting longer-lived subscriptions can call again
with the same replica after that budget ends.

Tests force a new bind on both endpoints and kill a coordinator after a blob chunk
has been verified, then assert that the manifest/chunk are not requested again.
The feed test changes the client socket after two verified blocks and asserts a
fresh session starts at that length, using a distinct feed key. Other tests cover
failed-bind rollback, repeated same-address resume notifications, monitor teardown,
old-cookie invalidation, and preserved content/publication intentions. They use
loopback UDP and explicit network notifications; they do not measure real Wi-Fi,
sleep/wake, or carrier NAT behavior.

## Per-source allocation bounds

These apply even under `RoutingPolicy::Unrestricted`, which disables routing and
lookup diversity only. IPv4 /24 and IPv6 /64 prefixes share canonicalization rules.

| Resource | Per identity | Per source prefix | Global |
| --- | ---: | ---: | ---: |
| Incoming packets per monotonic second | — | 64 | 256 |
| Cached request replies | 256 | 512 | 2,048 |
| Hosted provider registrations | 16 | 64 | 256 |
| Hosted values | 16 | 64 | 1,024 |
| Coordinator signaling exchanges | 8 | 32 | 128 |
| Provider incoming signaling sessions | 8 | — | 128 |
| Outer Noise sessions | 8 | 128 | 5,120 |

Existing renewals and cached replies do not consume a fresh slot. Rejecting an
over-budget prefix does not consume another prefix's remaining packet budget.
The epoch advances only with the monotonic clock, so clock rollback cannot refill
it. These bounds contain one identity/subnet's resource use; they do not solve
multi-prefix Sybil attacks.

## Resource bounds and verification

Hard ceilings: 16 publications with one lookup and up to three owned renewals each,
128 pending RPCs (including at most three routing-maintenance probes), 2048 routing
replacement candidates, 5120 Noise sessions, 5120 endpoint validation/RTT cache entries, 16 lookups with 128 candidates each, 256 hosted
registrations, 256 distinct local registration pairs (including managed intents), 128 each of coordinator,
incoming, and outgoing signaling sessions, 2048 replay-cache entries, and 20 routing
contacts per bucket (5120 total). Input parsing/verification has a global 256-packet
budget per supplied monotonic second and a 64-packet budget per source prefix;
output is returned immediately instead of queued forever.
These are conservative experiment constants, not tuned production defaults. The
prefix budget preserves capacity against one flooding subnet, but does not ensure
fairness against attackers spread across many prefixes.

RPCs start with a 500 ms retry interval when no RTT estimate exists. Clean replies
update a smoothed RTT and variation estimate; retry intervals stay within 200–4000
ms. Retransmitted replies do not become RTT samples (Karn's rule); they preserve
backoff until a clean sample is available. Retries back off exponentially with at
most four retransmissions per RPC. A request's absolute deadline is eight times its
initial retry interval, clamped to 2–8 seconds, and challenges cannot extend it.
Lookups retain a 40-second absolute deadline. Outgoing signaling has a separate
monotonic deadline in addition to its signed expiry.

`poll_timeout()` returns the earliest monotonic deadline for a retry, speculative
query, lookup expiry, signaling failover, or outgoing signaling timeout. Call `tick(Time)` then; a core
with no active operations, publications, managed registrations, or maintained routing
contacts does not need a periodic timer.
Unused stored state is pruned on incoming traffic/ticks. Managed registrations add
lease-renewal deadlines to this interface; optional routing maintenance adds contact
liveness, replacement checks, and randomized bucket-exploration lookups.

Run `cargo test -p dht-next -p driver` for deterministic network, real-UDP, and adversarial tests.
The [coverage-guided fuzz workspace](../fuzz/README.md) adds raw-datagram and
cookie-authorized signed-body campaigns with AddressSanitizer. The ignored
`cargo test -p driver --test next signaling_soak -- --ignored --nocapture` test
runs 100 real-UDP publication/discovery/coordinator-failover trials. Both have
bounded pull-request jobs in `.github/workflows/dht-fuzz.yml`.

Coverage includes:

- Client registration, multi-hop discovery, and signed offer/answer through two
  independent coordinators, with no direct client-to-client signaling datagrams.
- No routing admission before the challenge exchange; no client routing pollution.
- Twenty failed nearest candidates followed by a reachable farther candidate.
- Lost acknowledgement recovery without duplicate registration effects.
- Forged registrations, stolen cookies, mismatched response endpoints/types,
  repeated offers, forged answers, and attempted return-path redirection.
- Reusable grants, expiry/restart refresh, request authentication, clock
  jumps, RTT adaptation, and the speculative-query concurrency ceiling.
- Compact encryption, transcript binding, reordered packets, replay/tampering rejection,
  counter exhaustion, session expiry, and lost handshake/encrypted-reply recovery.
- End-to-end signaling confidentiality, signed key substitution, transcript binding,
  ciphertext corruption, maximum payloads, and answer retries after capacity errors.
- Automatic coordinator failover, lost return paths, deduplicated application offers,
  late answers, incompatible records, and bounded total call lifetime.
- Quiet routing contacts surviving multiple expiry periods, late bootstrap/discovery
  and encrypted signaling, bounded replacement caches, fresh promotion checks,
  failure versus newer activity, client-role downgrade, and maintenance cancellation.
- Automatic publication from one bootstrap hint, caller discovery and encrypted
  signaling, coordinator replacement, empty-bootstrap and capacity backoff, IP
  deduplication/cooldown, canceling discovery, and manual-ownership preservation.
- Managed renewal across multiple lease periods, signaling after the original lease
  expires, failed-coordinator recovery, stopping with an ACK in flight, out-of-order
  and expired ACKs, full registration capacity, and deferred renewal under RPC pressure.
- Lease expiry, pending-work and replay-cache saturation, datagram bounds, malformed
  bytes, strict versioning, and maximum IPv6 response sizes.

## Initial comparison (before the adaptive scheduler)

`cargo run -p dht-next --example lookup_fallback` runs the legacy and replacement
cores with twenty dead nearest contacts and one farther live candidate. The initial
result is legacy: no live result after 3500 virtual milliseconds; replacement: live
result after 28000 virtual milliseconds. The legacy query stops without trying the
farther peer; the new query continues after failures. The replacement's conservative
four-second RPC deadlines make this deliberately hostile case slow. This is evidence
of corrected fallback, **not a latency win** or a general benchmark. The next timing
work should improve that result without sacrificing the success guarantee.

The [paired lookup and signaling benchmark](benchmarks/dht-comparison.md) extends
this with healthy, high-RTT, lossy, and dead-peer scenarios. Raw per-trial results
and the reproducible command are included.

## Gates before public deployment

The [adaptive-scheduler report](benchmarks/dht-adaptive-comparison.md) records the
first performance phase, including 100 seeds per scenario. The
[peer-session report](benchmarks/dht-session-comparison.md) measures the subsequent
compact transport change. The [encrypted-signaling report](benchmarks/dht-encrypted-signaling-comparison.md)
measures mandatory end-to-end candidate encryption. Routing-identity separation,
operator diversity defenses, and mandatory outer encryption remain research/deployment
work. Signaling keys now rotate with bounded grace and retirement. Coordinator discovery/selection and
managed renewal are implemented for opted-in publications. The [failover report](benchmarks/dht-failover-comparison.md)
measures coordinator-path recovery;
these results do not establish parity with libtorrent or HyperDHT.

1. Topology/churn/loss trials and real HyperDHT/libtorrent loopback comparisons are
   recorded below. Extend these to independent regions and long-running workloads.
2. Validate routing/lookup/origin quotas against realistic subnet and churn distributions,
   add independently validated search paths and broader RTT-policy validation.
   Provider pagination and bounded per-source resource quotas are implemented.
3. Add stronger coordinator diversity/admission policy and broader failover-policy
   validation. Network-notification recovery, fresh-session transfer resumption,
   authenticated keepalives and restart contact snapshots are implemented. Wire
   platform-specific notifications into applications and test real network changes.
4. The explicit UDP adapter and public-key connection service are implemented and
   tested, including bounded one-sided birthday punching and opt-in PCP/UPnP leases.
   Validate independent regions, consumer routers and realistic NAT deployments.
5. Fixed v6 wire vectors, old-version rejection, property tests, and AddressSanitizer
   coverage-guided fuzz targets with bounded CI campaigns are implemented. Independent
   security review and sustained fuzz campaigns remain public-deployment gates.

Identity signatures prevent impersonation; they do not prevent Sybil identities,
malicious coordinators dropping traffic, routing-table concentration, or bootstrap
blocking. A complete public-network defense must address those explicitly.

## Current evaluation artifacts

- [Supplied-seed preservation and farther-seed discovery](benchmarks/dht-seed-hardening.md).
- [Malicious referrals, signaling blackholes, dishonest storage and identity concentration](benchmarks/dht-adversarial.md).
- [Topology, prefix concentration, loss, churn, and signaling](benchmarks/dht-topology.md).
- [Integrated value lookup and actual HyperDHT/libtorrent comparison](benchmarks/dht-value-lookup-comparison.md).
- [Historical v5 storage comparison](benchmarks/dht-external-comparison.md).
- Fixed protocol-v6 byte vectors live in `crates/dht-next/tests/vectors/`; property
  tests exercise arbitrary packets, signed malformed bodies, and mutable sequences.
