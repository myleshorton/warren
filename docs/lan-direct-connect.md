# `connect_direct` + cold-accept — dialing a LAN-discovered peer with no backbone

Follows `lan-discovery.md`, whose beacon half is built (`swarm::lan`, `driver::LanBeacon`): a
node now hears same-channel peers on the LAN as `(node_id, lan_addr)`. This spec is the second
half — **connecting** to one directly, with no DHT lookup and no coordinator-brokered punch.

## The crux: warren has no persistent accept endpoint

The obvious shape — "the acceptor listens on a well-known port; the initiator dials it" —
fights warren's connection model. A `Channel` **is** one UDP socket, and the punch primitives
consume it: `puncher::accept_any(socket, hosts, cfg)` waits for one `PROBE`, replies `ACK`, and
returns `Established { socket, peer }` — the socket becomes that one channel. There is no
"listening socket that yields many channels." In the DHT path this is fine: the coordinator
signals each inbound connect, and the node spins up a fresh data socket per signal. On the LAN
there is **no coordinator to signal an incoming connect** — that's the whole point — so we need
something to play the coordinator's "a peer wants to reach you, here's who" role, locally.

Two ways to supply it:

- **Option A (recommended): a tiny LAN control socket that brokers each connect**, then a
  normal per-connection punch. One persistent *unconnected* socket receives small `Connect`
  requests (it never becomes a channel), and each request spawns an ordinary
  `connect_to`/`accept` pair on fresh per-connection data sockets — exactly today's model,
  with the LAN itself replacing the remote coordinator.
- **Option B (rejected): a fixed advertised data port + a rebind-accept loop** (`SO_REUSEPORT`,
  re-bind a fresh socket after each `accept_any`). No new messages, but it leans on OS
  reuseport datagram distribution and races a `PROBE` against the moment between accepts. It's
  fragile and platform-dependent; Option A is barely more code and is robust.

The rest of this spec is Option A.

## The exchange (one message + a normal punch)

Deterministic roles avoid a double-connect: for a discovered pair, the **lower node id is the
Requester** (it calls `connect_direct`); the higher id is the **Responder** (its control loop
answers). So exactly one side initiates.

```
Requester A                                  Responder B
  bind fresh data socket SA
  send Connect{ node: A, topics, addr: SA }  ──►  B's control socket (from the beacon)
  accept_any(SA, [B's LAN host]) ── await ──          verify Connect (signed, same channel,
                                                       LAN source); bind fresh data socket SB;
                                              ◄──      connect_to(SB, SA)  ── PROBE SA
  PROBE arrives on SA → send ACK                       ── ACK arrives → Established(SB→SA)
  Established(SA→SB)                                    wrap SB as a Channel →
  → Channel → connect_direct returns it                surface via next_incoming()
```

Why this shape:
- **One control message.** The Requester advertises only *its* data address `SA`; the
  Responder dials it, so B never has to send its port back. (`connect_to`/`accept` are the
  existing PROBE/ACK primitives; on a LAN there's no NAT, so the punch is a formality that
  succeeds on the first probe — but reusing it keeps one code path.)
- **The channel lands where each side expects it.** The Requester gets its `Channel` back from
  `connect_direct` (like `connect()`); the Responder's `Channel` flows into the **existing**
  `incoming_tx` → `next_incoming()`, so the serve loop and the Noise-accept handle it
  identically to a DHT-punched inbound. Nothing downstream changes.
- **Identity is still bound by Noise, unchanged.** The Requester runs
  `NoiseLink::connect(channel, identity, peer_id)` (pins B's id); the Responder runs
  `NoiseLink::accept`, learning A's id from the XX handshake exactly as the DHT accept side
  does. The `Connect` message's signature is only a cheap garbage filter — a forged one costs
  one failed Noise handshake and nothing more.

## API + where it lives

The LAN subsystem folds into the `Node` (so the control loop can feed the node's `incoming_tx`,
and `connect_direct` can bind data sockets on the node's LAN IP the way `connect` does). The
standalone `LanBeacon` built in `driver::lan` becomes the node's LAN subsystem: **beacon +
provider set + control socket + Request loop**, started by a new `Node::bind_with_lan(...)`
(the plain `bind*` constructors leave LAN off, so existing callers/tests are unchanged).

- `Node::connect_direct(&self, peer_id: NodeId, control_addr: SocketAddr) -> Result<Connection, ConnectError>`
  — bind `SA` on the node's LAN IP, unicast a signed `Connect{node, topics, addr: SA}` to
  `control_addr`, `accept_any(SA, [control_addr.ip()])`, wrap the `Established` as a `Channel`,
  return `Connection { channel: Some(_), outcome: LanDirect }`. No `Command::Connect`, no DHT.
- **Cold-accept loop** (spawned by `bind_with_lan`): `recv` on the control socket; for each
  `Connect` that (a) is signed by a key hashing to a discovered provider, (b) shares one of our
  topics, and (c) comes from an **RFC1918 / link-local** source — bind `SB`, spawn
  `connect_to(SB, req.addr)`, and on success send the `Channel` to `incoming_tx`.
- `Connection`/`ConnectOutcome` gains a **`LanDirect`** variant so telemetry reads
  `connect X -> LanDirect` — we'll finally see LAN connects instead of `Relayed`.

Control message on the wire (its own small codec beside the beacon in `swarm::lan`):
`Connect{ version, key: PublicKey, addr: SocketAddr, topics: [Hash], sig }`, signed over
`(domain, key, addr, topics)` — the same discipline as `Beacon`.

## Session integration (`warren::session`)

- The session already holds the node; it reads `node.lan_peers()` (the provider set).
- For each channel peer, if a LAN provider exists **and** we are the lower node id, prefer
  `connect_direct(peer_id, control_addr)`; otherwise wait to be dialed (Responder) or fall back
  to the DHT `connect(peer_id)`. Dedup by `node_id` so a peer reachable both ways isn't fetched
  twice. `discover` / `subscribe` / `mirror` are otherwise unchanged — they consume the
  resulting `Channel`.
- Net: two same-wifi devices beacon, discover, the lower-id one `connect_direct`s over the LAN,
  the other accepts via its control loop, Noise binds both identities, and the feed syncs — with
  the backbone unreachable and behind a hostile shared NAT, because none of this leg touches
  either.

## Security

- **WAN safety.** The control loop accepts `Connect` only from RFC1918/link-local sources that
  match a discovered provider; `connect_direct` dials only such addresses. The control socket
  is never advertised off the LAN (its address rides only the link-local multicast beacon).
- **No impersonation.** Noise binds `peer_id` on both ends regardless of the `Connect`/beacon
  contents; forging either just wastes a handshake.
- **No amplification.** `Connect` is a single unicast reply-free request; the control socket
  never fans out.

## Testing

- **Codec** — `Connect` round-trip + `decode` never panics on garbage (as `Beacon`).
- **Two-node loopback, DHT disabled** — A `connect_direct`s B over a loopback control socket; B's
  cold-accept loop establishes; both wrap channels; a `NoiseLink` handshake completes and a feed
  syncs end to end — proving the leg needs no backbone. (Loopback + `SO_REUSEPORT`, like the
  beacon test; `#[ignore]` if the CI box lacks the multicast/loopback path, verified on a real
  host.)
- **Scoping** — a `Connect` from a non-LAN source, or for a topic we're not in, is refused; a
  forged signature is dropped.
- **Role dedup** — given a discovered pair, only the lower-id side issues a `Connect` (no double
  channel).

## Rollout

Additive: no DHT-wire or feed/blob-format change; `connect_direct` is a new path beside
`connect`; the control message is a new **local** protocol; `bind_with_lan` is opt-in. An
un-upgraded peer simply never beacons and is reached via the DHT as today. Sequence: `Connect`
codec (pure, tested) → fold `LanBeacon` into `Node::bind_with_lan` + the control/cold-accept
loop → `Node::connect_direct` + `LanDirect` outcome → session prefer-LAN + role dedup → iOS
multicast entitlement + a real two-device LAN test.

## Non-goals

Multi-path/latency-ranked provider selection beyond "LAN-first, lower-id-initiates"; connecting
LAN peers in *different* channels (topics gate it); a relay for symmetric↔symmetric peers on
*different* networks (separate work). Client-isolated APs remain unfixable at this layer.
