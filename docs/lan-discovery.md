# LAN discovery + local-direct connect

Let two devices on the **same local network find and connect to each other without the
backbone** — no DHT rendezvous, no coordinator-brokered hole punch, no NAT traversal. This is
the highest-leverage connectivity fix the field telemetry keeps pointing at: on a plane, in a
hospital, on café/hotel wifi, the remote rendezvous is often unreachable (UDP blocked) or the
two devices are behind a hostile shared NAT (symmetric, no hairpin) — yet they're one hop
apart on the LAN. Discovery and the punch are separate legs (see
`murmur-connectivity-failure-modes`); this bypasses **both** for same-network peers.

It does **not** help when the access point enables **client isolation** (many plane APs, some
enterprise wifi) — then peers can't exchange packets at all, and nothing at this layer can fix
it. It *does* help home / office / hospital / hotel wifi that permits client-to-client traffic.

## Cross-platform principle: one implementation in warren

This lives in **warren (Rust)**, not per-platform. The obvious Apple path — Bonjour via the
Network framework — is macOS/iOS-only and would mean re-implementing discovery three times
(Swift, Kotlin, …). Instead: a **UDP multicast beacon over `std::net::UdpSocket`**, which is
identical on Linux, macOS, Windows, and Android, so every current and future client gets LAN
discovery from the shared substrate.

The one platform wrinkle is **iOS**: since iOS 14, sending/receiving multicast (or broadcast)
requires the **`com.apple.developer.networking.multicast`** entitlement — a special entitlement
you request from Apple (granted for exactly this: local peer discovery). Raw multicast from
Rust needs it; Bonjour-via-`mDNSResponder` would be exempt, but that's the Apple-only path we're
declining for cross-platform. So: **request the multicast entitlement** for the iOS/Catalyst
build; every other platform needs nothing special (Android needs a `MulticastLock` + the
`CHANGE_WIFI_MULTICAST_STATE` permission, handled in its shell when we get there). iOS/macOS
also show the **local-network privacy prompt** on first use — needs `NSLocalNetworkUsageDescription`
and (iOS) a `NSBonjourServices`/multicast declaration in Info.plist.

## Piece 1 — the discovery beacon (`warren`/`swarm` `lan` module)

A small always-on task per node:

- **Group + port.** Join a fixed site-local multicast group (e.g. `239.x.y.z:PORT`) — link-local
  scope so it never leaves the LAN. One well-known port for the whole app.
- **Beacon (sent every ~2–5 s, and on a "someone new appeared" trigger):**
  `{ version, node_id, data_addrs: [SocketAddr], blinded_topics: [Hash], sig }`
  - `data_addrs` — the node's **LAN** data-socket address(es) (its `192.168/10./172.16` address
    + port), where a peer connects directly. Not the reflexive/external address — this is a LAN
    conversation.
  - `blinded_topics` — the **blinded, per-epoch channel topics**
    (`crypto::PublicKey::blinded_topic(epoch)`) the node participates in, current + previous
    epoch. This is how a peer recognizes "same channel as me" **without the channel being
    legible to anyone else on the LAN** — a passive observer sees rotating opaque hashes, not
    which channel you're in. (Reuses the exact blinding the DHT already uses, memory #23.)
  - `sig` — the node signs the beacon under its identity. Not load-bearing for safety (a
    forged beacon just points you at an address where the **Noise handshake will fail to bind
    the claimed node id** — see piece 2 — so spoofing wastes one connect attempt and no more),
    but it lets a receiver drop obvious garbage cheaply.
- **On receipt:** if any `blinded_topic` matches one we care about, surface the peer as a
  **local provider** `(node_id, lan_addr)` — deduped by `node_id`, with a short TTL so a peer
  that stops beaconing (left the LAN) ages out. Ignore our own beacons (match `node_id`).

Sans-IO discipline: the beacon **codec** (encode/decode + the topic-match + provider-set
logic) is pure and property-tested; only the socket join/send/recv is I/O. `decode` never
panics on hostile bytes (same bar as `sync`/`wire`).

## Piece 2 — local-direct connect (`driver`)

Given a `(node_id, lan_addr)` from the beacon, connect **without the DHT/coordinator**:

- **`Node::connect_direct(peer_id, addr) -> Connection`**: reuse the low-level
  [`open_channel(bind, peer, cfg)`] primitive to establish a UDP channel straight to `addr`
  (both on the LAN → no NAT between them, so no punch is needed), then run the **same
  `NoiseLink` handshake pinned to `peer_id`** the DHT path uses. Identity binding is unchanged:
  a peer whose key doesn't hash to `peer_id` is rejected (`PermissionDenied`), so a spoofed
  beacon can't impersonate anyone. No `Command::Connect`, no `Event::Connected`, no signaling —
  it's the punch-less sibling of `connect`.
- **Accept side — cold incoming.** Today the accept path (`DataListener::accept` /
  `puncher::accept`) expects a punch from a `peer_host` it was told about via signaling. A
  LAN-direct dial arrives **cold** (no prior signal). The driver needs to accept an unsolicited
  data-socket channel from a LAN source and surface it via the existing `next_incoming()`
  stream (then the normal Noise-accept + serve loop take over). This is the one genuinely new
  driver behavior; gate it so it only applies to LAN-scoped source addresses (RFC1918 /
  link-local), never the public internet, to avoid opening a cold-connect surface on the WAN.
- `ConnectOutcome` gains (or reuses) a `Direct`-class result labelled LAN so telemetry shows
  when a connection was local — we'll finally see "connect X -> LanDirect" instead of `Relayed`.

## Session integration (`warren::session`)

- The `lan` task feeds discovered `(node_id, lan_addr)` providers into the session (a shared
  set, like the peer cache).
- `discover` / `subscribe` / `mirror` **prefer a LAN provider when one exists** for a peer:
  `connect_direct(id, lan_addr)` first, fall back to the DHT `connect(id)` only if there's no
  LAN entry or the direct dial fails. Dedup by `node_id` so a peer reachable both ways isn't
  fetched twice.
- Everything downstream (feed sync, blob swarm, windowed mirror) is unchanged — it operates on
  the resulting `Channel`, indifferent to how it was established.

Net effect for the field cases: two devices on the same wifi (that isn't client-isolated)
announce beacons, see each other's matching blinded topic, `connect_direct` over the LAN, and
sync — **even with the backbone unreachable and behind a hostile symmetric NAT**, because the
LAN path touches neither.

## Security / privacy

- **No channel leak on the LAN**: only blinded per-epoch topics are broadcast; an observer
  can't tell which channel (or that two rotating hashes are the same channel across epochs).
- **No impersonation**: the Noise handshake binds `peer_id` regardless of what the beacon
  claimed; a forged beacon costs one failed connect.
- **WAN safety**: cold-accept is restricted to LAN-scoped source addresses; the beacon is
  link-local-scoped multicast and never routed off the segment.
- **Amplification/abuse**: beacons are tiny, rate-limited, and only multicast to the local
  group; no unsolicited unicast to strangers.

## Testing

- **Codec** — property test: `decode(encode(beacon)) == beacon`; `decode` never panics on
  arbitrary bytes; topic-match + provider-set (add/dedup/TTL-expire) as a deterministic unit.
- **Loopback multicast** — two `Node`s on `127.0.0.0/8` (or a test multicast group): A beacons,
  B receives + surfaces A, B `connect_direct`s A, Noise completes, a feed syncs — all with the
  DHT/coordinator explicitly disabled, proving the leg is backbone-free.
- **Cold-accept scoping** — a cold dial from a non-LAN source is refused; from a LAN source is
  accepted.

## Rollout

Purely additive: no change to the DHT wire protocol or the feed/blob formats. The beacon is a
new **local** protocol (its own multicast group/port); `connect_direct` is a new path beside
`connect`; the session prefers LAN when available and otherwise behaves exactly as today, so it
interoperates with un-upgraded peers (they just don't beacon, and are still reached via the
DHT). Sequence: beacon codec + provider set (pure, tested) → the multicast I/O task →
`connect_direct` + cold-accept in `driver` → session prefer-LAN wiring → the iOS multicast
entitlement + local-network Info.plist + a device test on non-isolating wifi.

## Non-goals

Internet-wide discovery (that's the DHT's job); NAT traversal (a LAN needs none); a data relay
(orthogonal — the fallback for symmetric↔symmetric peers on *different* networks, tracked
separately). Choosing *which* provider to prefer beyond "LAN first" (latency-ranked multi-path)
is a later optimization.
