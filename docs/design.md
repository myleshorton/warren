# Warren — design and threat model

Warren is a fully decentralized, serverless peer-to-peer stack: the substrate for
sharing large immutable content (its first target is non-copyrighted video)
directly between peers, with no servers, trackers, or coordination infrastructure
in the data path. It is built layer by layer, verification-first — every layer
ships with the means to verify it.

This document explains **why the design is what it is** (its advantages), then the
**threat model** it must survive if it gains adoption — including an *active*
censoring adversary — and the mitigations that follow.

---

## Why Warren is built this way

**1. Serverless by construction — nothing to seize or block centrally.**
Peers find each other over a distributed hash table and connect *directly* via UDP
hole punching. There is no relay, tracker, or rendezvous server in the data path,
so there is no central host to subpoena, seize, rate-limit, or add to a blocklist.
The cost of this choice is that connectivity is hard (NAT traversal), which is why
much of the stack is about punching and reliable direct transport.

**2. Trust the content, not the peer.**
Everything is *content-addressed and verified*:

- a **blob** is split into chunks, each named by its BLAKE3 hash; the list of
  chunk hashes (the *manifest*) is itself hashed, and that hash is the blob's
  address;
- a **feed** is a signed append-only log: a `(len, root)` head signed by the
  owner's key, plus a per-block Merkle inclusion proof.

A peer therefore *cannot serve you a bad byte*: you verify every chunk against the
hash you asked for and every block against a proof rooted in a signed head, using
only the key/hash you already hold — regardless of who sent it. This is the
property that makes everything else safe, and in particular makes **multi-peer
swarming** possible: any peer holding a chunk is interchangeable, because trust is
in the hash, not the source.

**3. One key, two jobs.**
A feed's public key is simultaneously *what to verify against* and *where to
find it* — a viewer who knows only the key can both discover the publisher and
verify every byte it sends. (This elegance has a censorship cost — the key becomes
a locator for the publisher — which we address in the threat model by decoupling
the DHT node id from the content key.)

**4. Sans-IO, adversarially-verified cores.**
The security-critical logic — DHT routing, the sync protocol, feed/blob
verification, and the transport's reliability — is written as *pure state
machines with no sockets and no clock*. The security question ("can a malicious
peer make us accept bad data, wedge our session, or exhaust our memory?") is
answered by deterministic, adversarial unit tests, not by hope or by watching it
run. Liveness (dropping a stalled peer) is delegated to the thin I/O layer, which
alone has a clock. This is why the same core verified in a deterministic simulator
runs unchanged over real sockets.

**5. A real transport, from scratch, over hole-punched UDP.**

- **NAT traversal** — DHT-brokered hole punching, including a *birthday* punch for
  the hard symmetric-NAT case. (Symmetric↔symmetric pairs are left unconnected by
  design: relaying their data would overload relays in a serverless model.)
- **Fragmentation** — messages larger than a datagram are split into MTU-sized
  pieces and reassembled, so large content isn't blocked by IP-layer fragmentation
  or platform datagram caps (e.g. macOS's 9216-byte limit); the default 64 KiB
  chunk, which no datagram can carry, syncs unchanged.
- **Selective-repeat reliability** — a lost fragment is repaired with a single
  NACK + resend, not a whole-message retransmit.
- **Congestion control** — an AIMD window paced across a *measured* RTT, so a
  large transfer adapts to the path instead of blasting it.
- **Swarming** — a blob's chunks are fetched from *several providers at once*,
  verified by hash, with a dropped provider's chunks re-partitioned to the rest.

**6. Collateral-freedom by lineage.**
The DHT is Kademlia — the same family as BitTorrent's Mainline DHT (millions of
nodes) and Hyperswarm. Warren therefore already lives in a traffic class a censor
cannot block wholesale without breaking mainstream peer-to-peer use. Blending
further (obfuscation, or riding an existing public DHT) is a *pluggable transport
seam*, not baked into the protocol.

---

## Architecture

Role-based crates, each a single responsibility, stacked lowest to highest:
`crypto`, `wire` → `feed`, `blob` → `sync` → `swarm`, `puncher` → `driver` →
`transfer`. The lower half is pure and sans-IO; `driver` and `transfer` are the
thin I/O layers that pump those cores over real sockets. See the repository
README for the full ladder and what each crate does.

---

## Threat model

Warren's primary context is the uncensored internet; its secondary, valuable
context is **domestic** peer-to-peer use *inside* censored countries — peers
reaching one another over the less-filtered national network rather than across
the censored international gateway. In both, the adversary can be an active,
adaptive censor, and we treat that as first-class rather than assume obscurity.

### Passive adversary (traffic analysis)

An on-path observer that classifies flows by size/timing/fingerprint. Documented
separately; the mitigation is the pluggable obfuscated transport seam and
MTU-sized, paced traffic that need not look distinctive.

### Active adversary (the censor)

If Warren gains adoption, the attack is well understood — and cheap. Measurement
work across 36 P2P networks (Kiffer et al., *Multiple Sides of 36 Coins*,
SIGMETRICS 2026) shows enumeration is turnkey:

- **Bootstrap blocking.** A fixed, well-known entry-node set is the cheapest
  chokepoint.
- **Enumeration.** Crafted `FIND_NODE` walks dump a peer's routing table
  bucket-by-bucket; *fewer than five contacted nodes* can reveal ~90% of a
  network's reachable peers — a blocklist of every participant.
- **Internet-wide fingerprinting.** A single scan of the default port with a
  protocol-specific payload identifies participants without joining the DHT.
- **Targeted surveillance.** A Sybil positioned near a content id in the key-space
  observes who *announces* (serves) and who *looks up* (fetches) that content.
- **Warren-specific exposure.** Because a feed's public key doubles as its DHT
  node id, anyone who knows a feed key can locate its publisher's node directly.

### Mitigations

**Decouple the DHT node id from the content key.** Publishers use a random
(or ephemeral) node id and advertise content under a *topic*, so knowing a feed
key no longer points at the publisher's node/IP.

**Blinded, rotating topics.** Announce and look content up under a *derived* topic
rather than the cleartext content id, so a crawler near the key-space sees opaque,
rotating identifiers instead of "provider of banned content X." Two regimes:

- *Key-blinded* — `topic = H(feed_key ‖ epoch)`. Any viewer who knows the feed
  key (as they must, to verify) can compute it; a censor who does *not* have that
  specific key sees only rotating opaque ids and cannot cheaply catalogue the
  network or keep a pre-computed blocklist current. Free — no extra coordination.
- *PSK-blinded* — `topic = HMAC(PSK, feed_key ‖ epoch)`. Only holders of a channel
  pre-shared key can derive the topic, so a censor with the feed key but not the
  PSK is blind. Stronger, at the cost of distributing the PSK out-of-band (the
  classic bootstrapping problem); opt-in, for private channels.

Rotation is **time-synchronized**: `epoch = floor(now / epoch_len)`, so every
participant computes the *same* topic in a given epoch — the provider set does
**not** fragment. Providers re-announce each epoch (piggybacking the DHT's
existing re-announce cadence, so we keep `epoch_len` at least that interval), and boundaries are
covered by **overlap** — providers announce under the current *and* next epoch,
viewers look up the current *and* previous — so clock skew never opens an
availability gap. `epoch_len` is **tunable**: shorter tightens the correlation
window a censor gets but adds re-announce churn; longer reduces churn but widens
the window.

**Ephemeral / query-only clients.** A pure fetcher never joins others' routing
tables, so it isn't enumerable *as a node*.

**Obfuscated, pluggable transport.** Both the DHT and data planes can run under a
wrapping transport (or be tunneled) so participation doesn't fingerprint as
Warren; this is a seam, not a core change.

**Cover via an existing DHT.** Because Warren is Kademlia, discovery can ride a
large public DHT (Mainline/Hyperswarm): a ready-made anonymity set and
collateral-freedom (blocking it breaks mainstream P2P). This secures only the
discovery plane, so it must be paired with blinded topics (public-DHT
announcements are themselves crawled) and transport obfuscation.

**Bootstrap resilience.** Many rotating bootstraps reachable via a
censorship-resistant rendezvous, rather than a fixed, blockable set.

### Usage guidance

- **Clients (consumers):** run query-only/ephemeral; *fetch, never announce* under
  threat; look content up under blinded topics; run over the obfuscated transport.
- **Providers (circumvention infrastructure):** advertise blinded topics so
  enumeration yields opaque ids, not "provider of banned content X"; use the DHT
  only for rendezvous while bulk data rides the punched direct channel, off the
  observable DHT; use resilient rotating bootstrap.

---

## Status

| Capability | State |
| --- | --- |
| DHT discovery, hole punching (incl. birthday punch) | built |
| Signed feeds, content-addressed blobs, verified sync | built |
| Reliable transport: fragmentation, selective repeat, AIMD + RTT pacing | built |
| Multi-peer swarming (full seeders, round-based) | built |
| Decoupled node id / blinded rotating topics | planned (this doc) |
| Ephemeral/query-only client mode | planned |
| Obfuscated transport, cover-DHT rendezvous | planned |
| Holdings-aware (partial-seeder) swarming, rarest-first | planned |
