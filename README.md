# Warren

*A warren is a network of interconnected burrows — many entrances, no center.*

A fully decentralized, serverless peer-to-peer stack in Rust — the substrate for a
P2P video platform for non-copyrighted content. Design rationale lives in
[`PEAR-ARCHITECTURE-AND-RUST-DESIGN.md`](./PEAR-ARCHITECTURE-AND-RUST-DESIGN.md).

This repo is built layer by layer, and **every layer ships with the means to
verify it**. Correctness is not asserted; it is demonstrated.

## Verify

One command runs the same gate CI runs:

```sh
make verify        # fmt-check + clippy (deny warnings) + tests + doc
```

Individual gates:

```sh
make test          # unit + integration + property tests
make test-deep     # property tests with 100k cases each (deeper fuzzing)
make clippy        # lint, warnings are errors
make fmt           # auto-format
make doc           # build docs, broken links are errors
```

## The verification ladder

Each layer is validated with the strongest technique that fits its shape. As
layers get less pure (network, timing, disk), we add heavier tooling rather than
accept weaker guarantees.

| Technique | What it proves | Where |
|---|---|---|
| **Unit tests** | Hand-picked cases, edge conditions, error paths | every crate |
| **Property tests** (proptest) | Invariants hold for *all* inputs; no panics on adversarial bytes; every Merkle proof verifies and tampering always fails; blobs round-trip and chunks are self-verifying | `wire`, `crypto`, `feed`, `blob` |
| **Known-answer tests** | Bit-exact match to published spec vectors (RFC 8032, BLAKE3) | `crypto` |
| **Two-party protocol loop** | A client and server state machine driven against each other with no I/O; a malicious server never makes the client accept bad data | `sync` |
| **Deterministic sim** | Multi-node behavior under a controlled clock/network — no flakes | `swarm` |
| **Oracle checks** | Lookup results verified against a brute-force ground truth | `swarm` |
| **Statistical guardrails** | Probabilistic behavior (birthday punch) measured against its analytic bound; fails if constants weaken | `swarm` |
| **Loopback integration** | Real `tokio` UDP sockets on one host: bootstrap, announce, lookup, a one-call `connect(id)` that punches a live channel, and a feed/blob downloaded + verified over a punched channel | `driver`, `transfer` |
| **Real-socket punching** | Actual UDP hole punching on one host — direct, dial, and a real birthday port-collision | `puncher` |
| **Fault injection** (planned) | Drops, reorders, corruption, partitions | `swarm`, `feed` |
| **Corpus / golden files** (planned) | Wire format stays stable across versions | `wire`, `feed` |
| **Live demo** | A human can watch the whole stack work: DHT forms, a viewer discovers a publisher by key, punches a connection, streams a signed feed, verifies every frame | `transfer` |

## Layout

```
crates/
  wire      byte-level codec (varints, length-delimited frames)    — done
  crypto    ed25519 identity, blake3 hashing, discovery keys        — done
  swarm     sans-IO Kademlia DHT + deterministic network simulator  — phase-0
            + NAT self-classification (wired into DHT ping sampling)
            + hole-punch strategy/birthday model + packet-level NAT model
            + announce/lookup + DHT-coordinated connect (discovery →
              coordinator-brokered signaling → punch)
            + Reflect/Reflected: a reflexive (STUN-like) probe a peer echoes,
              exempt from routing so a transient socket can't poison the table
  driver    tokio UDP driver: the sans-IO core over real sockets, async API
            + Channel/DataListener: live data channels via the puncher
            + connect(id) -> Connection { outcome, channel }: discover +
              coordinate + punch in one call; inbound channels surfaced via
              Node::next_incoming; symmetric-NAT (Punched) connects run the
              birthday spray/open-sockets punch, chosen by the resolved strategy
            + reflexive discovery: both dialer and target probe a reflector to
              advertise their data socket's external address (NATed peers punchable)
  puncher   real-UDP hole punching: simultaneous open / dial + birthday spray
  feed      signed append-only log (the "log"/hypercore role): BLAKE3 Merkle tree
            over blocks, a signed (len, root) head, and per-block inclusion proofs
            a peer verifies with only the owner's public key — the basis for
            sparse random-access sync. (Named `feed`, not `log`, to avoid the
            crates.io logging-facade collision.)
  blob      content-addressed store for large immutable data: split into chunks
            named by their BLAKE3 hash (self-verifying, dedup), a Manifest listing
            them whose own hash is the blob's address, and a Store that reassembles
  sync      sans-IO synchronization for both data primitives: FeedDownload
            (head + blocks, verified against the feed's public key) and
            BlobDownload (manifest + chunks, verified by content hash), with
            serve_feed/serve_blob answering from a local Log/Store. Pure
            request/response messages — the driver pumps them over a channel.
  transfer  runs sync over any Link (driver::Channel, or a test's lossy link):
            download_feed/download_blob (client) and serve_feed/serve_blob
            (server). A message larger than a datagram (a chunk, a block with its
            proof, a manifest) is split into MTU-sized fragments and reassembled
            on the far side — so the default 64 KiB chunk, which no datagram can
            carry, syncs unchanged. Reliability is selective repeat: a stalled
            receiver NACKs the fragment indices it's missing and the sender
            resends only those, so one lost fragment costs one datagram to
            recover, not the whole message. The seam where the data layer finally
            rides the transport over a real connection.

  next: congestion control / pacing (bound fragments in flight), port mapping,
        an incremental Merkle accumulator for feed, ...

  not planned: a relay data path for symmetric↔symmetric NAT pairs — relaying
        peer data would load relays too heavily for the serverless model, so
        such pairs are left unconnected (a `Relayed` connect reports no channel).
```

Try it:
- `cargo run -p swarm --example dht_sim` — a 30-node DHT bootstraps and answers a lookup.
- `cargo run -p swarm --example nat_sim` — a node classifies its own NAT by probing the swarm.
- `cargo run -p swarm --example punch_sim` — hole-punch success rate across every NAT pairing.
- `cargo run -p swarm --example connect_sim` — two NATed peers connect by id, coordinated over the DHT.
- `cargo run -p driver --example two_node` — a single `connect(id)` over **real UDP sockets** discovers, coordinates, and punches a live data channel; bytes flow.
- `cargo run -p transfer --example stream` — the whole stack: a viewer discovers a publisher by key, punches a connection, and streams a signed feed back over real UDP, verifying every frame — no server in the path.

Crates are `publish = false` while the design settles. Names are role-based and
unprefixed for clean internal imports.
