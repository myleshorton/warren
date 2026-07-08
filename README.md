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
| **Property tests** (proptest) | Invariants hold for *all* inputs; no panics on adversarial bytes | `wire`, `crypto` |
| **Known-answer tests** | Bit-exact match to published spec vectors (RFC 8032, BLAKE3) | `crypto` |
| **Deterministic sim** | Multi-node behavior under a controlled clock/network — no flakes | `swarm` |
| **Oracle checks** | Lookup results verified against a brute-force ground truth | `swarm` |
| **Statistical guardrails** | Probabilistic behavior (birthday punch) measured against its analytic bound; fails if constants weaken | `swarm` |
| **Loopback integration** | Real `tokio` UDP sockets on one host: bootstrap, announce, lookup, connect | `driver` |
| **Real-socket punching** | Actual UDP hole punching on one host — direct, dial, and a real birthday port-collision | `puncher` |
| **Fault injection** (planned) | Drops, reorders, corruption, partitions | `swarm`, `log` |
| **Corpus / golden files** (planned) | Wire format stays stable across versions | `wire`, `log` |
| **Live demos** (planned) | A human can watch it work (network forming, a video streaming) | binaries |

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
  driver    tokio UDP driver: the sans-IO core over real sockets, async API
  puncher   real-UDP hole punching: simultaneous open / dial + birthday spray

  next: wire the puncher into the driver's connect, port mapping, blob, log, ...
```

Try it:
- `cargo run -p swarm --example dht_sim` — a 30-node DHT bootstraps and answers a lookup.
- `cargo run -p swarm --example nat_sim` — a node classifies its own NAT by probing the swarm.
- `cargo run -p swarm --example punch_sim` — hole-punch success rate across every NAT pairing.
- `cargo run -p swarm --example connect_sim` — two NATed peers connect by id, coordinated over the DHT.
- `cargo run -p driver --example two_node` — the same connect, over **real UDP sockets** on loopback.

Crates are `publish = false` while the design settles. Names are role-based and
unprefixed for clean internal imports.
