# holepunch (working name)

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
| **Loopback integration** (planned) | Real UDP sockets, real punching, on one host | `swarm` |
| **Fault injection** (planned) | Drops, reorders, corruption, partitions | `swarm`, `log` |
| **Corpus / golden files** (planned) | Wire format stays stable across versions | `wire`, `log` |
| **Live demos** (planned) | A human can watch it work (network forming, a video streaming) | binaries |

## Layout

```
crates/
  wire      byte-level codec (varints, length-delimited frames)    — done
  crypto    ed25519 identity, blake3 hashing, discovery keys        — done
  swarm     sans-IO Kademlia DHT + deterministic network simulator  — phase-0 scaffold
  (next: NAT lifecycle + hole punching, real UDP driver, blob, log, ...)
```

Try the DHT: `cargo run -p swarm --example dht_sim` watches a 30-node network
bootstrap itself and answer a lookup.

Crates are `publish = false` while the design settles. Names are role-based and
unprefixed for clean internal imports.
