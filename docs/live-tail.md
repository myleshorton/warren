# Warren — live-tail feed replication

**Status: Layers 1 + 2 built (2026-07-11).** Server-push, resumable,
per-block-verified live replication ships across `sync` → `transfer` →
`warren::session`, now with swarm-failover subscription and blind-mirror
store-and-forward on top. A companion to [`design.md`](design.md).

**What shipped (Layer 1 — the primitive):**
- `sync`: a `Tail { have }` message + `FeedDownload::resume(pubkey, have)` — request,
  store, and return only `have..head.len`; the tail is transferred once, never
  re-fetched, and every block is still verified against the signed head.
- `transfer`: `serve_feed_tail` (holds a `Tail` at head until an `appended` signal
  or a keepalive, then pushes — the log is a `Mutex` locked per reply, never across
  the session, so a subscriber can't block appends) + `subscribe_feed` (the client
  loop). Tested end-to-end over a lossy link: a subscriber gets pre-existing blocks
  and each live append, no reconnect, no re-fetch.

**What shipped (Layer 2 — swarm-aware tailing + blind mirrors):**
- `feed`: a `Source` trait (implemented by both `Log` and a new read-only `Replica`)
  so the tail-serve path is generic over "a feed I own" vs "a verified copy I hold."
  `Replica::new` rejects a wrong-key, doctored, or truncated feed by construction, so
  a mirror is never trusted — every block still verifies against the author's key.
- `transfer`: `replicate_feed` (keep a `Replica` live from a provider) +
  `download_feed_full` (a one-shot download that also returns the signed head, what
  `Replica::new` needs to bootstrap).
- `warren`: a feed-discovery topic (`channel::feed_topic`) the author and every mirror
  announce under; `subscribe(feed_key, from, on_block)` is now *feed-centric* — it
  finds every provider and tails from one, **failing over** to another when a provider
  drops. `serve_by_key` serves our own log or a mirrored `Replica`; `mirror_feed` +
  `run_mirror` bootstrap and maintain a mirror. A DHT-backbone integration test proves
  the whole loop: author publishes → mirror replicates → author goes offline →
  subscriber fails over to the mirror and tails the full, verified feed.

**Layer 3 — deterministic multi-writer merge** (Autobase-style, for chat rooms where
many members write concurrently) — the *substrate* is now built too: `warren::merge`
(the convergent linearizer), the record clock, and `warren::room::Room`. See
[`multi-writer.md`](multi-writer.md). What remains is the app wiring (a chat client
driving the room view).

The original design follows, for the rationale.

## The problem

Warren's sync is **batch pull**. `transfer::download_feed`
(`crates/transfer/src/lib.rs:154`) opens a channel, pulls a feed up to its
current head, and returns; `serve_feed` (`:603`) answers requests until the
client goes idle. To see *new* appends, a consumer must reconnect and download
again — which is what the Murmur app does when it polls `refresh_feed()`.

That's the right shape for a **video feed**: you pull on demand, seconds of
latency are invisible, and the win is swarming a large blob from many sources.
It's the wrong shape for anything **real-time** (chat, live comments, presence),
where a new record must reach subscribers in ~hundreds of ms without a poll.

The unlock is a single primitive: **subscribe to a feed and receive its new
blocks as they are appended**, over a connection that stays open.

## What already exists (so this is additive, not a redesign)

- `feed::Log` is an append-only log with a monotonic `len()`, a **signed
  `head()`** that commits to the whole log, and per-block `proof(i)` /
  `verify_block_proof(head, i, block, proof)` (`crates/feed/src/lib.rs`). A
  subscriber that holds blocks `[0, n)` can verify block `n` against the current
  signed head — the exact check a tail needs on every new block.
- `driver::Channel` is a datagram link with `send` / `recv`; a punched
  `Connection` already carries one (`crates/driver/src/lib.rs`). `transfer::Link`
  (`:98`) is that same send/recv datagram abstraction, and `transfer` already has
  the reliable-delivery + repair machinery (`Wire`, `exchange`) on top of a lossy
  link.

Nothing new is needed at the transport or crypto layer. The work is a new
*mode* in `transfer`, plus keeping the connection open in the app.

## The primitive

```
transfer::subscribe_feed(channel, public_key, from, cfg, on_block)      // deliver each new block (verified) via on_block, from `from`
transfer::serve_feed_tail(channel, &Mutex<Source>, appended, cfg)       // serve + hold at head, pushing on each `appended` signal
```

Semantics: the client says *"I have feed `P` up to index `n` — send me `n` and
everything after it, and keep sending as the log grows."* The server verifies
against its own `head`, streams the missing blocks, then **stays attached** and
emits each subsequent `append` as a new frame. Every block the client receives
is checked with `verify_block_proof` against the latest signed `head`, so a live
block is exactly as trustworthy as a batch-downloaded one.

Contrast with `download_feed`, which returns once it reaches head. `subscribe`
*never returns at head* — head is where the interesting part begins.

## Two ways to implement it (build the first, keep the second in reserve)

1. **Held-cursor pull (minimal delta — recommended first cut).** Reuse the
   existing request/response + repair path almost unchanged. The only new
   behavior: when a "blocks after `n`" request reaches head, the server does
   **not** answer empty and end — it *holds* the request open until either a new
   block is appended (answer immediately) or a keepalive interval elapses (answer
   with a heartbeat). The client re-issues the next request as soon as it applies
   a response. This is `serve_feed` with "block at head instead of going idle,"
   and `download_feed` in a loop that advances `from_index`. Small, testable,
   and it inherits NACK/repair for free.

2. **Server push (optimization).** The server tracks attached subscribers and
   sends unsolicited `BLOCK{index, bytes, proof, head}` frames on append, saving
   the re-request round trip. Lower latency, but the wire must accept unsolicited
   frames and the server must track per-subscriber cursors. Worth it under load;
   not worth it for a first proof.

## Connection reuse

Live-tail only pays off if the connection is **long-lived**. Today the app does
one `connect` per request (fine to re-punch for a 5 MB clip, wasteful per "ok").
A real-time consumer should `connect` once per active peer and keep the
`Channel` open — subscribing to that peer's feed on it — instead of re-punching.
Multiplexing several feeds over one channel is the natural follow-on.

## What this primitive deliberately does *not* solve

- **Ordering across writers.** A tail delivers *one author's* log in order. A
  room view is many authors merged; a video wall merges newest-first by
  timestamp (fine), but a conversation needs causal/linearized order across
  writers (Keet's Autobase). That's a layer *above* this primitive.
- **Presence / typing.** Ephemeral signals must **not** land in a signed
  append-only log. Carry them as plain datagrams on the same open `Channel`
  (send/recv), never `append`ed. Separate, small, and out of scope here.
- **Offline delivery (store-and-forward).** A tail reaches only *online* peers.
  Offline delivery wants a **blind mirror that subscribes and retains**, then
  serves the absent author's blocks on demand — the mirror we already have,
  given a tail and a retention policy. A per-recipient inbox with receipts is a
  further step. (Note the usual tension: any always-on retainer is a small fixed
  surface — keep it blind, keep it optional; see [`design.md`](design.md).)

## Scope / first build

1. `serve_feed_tail` + `subscribe_feed` via the held-cursor approach (#1),
   reusing `Wire`/repair. Verify every block against the signed head.
2. A loopback test: writer appends while a subscriber is attached; assert the
   subscriber observes each append, in order, verified, without re-connecting.
3. App: keep one `Channel` per active peer and subscribe on it, replacing the
   poll in the real-time path. (Murmur's video feed can keep polling — it does
   not need this.)

Everything past step 1 (server push, cross-writer ordering, store-and-forward)
is independent follow-on work. The point of this note is that the *substrate* —
signed append-only logs with per-block proofs over a persistent datagram
channel — already supports a live tail; only a new `transfer` mode is missing.
