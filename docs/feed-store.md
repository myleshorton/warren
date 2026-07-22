# A redb-backed storage substrate for `feed`

## Motivation

`feed::Log` and `feed::Replica` are **in-memory**: each holds every block (`Vec<Vec<u8>>`)
and every leaf hash (`Vec<Hash>`) in RAM, and inclusion proofs (`tree::audit_path`) are
**recomputed from all leaves — O(n), all leaves resident**. Persistence is a hand-rolled
`warren::store` (append-line file + `rebuild` on boot) whose write atomicity is unproven.

That's fine for the sim and small feeds, but it blocks three things we actually want:

1. **The always-on seeder in the iOS VPN Network Extension** must fit a **~52 MB jetsam
   budget** (see `ios-vpn-extension-seeder.md`). A resident node holding whole feeds +
   whole mirrors in RAM blows that budget on the first busy channel. Storage must be
   disk-native with a bounded working set.
2. **Sparse replication** — the live-feed mirror work (`live-tail.md`) holds *whole*
   replicas; a seeder should be able to hold/serve a subset (recent blocks, or only what
   it's asked for) and still verify each block.
3. **Crash-safety** — an append that writes block + tree + head must be all-or-nothing, or
   a kill mid-write corrupts the signed log.

Goal: put block + Merkle-tree storage behind a `FeedStore` trait with an embedded,
crash-safe, disk-native backend — **without** losing the sans-IO/deterministic-sim
discipline that lets us verify the core.

## Non-goals

- Not reimplementing all of Corestore/hypercore (Autobase multi-writer, Hyperbee, browser
  RAS backend are out — see the Keet comparison in `PEAR-ARCHITECTURE-AND-RUST-DESIGN.md`).
- Not changing the **wire** protocol (`wire-protocol.md`) or the signed-log crypto — the
  `Head`/`Proof`/verification semantics are unchanged; only where bytes live changes.
- Not touching the sans-IO DHT/driver core — they don't hold feeds.

## The dependency decision (redb)

Warren has held a near-zero-dep line, but a storage substrate inherently needs a storage
engine, and the choice is confined to the `feed`/store layer — the sans-IO core stays
dep-free. **redb**: pure-Rust, ACID via a copy-on-write B-tree (MVCC: readers never block
the writer), single memory-mapped file, no C/unsafe-FFI → **cross-compiles cleanly to
`aarch64-apple-ios` / `-sim` / `-macabi` and Android**, which is the deciding factor.
Rejected alternatives: `sled` (effectively unmaintained, format churn), `sqlite`/`rusqlite`
(C dep — cross-compile + xcframework friction), raw `random-access-storage` reimpl (rebuilds
crash-safety we'd get for free). **Pre-commit due diligence:** confirm redb's max value size
covers our largest block, and build it for all four Apple targets + Android in a throwaway
branch before adopting.

## Design

### 1. The `FeedStore` trait

A typed, **synchronous** store (redb is sync + fast; async wrapping is the caller's job —
see §6). Batches are atomic — an append commits block + new tree nodes + new head together.

```rust
pub type FeedKey = [u8; 32];

/// One atomic unit of feed growth.
pub struct Batch {
    pub blocks: Vec<(u64, Vec<u8>)>,   // (index, bytes)
    pub nodes:  Vec<(u64, Hash)>,      // (flat-tree node index, hash) — see §3
    pub head:   Option<Head>,          // the new signed head
}

pub trait FeedStore: Send + Sync {
    /// Apply a batch atomically (all-or-nothing across a crash).
    fn commit(&self, feed: &FeedKey, batch: Batch) -> io::Result<()>;
    fn block(&self, feed: &FeedKey, index: u64) -> io::Result<Option<Vec<u8>>>;
    fn node(&self, feed: &FeedKey, index: u64) -> io::Result<Option<Hash>>;
    fn head(&self, feed: &FeedKey) -> io::Result<Option<Head>>;
    fn has_block(&self, feed: &FeedKey, index: u64) -> io::Result<bool>;
    /// Present block indices for a feed (for sparse serving); a range/iterator so we
    /// never materialize a whole feed to answer "what do I have".
    fn present(&self, feed: &FeedKey) -> io::Result<PresentSet>;
    /// Feeds we hold anything for — replaces the ad-hoc `mirrored` map + `store` scan.
    fn feeds(&self) -> io::Result<Vec<FeedKey>>;
}
```

Two impls:
- **`MemStore`** — `HashMap`-backed, no disk. Keeps the swarm sim and warren integration
  tests deterministic and fast. **This is what preserves the sans-IO discipline** — the
  storage engine is a trait, so nothing IO-bound leaks into the simulated paths.
- **`RedbStore`** — production. One `feeds.redb` under `data_dir`.

### 2. redb schema

One database, tables keyed by a composite `[u8; 40]` = `feed_key ‖ big-endian index`, so a
feed's blocks/nodes are a contiguous key range (prefix scan by the 32-byte feed key):

| Table | Key | Value |
| --- | --- | --- |
| `blocks` | `feed_key ‖ index:u64` | block bytes |
| `nodes` | `feed_key ‖ node_index:u64` | 32-byte Merkle node hash |
| `heads` | `feed_key` | encoded `Head` (len, root, signature) |

`has_block`/`present` derive from range scans on `blocks` (no separate bitfield in v1; add
one later only if the scans show up in profiles). Blobs stay as content-addressed files
initially (large, stream-friendly); folding them into a `blobs` table is a later option
(§Phasing D).

### 3. Persisted Merkle tree (the hard part)

Today `tree::audit_path` recurses over **all leaves** → O(n) and RAM-resident. To get
**O(log n) proofs from disk with no leaves in RAM**, persist the tree's internal nodes in a
**flat-tree layout** (node at a computable index), as hypercore does — then a proof is
O(log n) `store.node(...)` reads.

The subtlety: our tree is **RFC-6962-style** (split at the largest power of two ≤ n — an
unbalanced right spine), not hypercore's fully-balanced flat-tree. Two ways to reconcile:
- **(a)** Adopt a flat-tree index over the RFC-6962 shape: on `append`, emit the internal
  nodes that become fixed (a left subtree is immutable once its right sibling exists) and
  store them; leave only the mutable right-spine peaks (the existing `Accumulator`, O(log n)
  and tiny) in RAM. Proofs read fixed nodes from `store`, peaks from RAM.
- **(b)** Switch the tree to hypercore's balanced flat-tree outright (cleaner indexing,
  well-trodden), accepting a one-time change to how the root is computed. This diverges from
  the current RFC-6962 hashing and would be a format break, but yields the simplest
  persistence + matches Keet exactly.

**Recommendation:** stage it. v1 (Phase A) keeps O(n) proofs but moves leaves to disk (RAM
win + crash-safety + sparse blocks); the O(log n) flat-tree (Phase B) lands once the store
trait is proven. This is the single riskiest piece — spec it in its own doc before Phase B.

### 4. `Log` / `Replica` rewrite

Both stop owning `blocks`/`leaves` Vecs; they hold an `Arc<dyn FeedStore>` + `FeedKey` +
the in-RAM `Accumulator` peaks (O(log n), cheap) + the cached `Head`.

- `Log::append(block)`: compute leaf, fold into the accumulator, sign the new head,
  `store.commit(feed, Batch { blocks:[(i,block)], nodes:[…fixed nodes…], head })`. Atomic.
- `Log::get(i)` → `store.block(feed, i)`. `Log::proof(i)` → read nodes from `store`.
- `Replica::advance(head, new_blocks)`: verify exactly as today, then `store.commit`.
- **API ripple:** `Replica::blocks() -> &[Vec<u8>]` (added for the mirror work) can't return
  a borrowed slice from disk. It becomes `block(i)` / an iterator, and
  `Session::mirrored_records()` iterates `0..len` via `block(i)`. Small, mechanical.

### 5. The manager (subsumes `warren::store`)

One `Arc<dyn FeedStore>` opened at session construction replaces `store::{append_line,
write_blob,rebuild}` **and** the persistence half of the `mirrored` map. The own log and
every mirror are just feed keys in the same store — a Corestore-shaped unification.
`rebuild` becomes "open the redb file"; there's no replay (state is already durable).

### 6. Async / blocking

redb calls are sync. Reads are mmap-fast (µs) — call directly. Writes `fsync` (can be ms) —
wrap the commit in `tokio::task::block_in_place` (or a single dedicated storage thread with
an mpsc queue) so a slow disk can't stall the tokio reactor. Publish/append already isn't on
a hot path, so a storage thread is acceptable and keeps ordering trivial.

### 7. Migration

On first boot with `RedbStore`, if the legacy append-line log + blob files exist, replay
them into the store once (append each line via the normal path so the tree/head rebuild),
then rename the legacy files aside. Idempotent; a second boot sees the redb file and skips.

## Preserving the sim — and beating Keet on correctness

Because the engine is a trait, two test modes fall out:
- **Determinism:** all existing swarm-sim + warren integration tests run on `MemStore` —
  unchanged, still deterministic.
- **Crash-injection property tests (the moat):** a `CrashStore` decorator that applies the
  first *k* writes of a committed batch then "loses power". Property: for every k, reopening
  yields a feed whose stored head + present blocks **verify** (a consistent prefix, never a
  torn state). This is exactly the class of bug field-time buys Keet — and we can prove it
  deterministically instead of waiting to hit it.

## Phasing

| Phase | Delivers | Risk |
| --- | --- | --- |
| **A** | `FeedStore` trait + `MemStore` + `RedbStore`; `Log`/`Replica` store-backed; atomic commits; migration; crash-injection tests. **Disk-native + crash-safe + sparse blocks; proofs still O(n).** | Low–medium (mechanical + the async wrapping) |
| **B** | Persisted flat-tree → **O(log n) proofs, no leaves in RAM.** | High — the RFC-6962-vs-flat-tree reconciliation (§3); own doc first |
| **C** | Presence-aware serving: `serve_feed_tail` handles absent blocks; a bitfield exchange in `transfer` so a subscriber knows what a sparse holder has. | Medium — touches the wire protocol |
| **D** | Blobs into the store (or keep as files) + truncation/GC (bound a seeder's footprint) + optional at-rest encryption in the store. | Medium |

Phase A alone gets the seeder under the jetsam budget and makes storage crash-safe — the
highest-leverage slice. B/C/D are the "match hypercore's efficiency" tail.

## Verification

- **Unit:** `MemStore`/`RedbStore` round-trip (block/node/head/present); `commit` atomicity
  under the `CrashStore` for every truncation point; migration idempotence.
- **Parity:** the same `Log` operations produce identical `Head`s on `MemStore` and
  `RedbStore` (the store is invisible to the crypto).
- **Integration:** extend `backbone.rs` — mirror a feed, **restart the mirror's store from
  disk** (new Phase-2/cross-restart case), assert `mirrored_records()` still serves the
  author's blocks with the author offline.
- **Budget:** a soak that appends N blocks and asserts RSS stays bounded (leaves/blocks not
  resident) — the jetsam-budget guardrail.
- **Cross-compile:** `RedbStore` builds for all four Apple targets + Android (CI check).
