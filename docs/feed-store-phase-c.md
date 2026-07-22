# Phase C: sparse serving — hold and serve part of a feed

Follows Phase B (`feed-store-phase-b.md`: the Merkle tree is persisted; proofs and open are
O(log n)). This phase lets a node hold an arbitrary **subset** of a feed's blocks — the
recent tail, or just what it's been asked for — and serve exactly those, verified, while a
downloader fetches only the blocks it wants.

## Why

- **Bounded seeder footprint:** keep the last *N* blocks of each mirrored feed, drop the
  rest — the disk cap for an always-on seeder (pairs with Phase D's GC).
- **Cheap subscribers:** open a 1000-clip feed and pull one clip's blocks, not all of it.
- **Load spreading:** many nodes each holding a different slice collectively serve a feed
  none of them stores whole.

## What Phase B already gave us (most of it)

The verification is already sparse by construction — Phase C is mostly a *receive-side +
protocol* change, not new crypto:

- **`FeedStore`** stores blocks and tree nodes by index, with `has_block`/`contiguous_len`.
  A sparse feed is just a table with gaps.
- **`Accumulator::proof(i, get)`** returns a valid proof when `get` can supply `i`'s
  within-peak nodes, and **`None` when it can't** — so a holder missing block `i` naturally
  can't prove it.
- **`Replica::open`** already seeds the peaks via `Accumulator::from_peaks` (O(log n) peak
  reads) and verifies the root **without requiring the blocks** — the fast path needs only
  the peak nodes, not a complete prefix.
- **`sync::serve_feed`** answers `GetBlock{index}` with `Block{index, data, proof}` *or*
  `Absent` — already per-block, and already graceful about a block it lacks.

So a `Replica` that holds the peaks + a subset of blocks (with those blocks' proof nodes)
**already serves correctly today**: held blocks prove and return `Block`; missing ones
return `Absent`. The gaps are on the *receiving* and *negotiating* side.

## The gaps to close

### 1. A sparse holder that ingests a verified block

Today a `Replica` is built from a complete `blocks: Vec` (`new`/`with_store`) or a full
prefix already in the store. Add an **ingest** path: given the feed's `head` (its root +
len, already held) and a received `Block{index, data, proof}` message, verify it
(`verify_block(head, index, data, proof)`) and, if it checks out, persist:
- the block bytes at `index`, and
- the proof's **within-peak** sibling hashes at their flat-tree indices.

Then `Accumulator::proof(index, get)` can re-serve that block's proof from the stored
nodes + the peaks. This is the crux and the intricate bit (see §"the subtlety").

`Replica` construction relaxes accordingly: a sparse replica opens from the head + peaks
(no complete-prefix requirement — already how the `from_peaks` fast path works), and holds
whatever blocks it has ingested.

### 2. Mapping a received `Proof` back to flat-tree node indices

`Accumulator::proof` *emits* an audit path (within-peak siblings, then bagging siblings).
Ingest is the inverse: split a received path into the within-peak siblings (the first
`height(peak(index))` of them) and the bagging siblings, compute each within-peak sibling's
flat index from `index` (the same `(idx >> d) ^ 1` walk `proof` uses), and store them. The
bagging siblings are **discarded** — they're derived from the peaks, which the holder
already keeps. A small, well-tested `proof_nodes(len, index, &proof) -> Vec<(u64, Hash)>`
helper does this, and its correctness is pinned by a round-trip test (emit a proof, ingest
it, re-emit — identical).

### 3. A "have" negotiation + block requests in the protocol

`sync` already has `GetBlock{index}` → `Block`/`Absent` and a blob-side `GetHave`. Add the
feed analog so a subscriber fetches efficiently instead of probing:
- `GetHave{feed}` → `Have{feed, bitfield}` (or a run-length range list, since a seeder's
  holdings are typically a contiguous tail) — which block indices this peer holds.
- The subscriber picks blocks from the intersection of "what I want" and "what peers have",
  then issues `GetBlock{index}` for each (existing message), ingesting as in §1.
- **Head + peaks first:** a sparse subscriber fetches the head (`GetHead`) and the peak
  nodes before any block, so it can verify every ingested proof and re-serve. Peaks are
  O(log n) frozen nodes at computable indices — either a small `GetPeaks` message or piggy-
  backed on `Head`.

### 4. Session / mirror integration

- `Session::mirror_feed` gains a windowed variant: mirror only `[len-N, len)` (a suffix
  window) instead of the whole feed. `run_mirror` fetches the window and, as the author
  advances, ingests new tail blocks and lets old ones fall out of the window (GC, Phase D).
- `serve_by_key` already serves whatever the replica holds (it reads via the `Source`), so
  a sparse mirror serves its window with no change.
- `mirrored_records` (Murmur's feed read) already iterates `0..len` calling `block(i)`; for
  a sparse mirror it simply skips indices it doesn't hold — the app shows what's local, same
  as it does for an unreachable author today.

## The subtlety: which nodes are stable, which aren't

A proof has two parts. The **within-peak** siblings are frozen perfect-subtree nodes —
stable forever, addressable by flat index, safe to persist and re-serve. The **bagging**
siblings depend on the current length (as the feed grows, peaks merge and the bag changes),
so they have no stable flat index and must **not** be persisted as if they did. A sparse
holder therefore stores only the within-peak nodes and keeps the peaks live in its
accumulator (seeded via `from_peaks`, advanced as it tails) — exactly the split Phase B
already draws. Getting this boundary wrong (persisting a bagging sibling under a flat index)
would serve a stale proof after the feed grows; the round-trip and growth tests below guard
it.

## Correctness

- **Ingest round-trip:** for every `n ≤ 128` and every `i`, take `proof(i)` from a full
  accumulator, run it through `proof_nodes(...)` + ingest into a fresh sparse store, then
  re-emit `proof(i)` from the sparse store — assert byte-identical and verifying.
- **Sparse serve:** a `Replica` holding an arbitrary subset serves `Block` (verifying) for
  held indices and `Absent` for the rest; a held block still verifies after the feed grows
  (peaks advanced, within-peak nodes unchanged).
- **Windowed mirror:** mirror a suffix window over the loopback harness; the author advances;
  the mirror ingests new tail blocks, serves them, and a subscriber reconstructs them.

## Rollout

Additive: no root or `Proof` format change (proofs are byte-identical — Phase B's parity
test still holds), so it interoperates with un-upgraded peers; the new messages
(`GetPeaks`/`Peaks`, `GetFeedHave`/`FeedHave`) are new request types an old peer simply
doesn't send.

Sequence and status:

1. ✅ `proof_nodes` + `Replica::sparse`/`ingest` (+ round-trip and subset tests) — `feed`.
2. ✅ Sparse-serving protocol — `Source::peaks`/`held_ranges`, the `GetPeaks`/`Peaks` and
   `GetFeedHave`/`FeedHave` messages, and the windowed `FeedWindow` client — `sync`.
3. ✅ `transfer::download_feed_window` (the server side needed no change — `transfer`'s
   serve loop already dispatches `sync::serve_feed`).
4. ⏳ **Remaining:** windowed `Session::mirror_feed`/`run_mirror` in `warren` — bootstrap a
   sparse suffix-window replica, then ingest new tail blocks as the author advances and let
   old ones fall out of the window. The fall-out step is retention *policy*, so this lands
   with Phase D (GC); without it a windowed mirror only ever grows. **Specced in
   `feed-store-phase-d.md`** (step 1), together with GC, at-rest encryption, and the soak.
5. ⏳ Soak a suffix-window seeder (RSS + disk bounded by the window) — see Phase D.

Serving a sparse holding already works today with no `warren` change: a `Replica::sparse`
implements `Source`, so `serve_by_key`/`serve_feed_tail` serve whatever window it holds and
answer `Absent` for the rest, and `mirrored_records` already skips indices it doesn't hold.

## Non-goals

Choosing *what* to keep (retention policy, eviction) is Phase D (GC). Phase C provides the
*mechanism* — hold and serve a subset — not the policy. Erasure coding / redundancy tuning
across sparse holders is out of scope.
