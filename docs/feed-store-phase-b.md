# Phase B: persist the Merkle tree (O(log n) proofs, leaves off-RAM)

Follows `feed-store.md` Phase A (blocks + head in redb; leaves + accumulator still in RAM).
This phase persists the Merkle **tree** so a proof is O(log n) reads instead of O(n)
recomputed-from-all-leaves, and so the per-feed RAM cost drops from `O(n)` leaf hashes to
`O(log n)` peaks — the last big memory item for a seeder holding many feeds.

## The hard constraint: no format break

`Head` (len, root, signature) and `Proof` (sibling hashes) are on the wire (sync/transfer)
and committed to disk for every existing feed (own + migrated + mirrored). **Phase B must
produce byte-identical roots and proofs.** So we do **not** adopt hypercore's balanced
flat-tree (different hashing → every root changes → a network + data cutover). We keep
Warren's RFC-6962 tree exactly and only change *where its nodes live* and *how a proof is
assembled*.

## Background: the RFC-6962 tree is already an MMR

`tree.rs` builds an append-only RFC-6962 tree: `MTH(n) = node(MTH(left k), MTH(rest))` where
`k` is the largest power of two `< n`. Two facts make persistence clean:

1. **Every leaf lives in a complete, perfect power-of-two subtree** (a *peak*). The peaks
   decompose `n` by its set bits: sizes `2^b` for each bit `b` set in `n`, left-to-right
   largest-first. A perfect subtree's internal nodes are **frozen forever** once it
   completes — they never change as the tree grows.
2. **The only mutable part is how the peaks bag into the root**, and that is exactly what
   `tree::Accumulator` already tracks in RAM (the right-spine peaks, O(log n)).

So Phase B = *persist the frozen nodes; keep the peaks in the accumulator*. It extends the
accumulator (proven code), it doesn't rewrite the tree.

## Node addressing (flat-tree)

Persisted nodes are keyed by a **stable flat-tree index** (mafintosh `flat-tree` scheme),
which never changes as the tree grows:

- A node at depth `d` covering leaves `[o·2^d, (o+1)·2^d)` has index `(o << (d+1)) + (1<<d) − 1`.
- Leaf `i` (d=0, o=i) → index `2i`. The parent of a node at index `x` (depth `d`) is
  `x ± 2^d` averaged — computed by the standard flat-tree parent/sibling formulas.

These indices go in the existing `nodes` table (`(feed ‖ flat_index) → 32-byte hash`), which
Phase A already defined but left empty.

## What gets persisted, and when

- **Leaf** `i` (index `2i`): its hash, on every append.
- **Frozen internal nodes:** when `Accumulator::push(leaf)` merges two equal-height peaks
  into a taller one, that taller node's subtree has just completed — it is frozen. Emit it
  (index + hash). A push causes 0..log₂n merges, so an append emits `1 + (merges)` nodes.

Concretely, `Accumulator::push` changes from `-> ()` to `-> Vec<(u64, Hash)>` returning the
`(flat_index, hash)` of the leaf plus every node frozen by this push. `Log::try_append` /
`Replica::advance` put those into `Batch.nodes`; `RedbStore`/`MemStore` already persist them.

## Assembling `proof(i)`

Given length `n`, leaf `i`, a node-reader `get_node(flat_index)`, and the accumulator peaks:

1. **Within `i`'s peak** (a complete perfect subtree): walk leaf `i` up to the peak,
   reading each sibling from the store by flat index. All frozen ⇒ all present. This is the
   deepest part of the audit path, deepest-first.
2. **Peak bagging:** the root is `node(peak₀, node(peak₁, … node(peak_{m−1}, peak_m)))`
   (largest peak leftmost). For leaf in peak `j`, the remaining siblings, in order, are:
   `bag(peaks_{j+1..m})` (one combined hash), then `peak_{j−1}, peak_{j−2}, …, peak₀`. All
   from the accumulator (RAM).

Concatenated, this is **identical** to today's `audit_path(leaves, i)` — verified
exhaustively by the property test below. `verify_block`/`root_from_path` are unchanged.

## Open / rebuild: O(log n), with a one-time legacy backfill

- **Normal open** (`Log::with_store` / `Replica::open`): read only the **peak nodes** for
  length `n` (their flat indices are computable from `n`) — O(log n) reads — and seed the
  accumulator from them. No block re-hashing. `len` comes from the stored `Head`.
- **Backfill** (first Phase-B boot on a Phase-A feed): the `nodes` table is empty but blocks
  exist. Detect this (no peak nodes for a non-empty feed) and recompute once from the
  blocks — read each block, `push` its leaf, persist the emitted frozen nodes — an O(n) pass
  identical in cost to today's open, but now persisted, so every later open is O(log n).
- **`Replica::open`** verifies as today: reconstruct the root from the peaks and check it
  equals `head.root` (rejecting a tampered on-disk tree), same guarantee as the current
  block-rehash check.

## Feed API / struct changes

- `Log` / `Replica`: **drop `leaves: Vec<Hash>`**; keep `roots: Accumulator`; add `len: u64`
  (from the head). `proof(i)` reads the store + accumulator (no leaves). Everything else
  (`head`, `root`, `public_key`, `get`) is unchanged.
- `tree::Accumulator::push -> Vec<(u64, Hash)>`; add `peak_indices(n)`, flat-tree
  index helpers, and `proof_within_peak` / `bag_peaks` helpers.
- `FeedStore` trait: **unchanged** (Phase A already has `node`/`commit(nodes)`); redb/mem
  backends unchanged. `Batch.nodes` starts carrying data.

## Correctness: the property test is the acceptance criterion

Build the test **first**:

- For every `n` in `0..=512` and every leaf `i < n`: a store-backed `proof(i)` is
  **byte-identical** to `tree::audit_path(leaves, i)` computed the old way, and both verify
  against the head. (Deterministic, exhaustive — the sans-IO discipline's payoff.)
- Round-trips: append N, reopen from store (peaks only), proofs still verify; a Phase-A feed
  (empty `nodes`) backfills on open then verifies; a tampered persisted node is rejected by
  `Replica::open`.
- Edge cases: `n = 0`, `n = 1` (empty audit path), `n = 2^k` (single peak), non-power-of-two
  `n` (multiple peaks — the bagging path).

## Risks

- **Flat-tree index arithmetic** is the error-prone core — off-by-one in parent/sibling or
  peak enumeration yields a wrong proof. Mitigation: the exhaustive `audit_path`-parity test
  catches any such mistake before it can ship.
- **Backfill on a huge feed** is one O(n) pass at first Phase-B boot (bounded, same as
  today's open); acceptable and one-time.
- **Bagging order** must match RFC-6962's right-recursive peak combination exactly — pinned
  by the parity test across non-power-of-two `n`.

## Rollout

Purely in-crate (`feed` + its backends). No wire change, no on-disk *format* change beyond
populating the already-defined `nodes` table, and roots/proofs are provably identical — so it
ships without a cutover and interoperates with un-upgraded peers. Sequence: property test →
`Accumulator::push` returns frozen nodes + flat-tree helpers → `Log`/`Replica` persist + read
+ drop `leaves` → open-from-peaks + backfill → soak the RAM-bound (RSS stays O(log n) per
feed).
