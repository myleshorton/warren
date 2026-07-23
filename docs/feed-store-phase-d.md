# Phase D: bounded seeders — windowed mirroring, GC, at-rest encryption

Follows Phase C (`feed-store-phase-c.md`: the sparse *mechanism* — hold, serve, and fetch a
verified subset of a feed — is complete through `feed`/`sync`/`transfer`). This phase turns
that mechanism into an **always-on seeder whose RSS and disk are bounded**, and hardens the
data a seeder holds on others' behalf. It is the last planned phase of the storage
substrate, and it consolidates the remaining next steps.

## Why

A blind mirror (warren's store-and-forward durability) today holds every block of every feed
it mirrors, forever — unbounded disk for a long-lived seeder. Phase C made *holding a subset*
possible; Phase D makes the seeder actually *keep only a suffix window* and drop the rest,
and encrypts what it does keep so a stolen disk doesn't leak content the seeder is merely
relaying.

## The remaining work, in build order

### 1. Warren windowed mirror (the deferred Phase C step, which pairs with GC)

Serving a sparse holding already works with **no `warren` change** — a `Replica::sparse`
implements `Source`, so `serve_by_key`/`serve_feed_tail` serve whatever window it holds and
answer `Absent` for the rest, and `mirrored_records` already skips indices it doesn't hold.
What's missing is *acquiring and maintaining* a windowed replica:

- **`protocol::fetch_replica_window(node, provider, feed_key, window, store)`** — the
  windowed analog of `fetch_replica`. Compute the suffix window `[len−N, len)` (it learns
  `len` from the head that `download_feed_window` fetches first), call
  `transfer::download_feed_window`, then `Replica::sparse(pk, head, peaks, store)` and
  `ingest` each returned block. Returns the sparse `Replica`.
- **`Session::mirror_feed_window(provider, feed_key, window)`** — like `mirror_feed`, but
  bootstraps via `fetch_replica_window`, registers the sparse replica in `self.mirrored`,
  and announces under the feed's topic. Idempotent, same as `mirror_feed`.
- **`Session::run_mirror_window(feed_key, replica, appended, window)`** — the live tail.
  Each round: look up providers, fetch the current head, and if it grew, `download_feed_window`
  for the newly-appeared tail `[max(prev_len, new_len−N) .. new_len)`, `ingest` those, fire
  `appended`, then **prune** everything below `new_len−N` (step 2). Unlike `run_mirror`'s
  `Replica::advance` (which requires a contiguous fill from 0), a windowed mirror advances by
  `ingest` because its holdings don't start at 0.

`mirror_feed`/`run_mirror` (the dense mirror) stay as-is; the windowed pair is additive, and
an app chooses per feed which to use (small feeds: dense; large media feeds: windowed).

### 2. GC / retention — `FeedStore::prune`

`FeedStore::prune(feed, below) -> StoreResult<()>`: drop everything not needed to serve or
prove any block at index `≥ below`, keeping the feed still fully verifiable for what remains.

**The subtlety — which tree nodes may be dropped.** Blocks (leaf *bytes*) below `below` are
free to drop. Tree *nodes* are not: a *held* block `j ≥ below` has an audit path whose
within-peak siblings can be frozen nodes covering leaves `< below` (e.g. `j`'s immediate
sibling leaf, or an internal node spanning a pruned range). Those node **hashes** must stay
even though their underlying blocks are gone — that's exactly what lets a proof stay O(log n)
without the leaves. So the safe rule is:

> Keep node `X` iff `X` is a peak, **or** `X` lies on the audit path of some retained block
> `j ≥ below`. Drop every other node, and every block `< below`.

The retained-audit-path set is the union of `proof_nodes(len, j, …)` flat indices over all
retained `j` — computable from `below`, `len`, and the flat-tree arithmetic already in
`tree.rs`. Pinned by a property test: after `prune(below)`, every retained block still
`verify_block`s and every pruned block is `Absent`; and the retained node set is exactly the
peaks ∪ retained audit paths (no node kept that isn't needed, none dropped that is).

**Policy vs mechanism.** `prune` is the mechanism. The *policy* is a per-mirror
`window: u64` (keep the last N blocks) plus an optional global disk cap that evicts
whole feeds LRU when exceeded. Policy lives in `warren` (`run_mirror_window`), not in `feed`.

### 3. At-rest encryption

A seeder holds other authors' blocks; a stolen or seized disk shouldn't leak them. Encrypt
block and node values in the redb backend with a key derived from the node's identity (or a
per-device key in the keychain), AEAD per value keyed by `(feed ‖ flat_index)` as associated
data so a value can't be relocated. Keys and roots are unaffected (they're already hashes /
signatures over plaintext). This is a `feed-redb` change behind the `FeedStore` seam —
`MemStore` and the pure `feed` core are untouched, so the sans-IO tests stay plaintext and
deterministic. Verify the ciphertext-at-rest / plaintext-through-the-API boundary with a
round-trip test that inspects the raw redb bytes.

### 4. Crash-injection property tests — `CrashStore`

A `FeedStore` wrapper (test-only) that fails a `commit` at an arbitrary injected point.
Assert the substrate's crash-safety invariant end to end: because `Log::try_append` /
`Replica::advance` / `Replica::ingest` all **commit before mutating in-RAM state**, a failed
commit must leave the log/replica exactly as it was — no torn append, no half-ingested block,
no accumulator ahead of the store. Drive appends/advances/ingests through the crash points
and check the reopened feed is a valid prefix that still verifies.

### 5. Soak

Run a suffix-window seeder against the loopback backbone harness (and then a real device
pair): a long-lived author appends past the window many times over; assert the seeder's RSS
stays O(log n) per feed and its on-disk size stays bounded by `window × block size`, while a
subscriber can still reconstruct the live tail.

## Rollout

Additive and format-compatible: `prune` only removes data (roots/proofs over what remains are
unchanged), at-rest encryption is invisible above the `FeedStore` seam, and the windowed
warren methods are new APIs alongside the dense ones. No wire change.

Status:

1. ✅ GC — `tree::retained_node_indices`, `FeedStore::prune` (MemStore + RedbStore),
   `Replica::prune`, with an exhaustive property test.
2. ✅ Windowed mirror — `FeedWindow::suffix` + `transfer::download_feed_suffix`,
   `protocol::fetch_replica_window`, `Session::mirror_feed_window` /
   `run_mirror_window`; backbone test chains author → windowed mirror → downstream mirror
   with the author offline.
3. ⏳ At-rest encryption of blocks/nodes in `feed-redb`.
4. ⏳ `CrashStore` crash-injection property tests.
5. ⏳ Soak a suffix-window seeder (bounded RSS + disk).

## Non-goals

Erasure coding / redundancy tuning across sparse holders; choosing *which* peers hold *which*
windows (a swarm-scheduling concern, not storage); and key management beyond a per-device key
(no multi-device key sync, no re-keying protocol) — all out of scope for this phase.
