# Warren — multi-writer causal merge (Layer 3, design note)

**Status:** the Layer 3 **substrate** is built (2026-07-11) — the pure linearizer, the
record clock, and the `Room` view/frontier. What remains is the live-network/app glue
(feed a chat app's subscribed blocks into a `Room` and publish with a room clock). A
companion to [`live-tail.md`](live-tail.md) and [`design.md`](design.md).

## The problem

Live-tail ([Layer 1/2](live-tail.md)) delivers *one author's* signed log in order,
from any provider, in real time. A **group chat** is many authors at once, and a
conversation needs a single, **causally consistent** order that **every participant
computes identically** — otherwise two members see messages in different orders and
"replies" precede the messages they answer.

This is the last piece for concurrent-writer rooms, and it's exactly what Keet's
**Autobase** does: each writer keeps their own append-only log; the logs are merged
deterministically into one linear view.

## The model

- **Each writer = one Warren feed.** A room member's `feed::Log` is the per-writer
  log (signed, per-block-verified) — nothing new; L2 already replicates them.
- **Each record carries a causal clock.** When a member appends message *R*, it
  records a **version vector**: for every other writer *w* it knows about,
  `clock[w] = k` means "R causally follows the first *k* records of *w*" — i.e. R was
  written having seen them. Its own prior records are implied by R's position in its
  feed. A record also carries a **Lamport timestamp** `lamport = 1 + max(lamport of
  everything in its clock)`.
- **A deterministic linearizer** turns the set of all records + their clocks into one
  total order:
  - **Causal edges**: same-writer `(w, i-1) → (w, i)`, and cross-writer
    `(w, clock[w]-1) → R` for each writer in R's clock. This is a DAG (a message can
    only depend on messages that already existed).
  - **Topological sort (Kahn)**, and where two records are **concurrent** (neither in
    the other's history), break the tie by `(lamport, writer_id, index)` — a total
    order independent of arrival. Lamport-first means messages appear in roughly the
    order they were sent; the writer-id tiebreak makes it deterministic.
- **Convergence invariant:** any node holding the *same set of records* computes the
  *same* ordered sequence, regardless of the order they arrived — because the DAG and
  the tiebreak are functions of the records alone. This is the property the tests
  hammer.
- **Partial feeds → pending.** A record whose causal ancestor hasn't arrived yet
  cannot be ordered (you can't place a reply before the message it answers). It — and
  anything depending on it — stays **pending** until the missing ancestor arrives,
  then becomes orderable. So the view is *eventually* consistent: the linearizable
  prefix grows as feeds fill in, and never reorders what it has already shown.

## What's built (the substrate)

**L3a — `warren::merge`, the pure linearizer** (sans-IO, exhaustively testable):
- `Clock` (a version vector over `WriterId = [u8; 32]`) and `Entry<T>` (a record's
  causal metadata + an opaque payload the merge layer never inspects).
- `linearize(entries) -> Linearized { ordered, pending }` — the Kahn topological sort
  with the `(lamport, writer, index)` tiebreak, splitting off records with missing
  ancestors as `pending`.
- `next_lamport` for the append side.
- Tests assert the two things that matter: **causal order is respected**, and **the
  output is identical across shuffled / subset inputs** (convergence + the grow-only
  pending frontier).

**L3b — the clock in the record envelope** (`warren::record`):
- `Record` gains optional `clock` (author-hex → seen-len version vector) and `lamport`
  fields, serde-default and omitted on the wire when empty/zero — so single-author
  content (a video post) serializes byte-identically to before and nothing else moves.
- `Record::into_entry(index)` / `causal_clock()` bridge a decoded record into a
  `merge::Entry`, decoding the hex author key to a `WriterId`.

**L3c — `warren::room`, the stateful view + frontier** (`Room`):
- `observe(index, record)` accumulates decoded blocks; `view()` re-linearizes on
  demand (ordered transcript + pending).
- `frontier()` is the observed version vector (contiguous prefix per writer);
  `next_message_clock()` returns the `(clock, lamport)` a new local message should
  carry so it causally follows everything this node has seen.
- Tests: two-writer merge, contiguous-only frontier, a stamped message sorting after
  all it observed, reply-before-cause held pending then resolved, idempotent observe.

## First application: comments on videos (Murmur)

The natural first consumer of the merge substrate isn't a standalone chat app — it's
**comments on a video in Murmur**. A video's comment thread *is* the multi-writer
merge, scoped to one blob id: many authors write, everyone must see the same ordered
thread, replies must follow what they answer. It reuses Layer 2 (subscribe) and Layer
3 (`Room` + `merge`) almost as-is, and it makes the whole live-tail→merge stack visible
in the reference app without a new client.

**Shape.** A comment is a **body-only feed record** in its author's own signed log:
`content_type: "comment"`, `body: <text>`, `meta.reply_to: <video blob id>` (and, for a
nested reply, `meta.parent: <comment id>`), carrying the merge `clock` + `lamport`
scoped to *that video's* thread. Comments live in the same per-author feed as that
author's videos — one identity, one log — so no new feed type is needed.

**Read path.** To show video V's comments: from the feeds we already discover (channel
members), take records where `content_type=="comment" && meta.reply_to==V`, `observe`
them into a `Room` scoped to V, and render `view().ordered`. Live updates arrive for
free over `subscribe` — a new comment is pushed and re-linearized. Nested replies fall
out of the ordering: a reply's `clock` depends on its parent comment, so the linearizer
places it after; the UI draws the indentation from `meta.parent`.

**Write path.** On send: `Room::next_message_clock()` for the thread → stamp a
comment record → publish it to our own feed. This needs the one substrate addition
below; discovery reuses the existing content/channel announce.

**Two increments.**
1. *v1 — comments over channel membership.* Add a **body-only publish** path (today
   `Session::publish` always creates a blob; a comment carries only a `body`), a
   comment record shape, a per-video `Room` fed from discovered members' comment
   records, and a comments UI (the TikTok comment drawer). Flat threads first.
2. *v2 — reach + nesting.* A per-video `comment_topic(blob_id)` (a sibling of
   `content_topic`) so commenters are discoverable beyond the channel members you
   already aggregate, and nested reply threads via `meta.parent` + the parent in the
   comment's clock.

## Other follow-on (the live glue)

- **General rooms / group chat** are the same wiring without the video scope: subscribe
  to each member's feed, `Room::observe`, render, publish with `next_message_clock()`.
  Comments prove the path; a standalone chat room is a generalization.
- **Writer-set management.** First cut: the writer set is the room's discovered members
  (the PSK channel). Explicit add/remove-writer records (membership as data,
  Autobase-style) are a later refinement.
- **Presence / typing** stays *out* of the signed log — ephemeral signals ride as
  plain datagrams on the open channel, never appended (see the live-tail note).

The point, as with sync: the hard part is a **pure, deterministic, convergent**
algorithm proven on the bench; the substrate is complete, and the network layer
already carries the records it needs. The first app that spends it is video comments.
