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

## Follow-on (the live glue)

- **Wire it to the network path.** A chat app: subscribe to each room member's feed
  (Layer 2), `Room::observe` every delivered block (its feed index is the block's
  position), render `view().ordered`, and on send stamp the record with
  `Room::next_message_clock()` before `Session::publish`. No substrate changes — this
  is app wiring on top of what's built.
- **Writer-set management.** First cut: the writer set is the room's discovered
  members (the PSK channel). Explicit add/remove-writer records (membership as data,
  Autobase-style) are a later refinement.
- **Presence / typing** stays *out* of the signed log — ephemeral signals ride as
  plain datagrams on the open channel, never appended (see the live-tail note).

The point, as with sync: the hard part is a **pure, deterministic, convergent**
algorithm proven on the bench; the substrate is complete, and the network layer
already carries the records it needs.
