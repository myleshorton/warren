# Warren — roster membership (channels as authenticated groups, design note)

**Status:** design only (2026-07-12), not built. Elaborates the "writer-set management"
refinement flagged in [`multi-writer.md`](multi-writer.md) (§Other follow-on) and builds
directly on the Layer 3 merge substrate. A companion to
[`multi-writer.md`](multi-writer.md), [`live-tail.md`](live-tail.md), and
[`design.md`](design.md); threat-model context in [`design.md`](design.md).

## The problem

Today a channel is a **pre-shared key (PSK)**: `channel_topic = hash(domain, psk, epoch)`.
Membership *is* possession of the secret — anyone with the key can find the channel, read
it, publish into it, and reshare the key. That's dead simple and needs no coordination,
but under our threat model it has three holes a **state censor** can drive through:

1. **Undetectable infiltration.** A censor who obtains the PSK — a leak, a coerced
   member, a seized device — is cryptographically indistinguishable from a legitimate
   member. There is no notion of "who was let in, by whom."
2. **Impersonation by name.** Display names aren't bound to identity. A censor joins and
   calls itself "Alice"; a second key now claims the same name and no member can tell
   which is real.
3. **No recourse.** There is no revocation. You cannot remove a member; the only lever is
   to abandon the key and re-share a new one out of band with everyone *except* the
   suspected mole.

What the PSK model already gets right, and we keep: **posts cannot be forged.** Every
feed is signed by its author's key (identity decoupled from node id — see
[`design.md`](design.md)), so a censor cannot publish *as* Alice without Alice's private
key. The gap is not forgery; it is that *any key* is as good as any other.

**Scope of this note:** the impersonation/infiltration threat is a **write-and-identity**
problem, and that is what the roster fixes in v1. The complementary **read** problem — a
censor who leaked the PSK can *read* until the key changes — is a group-key-rotation
problem (forward secrecy), genuinely harder, and deferred to v2 (§Phasing).

## The model: two layers

A channel becomes two independent gates.

- **PSK — discovery + read-blinding (unchanged).** Still derives the rotating channel
  topic and encrypts content, so the channel is unfindable and unreadable to anyone
  without the key. This is the censorship-*visibility* defense and it stays exactly as
  today.
- **Roster — membership + authorship authority (new).** An **authenticated membership
  log** carried on the same `warren::merge` substrate as everything else: signed
  `add` / `remove` records that every node replays deterministically to compute the
  current member set. A post is honored only if its author is in the roster *as of that
  post's position in the causal order*; posts from non-roster keys are dropped.

The PSK is the outer gate ("can you see/decrypt it at all"); the roster is the inner gate
("are you an authorized member/author"). A leaked PSK alone therefore lets a censor read
(until re-keying, v2) but **not** be a member: their posts are ignored, they can't
impersonate anyone, they never appear in the roster, and they're excluded from the next
key epoch.

### The roster is itself a merge computation

Membership is data, Autobase-style: `add`/`remove` are records in the members' own signed
feeds, ordered by the same deterministic linearizer as messages
([`multi-writer.md`](multi-writer.md)). The member set is a **fold over the linearized
roster records**, so — like the message view — every node holding the same records
computes the *same* membership, independent of arrival order.

Validity is computed *during* the fold, because whether a record is authorized depends on
the state at that point:

- The channel **founder** (the keypair that created it) is the genesis authorizer — the
  first, implicit roster entry.
- Replaying in causal order: `add(X, by=A)` is honored iff `A` is an authorized member at
  that point; it makes `X` a member. `remove(X, by=A)` likewise. Records by
  not-yet-authorized keys are inert (dropped), deterministically.
- Because authorization is evaluated against the linearized prefix, the result is a pure
  function of the record set — the convergence invariant extends to membership.

**The roster is its own log.** A membership record's merge clock is stamped over *other
roster records only*, and it is positioned by its index *among its author's roster records*
(a roster-only index space, distinct from the author's full-feed position). So membership
orders and converges **independently of content volume** — a `member.add` never waits on a
video block to become orderable, and the resolver never has to hold the entire content log
to place a membership change. The alternative (fold membership over the full content log,
sharing one clock/index space) was rejected: it couples roster convergence to content and
forces the resolver to linearize everything. Consequences: a publisher stamps membership
clocks from a roster-only view, and `warren::roster::members_from_records` enumerates the
per-author roster index itself (it takes `(writer, record)` in feed order and counts only
roster records).

### Record shape

Roster records are ordinary body-only feed records (same envelope as a comment/message),
so no new feed type — one identity, one signed log, carrying videos, messages, *and*
membership:

```
content_type: "member.add" | "member.remove"
meta.subject:  <hex pubkey being added/removed>
meta.role:     "member" | "admin"           # v1: member only (see Decisions)
# author = the signer (from the feed key); merge clock/lamport as usual
```

An **invite** is then a signed capability the sharer creates offline: the channel's PSK +
bootstrap peers (today's invite) **plus** a pre-signed `member.add(subject = invitee's
pubkey)` the invitee replays into the roster on join. So joining is: get the invite →
learn the PSK (discovery/read) → publish your own feed → your `add` record (signed by an
existing member) makes you a roster member everyone converges on.

## What it defends — and what it doesn't

Honest scope, so we don't oversell v1:

**Stops (v1):**
- Infiltration by key possession alone — a censor with the PSK is not a member; someone
  must *vouch* them in, which is a social-trust boundary and is **auditable** (the `add`
  chain shows who admitted whom).
- Name-collision impersonation — identity is the key, the roster is the source of truth,
  and the UI can surface membership/vouch state so a fake "Alice" is detectable.
- Unbounded write-Sybil — non-roster keys can't post.
- Gives **revocation of future writes** — `remove(X)` drops X's later posts everywhere.

**Does not stop (needs more):**
- A censor who social-engineers *one* real member into vouching them is in. Mitigable
  (visible vouch chains, multi-vouch thresholds), not eliminable — this is inherent to
  any web of trust.
- **Read forward secrecy.** `remove(X)` stops future *writes*, but X already read past
  content and — until the PSK/content key is rotated — can still read new content.
  True exclusion requires re-keying the group on removal and distributing the new key to
  remaining members only (§v2).

## Decisions to lock (with a recommended v1)

1. **Who can vouch/add?**
   - *Flat* (any member can `add`): most coercion-resilient (no single admin to seize),
     but one compromised member admits the censor; the `add` chain is at least auditable.
   - *Admin-only*: controlled, but admins are coercion targets and single points of
     failure.
   - **v1: flat vouching + visible vouch chains + revocation.** It mirrors how real
     trust networks form and avoids a coercible central role; add `admin`/threshold roles
     in v2 if moderation-at-scale demands it.
2. **Revocation depth?**
   - *Revoke-future-writes only* — cheap, no re-keying, no forward secrecy.
   - *Rotate the group read-key on removal* — real forward secrecy, but every removal
     re-keys every remaining member.
   - **v1: revoke-future only.** Past posts stay (they were authored while a member);
     future posts from the removed key are dropped. Key rotation is v2.
3. **Membership conflict resolution?** Concurrent changes (two members `add`/`remove` the
   same subject, or remove each other) are *ordered* by the linearizer but need a
   deterministic *policy*.
   - **v1: remove-wins**, evaluated in causal order — a `remove` that is authorized at its
     position beats a concurrent `add`; mutual removes both apply (both out). Simple and
     deterministic; revisit if it proves too blunt.

## Phasing

- **v1 — authenticated identity + append-only roster.** Founder genesis, `member.add`/
  `member.remove` on the merge log, flat vouching, revoke-future, remove-wins,
  authorship gate (drop non-roster posts), and the UI to show membership + vouch chain.
  Directly closes the impersonation/infiltration (write-side) threat. PSK unchanged.
- **v2 — read forward secrecy + roles.** Group key rotation on removal (sender-keys or an
  MLS/TreeKEM-style ratchet — the hard, careful part), admin/threshold roles, richer
  invite policies (expiry, approval). Only then is a removed member fully excluded from
  reading.

## Where it sits on existing primitives

Nothing here is from scratch: signed feeds + node-id/feed-key decoupling already give
per-user cryptographic identity; `warren::merge` gives the deterministic, convergent
shared log the roster folds over; the PSK channel + `keep_announced` give discovery. The
roster is a new **record semantics** layer (a fold + an authorship filter) on top — not a
new transport.

## Sequencing (how this unblocks the product)

The roster **redefines what a channel is**, so it comes before the product features that
assume it:

1. **Roster membership (this note)** — a channel is an authenticated group.
2. **Multi-channel** — membership in several rostered rooms at once (engine holds N
   channels, N announce/discover loops, per-room `Room` views).
3. **Create-or-join onboarding** — no baked-in default room (Keet-style): first run is
   *create a channel* (you're the founder/genesis admin) or *join via an invite* (which
   carries the PSK + your pre-signed `add`). No public directory — discovery stays social,
   which also keeps blinded topics intact.
4. **Publish picker + share extension** — choose *which* rostered room a post (or a
   shared-in file) goes to.

## Open questions

- **Invite as capability vs. join-request.** Pre-signed `add` in the invite (works
  offline, but the sharer picks the invitee's key ahead of time) vs. the joiner posts a
  `join-request` an existing member later approves with an `add` (more flexible, needs the
  approver online). v1 leans pre-signed; both can coexist.
- **Founder loss / succession.** If the founder key is lost, can admins still run the
  room? Flat vouching softens this (any member can add), but a genesis-only capability
  (e.g., rotating the room) would be stranded. Consider designating multiple genesis
  admins at creation.
- **Roster availability.** Membership records must be as replicated as content — a member
  offline shouldn't hide the `add` that authorized someone. They ride the same feeds +
  blind-mirror/store-and-forward as everything else, so this is the general availability
  problem, but worth stating: you can't validate authorship without the roster records.
- **PSK rotation cadence vs. roster.** When v2 re-keys on removal, the epoch'd
  `channel_topic` already rotates for discovery; the *content* key rotation is the new
  part. Align the two so a removal cleanly starts a new readable epoch.
