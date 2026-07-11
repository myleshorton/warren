# Warren — blind push notifier (design note)

**Status:** design only, not built (2026-07-11). A companion to [`design.md`](design.md)
and [`live-tail.md`](live-tail.md).

## The problem

A Warren peer on a mobile OS is **suspended** when backgrounded: it stops
announcing, serving, and — the part that matters for real-time apps —
receiving. To act on new activity it must first be **woken**.

On iOS there is no API to keep an app foregrounded, and **the only reliable way
to wake a suspended app is an APNs push** (Android: FCM). The catch for a
serverless system: **APNs only accepts a push from a sender holding the app's
APNs key**, over a persistent authenticated connection. A peer cannot hold that
key (it can't be shipped in the client without leaking, and Apple binds it to
the app) and does not maintain an APNs connection for others. So a peer
**cannot wake another peer's phone directly** — waking device `D` requires a
component that (a) holds the APNs key, (b) knows `D`'s push token, and (c) is
reachable by whoever wants to wake `D`.

That component is the one unavoidable bit of infrastructure. The design goal is
to make it **blind** — to learn as little as an APNs relay possibly can.

## The primitive: a blind notifier

A minimal always-on service, sibling to the **blind mirror**. Where a mirror is
blind about *content* (it serves ciphertext it can't read), the notifier is
blind about *content and, as far as possible, membership* (it relays opaque
wakes). It exposes two operations:

```
register(wake_handles: [Handle], push_token)   — device: "wake me for these handles"
wake(handle: Handle)                            — peer:   "wake whoever registered this"
```

### Opaque, rotating, per-device wake handles

The handle a device registers is **not** the channel topic (that would let the
notifier group devices by channel and infer co-membership). It is a blinded,
**per-device, per-epoch** value that any channel member can compute but the
notifier cannot invert:

```
wake_handle(D, epoch) = H("warren:wake:v1", channel_key, D_feed_pubkey, epoch)
```

- Any member holds `channel_key` and sees `D_feed_pubkey` in the channel feed,
  so members can compute `D`'s current handle to wake it.
- It **rotates every epoch** (like the discovery topic), bounding long-term
  linkage.
- The notifier only ever stores `{ wake_handle → push_token, expiry }`. It never
  sees `channel_key`, feed identities, or content, and — because handles are
  per-device — it can't cluster devices into channels.

Devices refresh their registration each epoch (register `epoch` and `epoch+1`
for overlap, mirroring `keep_announced`).

### The wake path

1. A peer (or a blind mirror) with new activity for `D` — a new clip in a
   followed channel, or a direct message — computes `wake_handle(D, epoch)` and
   calls `wake(handle)` on the notifier. **No content is sent** (ideally zero
   payload; at most a few opaque bytes encrypted to `D`).
2. The notifier maps `handle → push_token` and fires a **silent** APNs/FCM push.
3. iOS wakes the app for a short window. The app **reconnects to the swarm** and
   pulls what changed — `subscribe`/`download_feed` (this is exactly what
   [`live-tail`](live-tail.md) is for) — then, if it's user-facing, posts a
   **local** notification with the *locally decrypted* content. The content
   never touched the notifier.

This is the standard privacy-preserving pattern (Signal, and Keet's own push
service do a version of it): the push is a dumb "wake + go look", not the
message.

## What the notifier can and can't learn

| Learns | Does **not** learn |
| --- | --- |
| a set of opaque, rotating handles ↔ push tokens | channel keys, content, feed identities |
| wake events: handle `X` woken at time `T` (timing/volume) | which channel a handle belongs to |
| (with Apple/Google) that a token maps to a device | co-membership — handles are per-device |

The irreducible leak is APNs itself: Apple can link a push token to a device.
Using APNs *at all* means Apple is in the loop — that's not something any design
removes.

## Honest tradeoffs

- **It is a fixed, central-ish surface.** One always-on endpoint holding the
  APNs key: **blockable** (a censor blocks the notifier → no background wake; the
  app still works in the foreground) and **Apple-pressurable** (Apple can revoke
  the app's push key). State this plainly — it is the one place a serverless
  design concedes infrastructure. Mitigate by running several instances /
  rotating addresses and treating background wake as an *enhancement* that
  **degrades gracefully** to foreground + `BGTaskScheduler` polling when the
  notifier is unreachable.
- **Abuse / battery drain.** Anyone who can compute a handle can wake that
  device. Rate-limit per handle and per source. A stronger v2: the device issues
  **blind-signed, single-use wake capabilities** to peers, so only authorized
  members can wake it and the notifier still learns nothing about who.
- **Token custody.** Encrypt tokens at rest, minimal retention, rotate.

## Alternatives (and why the notifier still wins for reliability)

- **VoIP push (PushKit) + CallKit** — the most reliable background wake, but
  since iOS 13 you must present a *call* UI on receipt or iOS penalizes/revokes
  the entitlement. Legitimate for a real-time **call** app on Warren; App-Store-
  risky to abuse for a feed or chat.
- **Silent push (`content-available:1`)** — what the notifier sends; iOS
  throttles it hard (coalesced, deprioritized on low battery, not guaranteed).
  Fine for "sync soon", not "instant". Still requires the notifier (still APNs).
- **`BGTaskScheduler` / background fetch** — no server, but the OS picks the time
  (minutes to hours), best-effort. The right **fallback**, not a substitute.
- **Local notifications** — can't wake a suspended app; only useful once running.

## Fit for Murmur (and why it's optional there)

Murmur is a **feed, not a chat**: background *delivery* matters far less than
*availability*. For Murmur a notifier is at most low-frequency "new clips in a
channel you follow" nudges — optional and per-channel. Availability/seeding is
better served by **desktop and always-on peers + blind mirrors**, which don't
suspend (see the device-agnostic positioning). A notifier becomes closer to
*required* only for real-time apps (chat) built on Warren — and there it pairs
with live-tail: the push buys a window, live-tail is what the app does in it.

## Scope / non-goals

**If pursued:** (1) a notifier service (APNs + FCM sender) with `register` /
`wake`; (2) client: derive rotating per-device handles, register on foreground,
handle silent push → reconnect → live-tail → local notification; (3) graceful
degradation to `BGTaskScheduler`. Start with Murmur "new content" nudges (low
stakes) before any chat real-time path.

**Non-goals:** guaranteed delivery (iOS won't promise it); being the message
transport (content never flows through the notifier); hiding from Apple (APNs
inherently involves Apple). The notifier is a blind doorbell, not a mailbox.
