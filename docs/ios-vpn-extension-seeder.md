# Warren — background seeder via the VPN Network Extension (design note)

**Status:** design only, not built (2026-07-11). A companion to [`design.md`](design.md),
[`live-tail.md`](live-tail.md), and [`blind-notifier.md`](blind-notifier.md).

## The problem

A Warren peer on iOS is **suspended** when the app is backgrounded: it stops
announcing, serving, and receiving. That makes phones close to useless as
*seeders* — a device is only an available peer while its owner is staring at the
screen. Strength-in-numbers (the censorship-resistance argument) wants the
opposite: many devices quietly available in the background.

[`blind-notifier.md`](blind-notifier.md) addresses one half of this — *waking* a
suspended peer to receive a message. It does **not** give sustained availability:
APNs buys you seconds of wake time, not a background peer that stays announced and
serves blocks for minutes or hours.

## The mechanism: run the node inside the VPN tunnel process

If the containing app is a VPN (as a Lantern-class app already is), it ships a
**Network Extension** — an `NEPacketTunnelProvider`. The key property:

> The Network Extension runs in a **separate process that iOS keeps resident for
> as long as the tunnel is connected.** It is not subject to the main app's
> background suspension, and it has network access by definition.

So a Warren node hosted *inside the NE* stays alive in the background: it keeps its
DHT announces fresh, accepts inbound hole-punches, and serves feed/blob requests —
continuously, with no wake step. This is categorically stronger than any main-app
background mode, and stronger than the blind notifier for the **seeding** role:
the notifier wakes a sleeping app; the NE node never sleeps.

## The binding constraint: the jetsam memory budget

The NE runs under a hard per-process memory ceiling; exceed it and iOS kills the
extension (jetsam). This is *the* feasibility question, so pin the real numbers
(from a current — iOS 26.5, 2026-06 — real-world VPN-in-tunnel investigation,
[VpnHood](https://github.com/vpnhood/VpnHood/blob/develop/docs/ios/ios-extension-memory-and-throughput.md)):

- **The kill threshold is ~52 MB** (`phys_footprint`) on modern iOS — *not* the
  ancient 15 MB still quoted in old forum threads.
- **Only dirty + compressed anonymous memory counts** (`footprint ≈ anon + comp`).
  File-backed code/AOT is **not** counted — binary size is free; heap, buffers,
  and live connections are the budget.
- The dominant cost is `per-flow-cost × concurrent-flows`. Their full VPN datapath
  (100-connection TLS proxy) peaked ~45 MB only after connection caps, fast idle
  reaping, and dynamic receive windows.
- Their **language runtime alone** was the floor: Mono ~42 MB, CoreCLR ~23 MB —
  i.e. tens of MB spent just existing, before any work.

### Why Warren is favourably placed

- **Rust has no managed runtime and no GC-heap floor.** A Rust static library's
  resident baseline is a few MB, versus the 23–42 MB a .NET (or gomobile/Go)
  runtime costs before it does anything. We start with almost the whole budget
  free.
- **Warren does not proxy arbitrary traffic.** It holds only its own bounded P2P
  connections — a swarm capped at `MAX_SOURCES` (5) plus a handful of subscriber /
  mirror links — a dozen UDP sockets with small buffers, not ~190 TLS flows. The
  per-flow × count blow-up that dominates a full-tunnel datapath barely applies.
- **The blob store is disk-backed**, so held content does not sit in the footprint;
  only in-flight chunk buffers do, and those are bounded by the transfer window.

### The real tension: co-residency with an active VPN

The 52 MB is shared with whatever the NE is *already* doing. If the app is also a
genuinely-active forwarding VPN, that datapath eats most of the budget (the
VpnHood case shows ~45 MB for the VPN alone), leaving little for Warren. The clean
regimes are:

1. **Warren is the primary tenant** — the "tunnel" is thin/idle and its real job is
   hosting the node. Warren gets most of the 52 MB; a lean Rust seeder fits
   comfortably.
2. **Both run lean** — Warren in a hard-capped seeder mode (few connections,
   disk-backed store, small buffers) alongside a light VPN. Tight but plausible.

What does **not** work: bolting Warren onto a heavy always-forwarding VPN in the
same process. Budget it explicitly, with a probe like VpnHood's
(`footprint/peak/conn/...` to a log), before trusting it on device.

## Architecture: the NE owns the node

The UI lives in the app process; the resident node lives in the NE process. Two
processes cannot both own the `feed::Log` / `blob::Store`. So:

- The **node lives permanently in the NE** as the single authoritative instance,
  with its `data_dir` in the **App Group container** (shared between app and NE).
- The **foreground app is a thin client** that sends commands (`publish`, `fetch`,
  `refresh`) to the NE via `NETunnelProviderSession.sendProviderMessage`, and reads
  results / rendered blobs from the shared container.
- On a **jetsam kill under system pressure**, the NE relaunches (on-demand /
  always-on config) and the node **rebuilds from `data_dir`** — which Warren
  already does (`store::rebuild`, `store::load_or_create_seed`). Restart is a
  re-hydrate, not data loss; this maps onto the existing design for free.

## Integration details that bite

- **UDP hole-punch from inside the NE.** Warren's channels are UDP punches. Sockets
  opened in the tunnel provider must be bound to the **physical** interface (via
  `Network.framework` / socket options that bypass the tunnel), or Warren's own
  punch traffic loops back into its own tunnel. This is doable but is the single
  fiddliest piece of the integration.
- **Battery / data policy.** A background seeder over cellular is a battery and data
  sink. Seed aggressively only on **Wi-Fi + power**; on cellular stay minimally
  present (keep announced, accept a few requests) or idle. This is also what keeps
  the feature defensible.
- **App Review.** A VPN app running a P2P node in its NE is legitimate *when the app
  genuinely is a VPN* and is honest about the dual use. Using the NE purely as a
  background-compute shell for an app that isn't really a VPN is the kind of thing
  Apple rejects. For a Lantern-class app the entitlement is already justified.

## What it does and does not solve

- **Solves — availability / suspension.** Turns a phone from "a peer only while
  foregrounded" into a real background seeder. This is the big win.
- **Solves — background wake for seeding.** No APNs round-trip; the node is already
  running. For the seeding role the NE largely *replaces* the blind notifier; APNs
  stays complementary for waking non-VPN clients to receive a message.
- **Does not solve — NAT reachability.** Two symmetric-NAT peers still can't punch
  without a relay (unchanged; see [`design.md`](design.md) and the site's honest
  limitations). This is purely an availability win, not a connectivity one.
- **Bounded by the VPN being on.** The node is alive only while the tunnel is
  connected (user-controlled; on-demand rules extend it), and only within the
  ~52 MB jetsam budget.

## Android note

The same shape applies with `VpnService` (a long-lived foreground service),
generally with more latitude than iOS and without the hard NE memory ceiling —
so if the iOS case closes, Android follows easily.

## First steps (when built)

1. A **lean seeder mode** for `Session`: hard caps on concurrent connections and
   in-flight buffers, disk-backed only, plus a memory probe, validated on device
   against the ~52 MB budget.
2. **NE-hosts-node + app-as-client IPC**: node in the extension over an App Group
   `data_dir`; `sendProviderMessage` command channel; the physical-interface
   socket bypass for punches.
3. A **seeding policy** gate (Wi-Fi + power) wired to the OS reachability/power
   signals.

Design-only for now; no code. The point of this note is that the *substrate*
already fits — a lean Rust node with a disk-backed store and rebuild-on-start is
close to ideal for an NE — and the open work is the iOS integration and the memory
budgeting, not the P2P core.
