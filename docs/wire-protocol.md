# Warren wire protocol: the opening-book transport

**Status:** design note (2026-07-14). **Phase 0 (Noise-in-core) is built** — see
[myleshorton/warren#50](https://github.com/myleshorton/warren/pull/50): the punched channel is now a
Noise XX channel (forward-secret, mutually authenticated, bound to the peer's node id via
`NodeId = hash(node_pubkey)`). The rest below — the `Link`/`Transport` seam, the opening-book cover
transports, signed signaling — remains the plan. A design for giving Warren a real,
authenticated, encrypted, blend-in transport — replacing the (now closed) plaintext punched
channel. Grounded in a direct read of Warren (`crates/{driver,puncher,transfer,swarm,crypto}`),
[flint](https://github.com/getlantern/flint) (`flint-tls/{gambit,anchor,ja4,connector,profile}`),
spark's opening-book notes, and the censorship-circumvention literature (paper ids in the
form `YEAR-author-topic` are the corpus's canonical ids). Companion to [`design.md`](design.md).

The stance, up front:

- **Be real, don't parrot.** A mimic must satisfy ~12 requirements at once while a censor needs
  one failure (`2013-houmansadr-parrot`: "unobservability by imitation is a fundamentally flawed
  approach"). So run a *real* crypto library for the handshake — never imitate one.
- **Shape only the opening.** A modern censor files its verdict on the first few hundred bytes; if
  the opening passes, the opening was the game. Spend the evasion budget there and leave the
  middlegame to the transport (spark's "opening book").
- **Split the transport by who's on the other end** — peer↔peer is residential, bootstrap touches
  infrastructure, and they face different censorship.
- **Ship a "move" as a few signed bytes** — a genome, not a redeployed binary (flint's `SignedGambit`).

## 0. Ground truth from the code

Three facts shape everything, and each is verified in the tree:

1. **The `Link` seam already exists.** `crates/transfer/src/lib.rs:98` defines `pub trait Link { async fn
   send(&self, &[u8]) -> io::Result<usize>; async fn recv(&self, &mut [u8]) -> io::Result<usize>; }`,
   `driver::Channel` implements it, and `Wire<'a, L: Link>` runs the whole sync + fragmentation +
   selective-repeat + AIMD/pacing protocol over that trait, never touching a socket. So "add a `Link`
   trait" is really **"promote the existing seam and give it more than one implementation."**
2. **Warren's data socket is `connect()`-ed to exactly one peer**, learned via signaling
   (`driver::connect_channel`; `Channel::recv` doc: "the OS drops datagrams from any other source").
   A Warren peer is **not a server** and cannot be probed off-path — worth more for probe resistance
   than any handshake (§5).
3. **The GFW fully-encrypted-traffic detector is scoped to datacenter ranges.** `2023-wu-fully-encrypted-detect`
   (USENIX Sec 2023): blocks fully-random flows with p≈0.26, targeting VPS ASNs, and leaves "most
   residential/enterprise IPs unaffected." Warren's **peer↔peer plane is residential↔residential
   (under the FET radar today); the bootstrap plane touches CDN/cloud infrastructure** (where FET,
   SNI filtering, and whitelisting bite hardest). That asymmetry is why the transport splits by endpoint.

## 1. The `Link` / `Transport` seam

### 1.1 Layering

```
sync (pure) ─ blob/feed verification, request/response state machines
   │  Message
transfer::Wire<L: Link> ─ fragmentation + selective-repeat + AIMD/pacing   ← UNCHANGED
   │  send(&[u8]) / recv(&mut [u8])            (whole Warren datagrams)
╔══╪═══════════════════════════════════════════════════════════════╗
║  Link  (the seam)  ← plain-UDP | Noise | DTLS-WebRTC | QUIC-H3 | H2 ║   NEW: >1 impl
╚══╪═══════════════════════════════════════════════════════════════╝
   │  a connected datagram socket + (optionally) a completed opening
puncher::Established { socket, peer }  ─ PROBE/ACK hole punch          ← gains a Probe seam
   │
UdpSocket
```

The `Link` sits **above `puncher`, below `transfer::frame`**. `transfer::Wire` is the invariant: it
already tolerates loss/reordering/duplication, so it rides an *unreliable* encrypted transport (DTLS
records, QUIC DATAGRAM frames) with no double-reliability — which also keeps the middlegame looking
like media, which is unreliable too.

### 1.2 The traits (new `crates/link`)

```rust
/// The datagram seam transfer::Wire runs over. (Today's transfer::Link, relocated, + mtu/auth.)
#[allow(async_fn_in_trait)]
pub trait Link: Send {
    async fn send(&self, datagram: &[u8]) -> io::Result<usize>;
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Max Warren-payload bytes per datagram after this transport's own framing overhead.
    /// plain-UDP ≈ 1232; DTLS 1.3 ≈ 1232 − 13(rec hdr) − 16(AEAD tag) − 1(content-type);
    /// QUIC DATAGRAM ≈ 1232 − ~3(frame hdr) − ~5(short hdr) − 16(AEAD); Noise ≈ 1232 − 16.
    /// transfer replaces its hard-coded FRAGMENT=1200 with `link.max_payload()`.
    fn max_payload(&self) -> usize;

    /// AEAD/authenticated? A plain-UDP link is false and keeps transfer's current
    /// hostile-header hardening; an authenticated link may relax it.
    fn authenticated(&self) -> bool;
}

/// Turns a punched socket (or, for bootstrap, a fresh dial) into a Link by running
/// the opening handshake. One impl per cover.
#[allow(async_fn_in_trait)]
pub trait Transport {
    type Link: Link;
    /// Dialer side. `est` is the punched, connected socket from `puncher`.
    async fn connect(&self, est: puncher::Established, peer: NodeIdentity) -> io::Result<Self::Link>;
    /// Listener side (the reachable peer).
    async fn accept(&self, est: puncher::Established, peer: NodeIdentity) -> io::Result<Self::Link>;
}

/// Everything a Transport needs to authenticate the peer, from the *signed Signal* (§4.5).
pub struct NodeIdentity {
    pub node_pubkey: [u8; 32],        // Ed25519 — NodeId == crypto::hash(node_pubkey)
    pub dtls_fp:     Option<[u8; 32]>,// expected DTLS cert fingerprint (WebRTC binding model)
    pub ice:         Option<IceCreds>,// ufrag/pwd for STUN short-term auth (WebRTC path)
    pub role_seed:   u64,             // deterministic DTLS-client / ICE-controlling tiebreaker
}
```

`puncher` today hard-codes `PROBE=1`/`ACK=2`. Generalize that behind a `Probe` trait (default = the
current 1-byte exchange) so a transport can supply its own punch control bytes (the WebRTC path
supplies STUN Binding Request/Response):

```rust
pub trait Probe {
    fn probe(&self) -> Vec<u8>;                       // what to spray  (plain: [1])
    fn ack(&self)   -> Vec<u8>;                       // reply on receipt (plain: [2])
    fn is_control(&self, dgram: &[u8]) -> ControlKind;// Probe | Ack | NotControl
}
```

Nothing else in `puncher` (birthday spray, IP-match accept, `_any` candidate fan-out) changes.

### 1.3 How each implementation slots in

| Impl | Opening | send/recv maps a Warren datagram to… | `authenticated()` | Used |
|---|---|---|---|---|
| **`PlainUdp`** (= today's `Channel`) | PROBE/ACK punch only | `sendto`/`recvfrom` verbatim | `false` | uncensored primary; tests |
| **`NoiseLink`** (`snow`, IK/XX) | 1–1.5-RTT Noise after punch | Noise transport msg (AEAD, 16-B tag) | `true` | bare-UDP, residential↔residential **only** (§4.4) |
| **`DtlsWebrtc`** (peer) | **STUN/ICE = the punch**, then real DTLS 1.3 | one DTLS application-data record | `true` | residential↔residential under a UDP-hostile censor |
| **`DtlsConnectionIdOnly`** (peer) | STUN punch + one-shot key setup, **no visible DTLS handshake** | DTLS 1.3 record w/ Connection ID (RFC 9146) | `true` | where the DTLS *handshake itself* is blocked |
| **`QuicH3`** (bootstrap) | real QUIC-TLS 1.3 dial to CDN/DoH edge (no punch) | QUIC DATAGRAM frame (RFC 9221) or a bidi stream | `true` | rendezvous/config where UDP/443 lives |
| **`H2Tls`** (bootstrap) | real Chrome-JA4 TLS 1.3 over TCP-443 (flint) | H2 DATA frame / stream body | `true` | **required** fallback where UDP/QUIC is dropped (§3) |

Two structural consequences:

- **On the WebRTC path the punch merges with the opening.** ICE connectivity checks *are* hole
  punches, so `DtlsWebrtc`'s `Probe` supplies STUN Binding Request/Response as probe/ack — the bytes
  crossing the NAT are byte-for-byte a browser ICE agent's. This is why WebRTC is the natural
  residential↔residential cover: its own NAT traversal is the punch.
- **`transfer` must ask the `Link` for its MTU** — replace `const FRAGMENT: usize = 1200` with
  `link.max_payload()`, because each transport subtracts different overhead.

## 2. WebRTC opening book (peer path)

**Goal:** the residential↔residential UDP-punched link opens like a browser WebRTC session — a real
ICE/STUN exchange plus a real DTLS 1.3 handshake with a browser-matched ClientHello — then carries
Warren's encrypted datagrams as the "media" middlegame. **We do not build a libwebrtc media stack.**

### 2.1 The honest problem statement (flag #1)

`2016-fifield-fingerprintability` extends "the Parrot is Dead" to WebRTC: a non-browser implementation
is fingerprintable across DTLS version, cipher ordering, certificate common-name, cert validity, STUN
server selection, and ICE packet sequence. Two adversaries — say which we beat:

- **The deployed adversary (a DTLS-ClientHello fingerprint rule):** beatable, and our primary target.
- **A WebRTC-*conformance* adversary (ICE choreography, cert conventions, DTLS-SRTP, packet sequence):**
  a DTLS-lib-only opening will **not** fully fool this. Fully "being real" means being a real browser
  (as naiveproxy is real Chrome), which the direction rules out.

Stance, plainly: **we shape the opening to defeat the deployed fingerprint rule and to be spec-correct
enough to pass a structural check, and we accept residual conformance distinguishers rather than
pretend to eliminate them.**

Two hard caveats:
- **Cover-population thinness (flag #4).** A one-day LBNL capture found only **7 DTLS handshakes**
  (`2016-fifield-fingerprintability` §5) — a perfectly-shaped WebRTC opening is still a *rare* flow
  where video calling is uncommon, and rarity is a signal. Value is highest where video calling is
  common — a per-deployment judgement.
- **Today's WebRTC blocking is deterministic DPI, not ML** (`2026-vilalonga-obscura`). So the
  *opening fingerprint* is the live battleground; the flow-ML threat (§5) is the trajectory to design
  for, not yet the deployed reality.

### 2.2 JA3/JA4-for-DTLS is real and deployed

Correcting a common misconception: a JA3/JA4-for-DTLS **exists and is the actual peer-path adversary.**
Russia (TSPU) began blocking Snowflake **2026-03-30 by detecting DTLS ClientHello JA3/JA4 fingerprints**;
in-country PCAPs proved it fingerprint-based — every failed connection shared one fingerprint, and a
single connection with a *different* fingerprint succeeded (`2026-wkrp-snowflake-targeted-dtls-filtering`;
net4people/bbs#603). The tool `dfind` identifies the pion stack by unique DTLS-extension byte patterns
(`2025-midtlien-fingerprint-resistant`). Consequences:
- **The anchor must track a moving browser target.** Chrome randomized its DTLS extension order from
  v129 (Sept 2024 → 6! = 720 permutations); Firefox defaulted to DTLS 1.3 from v127. Per-session
  extension-order randomization is a *feature to match*, not just drift to guard.
- **RFC 5763 makes the DTLS *client* the fingerprintable role** — shape whichever side initiates DTLS.

### 2.3 Genome format: reuse flint's envelope, add WebRTC layers

flint's `SignedGambit`/`Gambit` envelope ports **wholesale** — detached Ed25519 over `postcard(gambit)`,
`PinnedKeys`, monotonic `version` anti-rollback (`verify(&keys, floor)` rejects `version <= floor`), and
`requires: Vec<Capability>` gating (an executor declines a move whose capabilities it can't meet and
falls back to its best portable one — "a bold move never costs a connection"). Keep it byte-for-byte. Add:

```rust
pub enum Anchor {                        // extends flint's enum (serde-tagged)
    Chrome137,                           // flint's TCP-TLS anchor (unchanged)
    WebrtcChrome { major: u16 },         // NEW: versioned per browser release (ext order moves)
    WebrtcFirefox { major: u16 },        // NEW
    WebrtcMessenger { family: MsgFamily },// NEW: Signal/WhatsApp calling stacks
}

// Extend flint's Capability vocab with:
pub enum Capability {
    /* …flint's Ech, Alps, PqKem, SessionIdInject, RawClientHello… */
    Dtls13,                // offer DTLS 1.3 (else fall back to a 1.2 anchor)
    SrtpExt,               // include use_srtp (a positive WebRTC tell)
    StunShortTermAuth,     // MESSAGE-INTEGRITY over ICE ufrag/pwd
    DtlsRandomizeExtOrder, // per-session ClientHello ext permutation (§2.3, constrained to cipher_set)
    DtlsConnectionIdOnly,  // the no-visible-handshake mode (§2.6)
}

/// Layer S — the STUN/ICE opening (this path's punch).
pub struct Stun {
    pub software: Option<String>,     // SOFTWARE attribute, or omit (browsers omit)
    pub fingerprint: bool,            // append FINGERPRINT attr — browsers: yes
    pub message_integrity: MiMode,    // SHORT_TERM keyed by ICE ufrag/pwd from the signed Signal
    pub priority_formula: IcePriority,// RFC 8445 candidate priority; match browser type-preferences
    pub nomination: Nomination,       // aggressive (Chrome) | regular
    // transaction ids: 96-bit random per RFC 5389, NEVER pinned (fresh each time = replay defense)
}

/// Layer D — the DTLS ClientHello (the Layer-A analog for datagram TLS).
pub struct DtlsClientHello {
    pub extension_order: Option<Perm>,// reuse flint's Perm { PermuteSeed(u32) | Explicit(Vec<u16>) }
    pub cipher_order:    Option<Perm>,
    pub cipher_set:      Vec<CipherId>,   // the ANCHOR cipher set — randomization is constrained to THIS
    pub curves:          Vec<NamedGroup>, // browser-matched order, e.g. [X25519, P-256]
    pub sig_algs:        Vec<SigScheme>,  // ECDSA P-256 SHA-256 first (WebRTC convention)
    pub use_srtp:        Vec<SrtpProfile>,// present even though we carry no SRTP (a WebRTC tell)
    pub dtls_version:    DtlsVersion,     // 1.2 | 1.3 — match the anchor
    pub cookie_echo:     bool,            // honor the HelloVerifyRequest cookie round-trip (RFC 9147)
    pub grease:          Option<u32>,
    pub cert:            WebrtcCertPolicy,// self-signed ECDSA P-256, ~30-day validity, generic/absent CN
}
```

- **Layer A reuse.** The DTLS 1.3 ClientHello *is* a TLS 1.3 ClientHello with datagram extras
  (`use_srtp`, the cookie round-trip, DTLS codepoints in `supported_versions`), so flint's
  permutation-from-seed, GREASE, ALPS, and padding knobs carry directly.
- **`use_srtp` is load-bearing.** A DTLS handshake *without* `use_srtp` is not a WebRTC handshake; we
  offer it even though we never send SRTP (we carry Warren datagrams as DTLS application data).
- **`DtlsRandomizeExtOrder` constrained to the anchor cipher set.** Full per-session randomization is
  ~10¹² permutations but drives handshake failure to ~27% if it offers ciphers the responder rejects
  (`2025-midtlien-fingerprint-resistant`, Table 1: browser mimicry 18.2% failure vs 12.5% baseline).
  **Because both Warren endpoints are ours, we control the accepted set** — so we randomize the
  extension order aggressively *within* `cipher_set` with no failure penalty. A genuine advantage over
  Snowflake's client-to-arbitrary-bridge case, and why the capability is gated to the anchor's ciphers.

### 2.4 Anchor + drift control (no FoxIO JA4-for-DTLS, so define our own)

flint's discipline transfers (`anchor.rs`: run the handshake against an in-memory EOF stream, compute
the fingerprint, CI-assert it equals the pinned anchor, human-validate out of band). Since FoxIO JA4 is
TLS/QUIC-only:

- **Define `ANCHOR_DTLS_FP`** — a KAT-pinned tuple over the DTLS ClientHello:
  `dtls-version ‖ ordered-cipher-list ‖ ordered-extension-list ‖ curves ‖ sig-algs ‖ use_srtp-profiles ‖
  grease-pattern`. "JA4-for-DTLS, our construction," pinned like `crypto::blinded_topic`'s wire bytes.
- **Source the anchor from real browsers/messengers, not the DTLS lib's defaults** — those defaults are
  exactly what got pion blocked. Capture current Chrome/Firefox/Signal DTLS ClientHellos
  (`chrome://webrtc-internals` + pcap), pin per browser major. **Reuse/vendor Psiphon's `covert-dtls`
  browser profiles** — the production answer to net4people#603.
- **Rust DTLS reality (honesty).** The mature browser DTLS stack is BoringSSL. To get byte-exact
  browser cipher/curve/extension lists, drive **BoringSSL via `boring2` in DTLS mode** (the dependency
  flint already carries), feature-gated like flint's `boring` feature — rather than a pure-Rust
  `webrtc-dtls` crate whose defaults are the *blocked* fingerprint. Real cost: a C/cmake build.

### 2.5 The opening, byte level, and the DTLS-client tiebreaker

Dialer D and reachable peer R have exchanged a **signed Signal** (§4.5) carrying each other's
`node_pubkey`, ICE `ufrag`/`pwd`, `dtls_fp`, `data_addrs`, and `role_seed`.

1. **ICE connectivity checks = the punch.** Both sides send STUN Binding Requests to the peer's
   `data_addrs` (replaces `[PROBE]`), each with `USERNAME=R.ufrag:D.ufrag`, `MESSAGE-INTEGRITY` keyed by
   the signed `pwd`, `PRIORITY`, `ICE-CONTROLLING`/`CONTROLLED`, `FINGERPRINT`. First valid Binding
   Success Response with a matching `XOR-MAPPED-ADDRESS` = the punched path (replaces `[ACK]`). Birthday
   spray for symmetric NAT is unchanged; it sprays STUN.
2. **DTLS-client role tiebreaker.** RFC 5763 makes one side the DTLS client (the fingerprintable role).
   Decide deterministically: the peer with the lower `H(role_seed ‖ min(pk_D,pk_R) ‖ max(pk_D,pk_R))` is
   DTLS client — both agree without an extra round trip, and an observer can't steer it.
3. **DTLS 1.3 handshake** over the punched `connect()`-ed socket, ClientHello shaped by
   `DtlsClientHello`, honoring the HelloVerifyRequest cookie (RFC 9147). The peer presents a fresh
   self-signed ECDSA P-256 cert; the handshake is accepted **iff the cert fingerprint equals `dtls_fp`
   in the signed Signal** — WebRTC's actual identity model, and how the Ed25519 node identity binds the
   session (§4.2).
4. **Opening ends at DTLS `Finished`.** The genome goes silent. The next datagram is Warren's first
   `sync::Message` fragment, carried as **DTLS application-data records, not SRTP** (Warren already has
   its own reliability/framing; SRTP would add a redundant media framing to fake). Honest seam: **the
   opening is real WebRTC choreography; the middlegame is Warren datagrams wearing a DTLS record
   header** — that mismatch is §5.

### 2.6 `DtlsConnectionIdOnly` — the no-visible-handshake variant

Where the DTLS *handshake itself* is blocked (observed from a VPS in Iran), **Oscur0 never completes a
visible handshake — it sends only Application Data with a Connection ID (RFC 9146) after a one-shot
setup** (`2024-chen-extended`). Add a second peer-path variant: after the STUN opening and a one-shot
key setup (keyed from the signed-Signal material), run DTLS 1.3 with Connection ID and no observable
ClientHello/ServerHello flight. It trades WebRTC-opening realism for handshake invisibility — the right
move against a censor that blocks the DTLS handshake rather than fingerprinting it. Capability
`DtlsConnectionIdOnly`; the executor picks it per the deployment's signed policy.

## 3. QUIC-Initial reuse of flint + the required TCP-443 sibling (bootstrap path)

**Goal:** peer→infrastructure dialing (rendezvous, config/bootstrap fetch, CDN-frontable/DoH) opens
like a browser→CDN HTTP/3 session. Highest flint reuse — bootstrap is flint's `BootstrapDial` remit.

### 3.1 What ports directly from flint

- The entire envelope (`SignedGambit`, Ed25519 verify, anti-rollback `floor`, `PinnedKeys`, `Capability`
  gating, the `GambitContext`/`compute_gambit` dynamic path).
- Layer A (`ClientHello`) almost verbatim — a QUIC Initial carries a TLS 1.3 ClientHello in CRYPTO
  frames; the permutation-from-seed, GREASE, ECH mode, ALPS, PQ-KEM (X25519MLKEM768) knobs apply
  (Chrome offers ECH+PQ over QUIC, so these are *required* to match).
- JA4 machinery, QUIC variant — FoxIO JA4 defines a QUIC form (`q` prefix) folding in
  `transport_parameters`; `ja4.rs` extends rather than gets replaced. Add a `Chrome137Quic` anchor with
  a pinned `ANCHOR_JA4Q` + the same capture-and-pin CI drift guard.
- The engine-capability-split pattern (flint `design.md`: real ECH in rustls, exact Chrome-JA4 in boring).

### 3.2 What is genuinely new (QUIC-specific)

- **QUIC Initial packet protection (RFC 9001)** — Initial keys via HKDF over a version-specific
  `initial_salt` + the client DCID, then AEAD + a header-protection mask. Pin: QUIC version, DCID length
  distribution, **Initial padding to ≥1200 bytes** (Chrome does this — a hard requirement and a
  fingerprint), packet-number-length convention, coalescing of Initial+Handshake+0-RTT.
- **Version negotiation** — pin offered version(s); censors key on which versions Chrome offers.
- **`transport_parameters` extension** — part of JA4Q, must match.
- **Connector** — a stack whose ClientHello you can shape: **`quiche` (BoringSSL-backed) or boring's
  QUIC API**, keeping flint's pinned cipher/curve lists so JA4Q stays consistent. `quinn` (rustls) would
  fork the fingerprint from flint's boring lineage — not recommended for the shaped path.

### 3.3 The required real-H2-over-TCP-443 sibling (do not skip)

QUIC is safe under the *throttling* regime but **fails in an Iran-style whitelist shutdown.** Iran June
2025 forwarded only DNS/53, HTTP/80, HTTPS/443-**TCP** externally, and explicitly "QUIC/HTTP3 … will
fail" (`2025-aryapour-stealth-blackout`); two Iranian ASes drop non-matching traffic after **~6 packets**
regardless of IP (`2025-alaraj-iran-refraction`). So the bootstrap plane needs **`H2Tls` — real
Chrome-JA4 TLS 1.3 / HTTP-2 over TCP-443, using flint directly — as a first-class sibling, not a
throttle fallback.** QUIC/H3 is *preferred* where UDP/443 lives; flint's H2 is *required* where it
doesn't. Nearly free since it *is* flint (`connect()` + `record_fragment`/`tcp_split` + the
CDN-edge/raw-IP/hostname pool). Avoid TLS-in-TLS: encapsulated inner-TLS-over-TCP handshakes are
detectable protocol-agnostically at >1M users, but a QUIC-inner transport is "structurally immune"
(`2024-xue-fingerprinting`) — so where QUIC survives it beats a tunnel; where it doesn't, use flint's
*real* H2, not a nested tunnel.

Bootstrap is **not punched** (client→CDN, no `Established`); `QuicH3`/`H2Tls::connect()` take an
endpoint set + genome, race compositions (happy-eyeballs / flint's smart-dialer), and return a `Link`.
Since payloads are Ed25519-signed (Warren already signs feeds/records), the channel needs integrity of
a small blob, not tunnel confidentiality.

## 4. Encryption and identity

### 4.1 The cover's real handshake *is* the confidentiality+auth layer

On both hardened paths the cover's own handshake supplies confidentiality, integrity, and forward
secrecy — no separate Warren crypto handshake to fingerprint:

- **Peer path:** DTLS 1.3 (RFC 9147) — TLS 1.3 core over datagrams, AEAD records, ephemeral ECDHE →
  forward secrecy. Replaces today's plaintext punched channel. `crypto::seal` stays for *content*
  (blind relays/mirrors, at-rest, per-recipient key-wrap); DTLS adds *transport* confidentiality +
  on-path integrity that content-addressing never provided.
- **Bootstrap path:** QUIC-TLS 1.3 / TLS 1.3 (H2), same guarantees.

### 4.2 Binding the Ed25519 node identity (the realistic version)

"Make the DTLS/QUIC cert key be the Ed25519 node key" **breaks the cover** — browsers present ECDSA
P-256 self-signed certs for WebRTC and CA chains for H3; an Ed25519 cert is itself a fingerprint. Bind
the way WebRTC actually binds — **fingerprint-in-signed-metadata**, with the DHT Signal as signed SDP:

1. Each node has a **node keypair** (Ed25519, distinct from any feed/content key). `NodeId =
   crypto::hash(node_pubkey)` — self-certifying, and it **preserves the node-id/content-key decoupling**.
2. Peer path uses a fresh ephemeral ECDSA P-256 self-signed DTLS cert per session (WebRTC-shaped:
   generic/absent CN, ~30-day validity).
3. The **signed Signal** carries `{ node_pubkey, dtls_cert_fingerprint, ice_ufrag, ice_pwd, data_addrs,
   nat, role_seed, epoch, ts }`, signed by the node key. DTLS is accepted **iff the presented cert
   fingerprint == the signed one.** The browser-shaped cert is unauthenticated on its own (as in real
   WebRTC); the Ed25519 node key authenticates it out of band through the Signal.
4. Bootstrap path: the QUIC/H2 cert is a real CDN/origin cert (verified as a browser would); node
   identity is asserted by signing the *application* payload with the node key.

### 4.3 Replay resistance comes free from server randomness

The GFW defeats exact-match replay caches by *permuting* replayed bytes (`2020-frolov-httpt`), so "any
protocol that must authenticate clients should incorporate server-provided randomness." DTLS/QUIC
already mix server randomness into key derivation, so replay is dead on the hardened paths for free. Do
**not** build a static-nonce auth (Shadowsocks's mistake, `2020-alice-shadowsocks-detection`).

### 4.4 Noise IK/XX as the bare-UDP fallback (with hard caveats)

For a bare-UDP link with no cover (both peers residential, no UDP hostility), run **Noise (`snow`)**:
**IK** when the initiator knows the responder's static key (it does, from the signed Signal) — 1-RTT,
responder-identity hiding, binds the node key directly (here Noise *can* use the node key — no cover
cert to imitate); **XX** for the general no-prior-key case. Caveats the research forces:

- A Noise handshake on bare UDP is *look-like-nothing* — high-entropy from byte one; `2023-wu` blocks
  exactly this on datacenter ranges (obfs4 is dead for it). **Safe only residential↔residential, never
  toward a datacenter.** If a Noise link must touch a monitored range, apply the cheap escape hatch (a
  ≥6-byte printable-ASCII preamble, GFW Ex2/Ex3, or a TLS/HTTP prefix, Ex5) — a patch, not a plan.
- **If Noise uses Elligator2 to hide static keys, ship uniformity KAT vectors.** obfs4's Elligator
  flaws (non-canonical square roots, bit-255 always zero, prime-order-only points) made keys
  100%-distinguishable until fixed (`2023-fifield-comments` §3). Add these alongside `crypto`'s existing
  BLAKE3/Ed25519 KATs.

### 4.5 Signed Signal + capability tokens (the DHT fix)

Today `swarm::msg::Packet` is `{ sender: NodeId, rid, msg }` with an opaque, unbound `NodeId` and an
**unsigned `Signal`** — anyone can announce under another's id or forge a Signal's `data_addrs`
(redirection/amplification). Fix in three signed records:

```rust
// NodeId = hash(node_pubkey); packets prove possession of that key.
struct SignedAnnounce { topic: NodeId, node_pubkey: [u8;32], addr: SocketAddr,
                        epoch: u64, sig: Signature }        // sig by node key over the rest
struct SignedSignal   { target, initiator, initiator_addr, data_addrs, nat, is_reply,
                        node_pubkey, dtls_fp: [u8;32], ice_ufrag, ice_pwd, role_seed,
                        ts: u64, sig: Signature }            // the endpoint that OWNS data_addrs signs
struct CapabilityToken { subject: [u8;32] /*node_pubkey*/, topic: NodeId,
                         epoch: u64, grant: Signature }      // signed by the channel authority key
```

Announces/Signals verify (`NodeId == hash(node_pubkey)` + signature) — a censor can no longer announce
*as* another provider or hand a victim forged punch targets. Capability tokens gate *who may serve a
private/PSK channel* (the channel authority signs a grant binding a node pubkey to a topic for an
epoch); public content stays permissionless but the announce is still signed to raise poisoning cost.
Composes with blinded/rotating topics + per-epoch re-announce (the token's `epoch` matches the topic's).

**Tension:** signatures add ~96 bytes and a distinctive structure, fighting the "ride a public DHT for
collateral-freedom" mitigation (Mainline/Hyperswarm packets are unsigned bencode). Resolution: keep the
*routing* RPC (`FIND_NODE`/`Nodes`) Mainline-shaped and carry signature material **inside opaque value
payloads** (BEP-44 "mutable item" style), not on every packet.

## 5. Active-probing resistance and the flow/timing reality

### 5.1 Why probing a Warren peer is weak for the censor

The strongest probe-resistance property is structural, and Warren already has it: **the data socket is
`connect()`-ed to exactly one signaling-authenticated peer.** So:

- An **off-path prober** is dropped by the OS before a byte reaches the transport. Unlike
  REALITY/trojan/naive — servers that must accept arbitrary probes and need elaborate fail-to-real — **a
  Warren peer is not a server.** Lean on this; don't reimplement REALITY.
- An **on-path prober** that observed the punch can spoof the peer's src IP:port. Against `PlainUdp` it
  can inject/observe (content stays safe — hash/signature-verified — but the session can be disrupted).
  Against DTLS/QUIC/Noise, AEAD makes injection fail and the stream opaque. **This — not probe
  deflection — is the real reason to run the handshake on hostile paths.**
- **Residual probe surface = the rendezvous/bootstrap plane**, closed by §4.5 + real-CDN fronting.

Rules the surfaces that *do* accept unauthenticated bytes must satisfy:
1. **Fail-to-real must be complete** — "LZR identifies 99% of unexpected services in five handshakes"
   (`2024-durumeric-ten-years-zmap`); ShadowTLS was caught via three tiny divergences until it forwarded
   *everything* unrecognized to the real mask site (`2023-wang-chasing`). The QUIC/H2 bootstrap front is
   a real CDN/DoH endpoint (it is), so this holds by construction.
2. **Silent drop is a fingerprint unless it matches real-host base rates** — infinite-timeout hosts are
   0.7% of an ISP tap but 42% of active scans (`2020-frolov-detecting`). If a surface drops probes,
   match a common finite timeout (10/15/20/30/60 s covers 82% of endpoints).
3. **Per-registration, not global-static, secrets** (Conjure, `2019-frolov-conjure`). The signed Signal
   already gives per-session ICE ufrag/pwd + cert fingerprint — keep them per-session.
4. **Assume probing from day one in TSG-equipped states** (Myanmar, Pakistan, Ethiopia, Kazakhstan —
   the Geedge/MESA export list; procurement, not engineering, is now the censor's only barrier,
   `2025-interseclab-internet-coup`).

### 5.2 The flow/timing reality past the opening (the flag the direction most needs)

The opening-book wager is a bet against a **handshake/first-packet** classifier. It's a *good* bet
against the deployed reality (FET is first-packet; SNI filtering is ClientHello; the pion-DTLS block was
a ClientHello fingerprint; the first ~5–6 packets decide a flow, `2026-kulatilleke-mambanetburst`,
matching the ~6-packet Iran allowlist cutoff). It is **not** a bet you win against a determined **flow**
classifier, and the corpus quantifies why:

- **Cost is no longer the obstacle.** A flow-physics-only classifier (AEGIS) hits **F1 0.9952, FPR
  0.21%, at 262 µs on a single RTX 4090**, discarding all payload (`2026-ferrel-aegis`). "The assumption
  of low censor capability is no longer valid." The Geedge/MESA leak confirms intent + maturity — but
  gives no verdict-timing numbers, so this envelope is the academic one.

A Warren swarm leech that *opens* like a WebRTC call does not *flow* like one:

| Feature | Real WebRTC video call | Warren bulk swarm middlegame |
|---|---|---|
| Bidirectional byte ratio | near-symmetric, ~1–4× | **highly asymmetric, 100–1000×** (down=data; up=tiny NACKs) |
| Throughput envelope | bounded (~1–3 Mbps), jitter-buffer-paced | AIMD ramps to fill the pipe — an elephant flow |
| Packet-size distribution | bimodal (audio + video) | near-uniform MTU DATA + rare tiny NACKs |
| **Flow duration** | call-length, steady rate | **"unusually long vs background UDP"** (`2024-wails-precisely`) |

The **bidirectional byte ratio and flow duration are the sharpest cheap discriminators.**

What actually helps (and what doesn't):
- **The base-rate escape bounds the threat.** Per-flow CNNs on Snowflake reach Prec 0.95 at λ=1k but
  **near-zero precision at λ>10⁶** (`2024-wails-precisely`); today's WebRTC blocking is deterministic
  DPI, not ML (`2026-vilalonga-obscura`). Design for flow-ML; don't panic about it.
- **The strongest mitigation is genuine human-paced multiplexing, not synthetic shaping.** AEGIS
  detection **collapses to 1.17%** when a transport multiplexes *true human browsing entropy*;
  "automated high-throughput flows stay detectable" (`2026-ferrel-aegis` §V-G). Prefer carrying Warren
  sync *alongside* a peer's real interactive traffic (or human-variable pacing) over synthetic padding.
- **Duration rotation is cheap and fits the swarm model** — rotate/reconnect the DTLS session before
  predictable thresholds; Warren's many-short-chunk-fetches-over-rotating-peers is already shaped that way.
- **Tiered policy:** primary (uncensored) → no shaping, `PlainUdp`. Secondary, no flow classifier
  observed → run the WebRTC/QUIC opening, don't shape the middlegame (residential bulk UDP hides in
  BitTorrent-class collateral). Secondary + flow classifier present → opt-in media-profile mode (pace to
  a plausible bitrate; uplink padding to fix the ratio; bimodal sizes) *plus* entropy-borrowing/rotation.

**The blunt truth:** you cannot both saturate a link with a bulk swarm and match a real-time media
flow — they are physically different, and automated high-throughput flows stay detectable regardless of
the opening. The WebRTC opening buys the *opening*; against a flow-classifying censor the honest answer
is entropy-borrowing + duration rotation, and failing that, accepting that Warren's data plane is a
background-P2P flow hiding in BitTorrent collateral, not a video call.

## 6. Reuse-vs-extend flint, and the phased build plan

### 6.1 Lifts from flint directly (no change)

`SignedGambit` envelope + Ed25519 verify + anti-rollback + `PinnedKeys` + `Capability` gating; the Layer
A ClientHello genome; the anchor-drift CI discipline; the JA4 machinery (extended for QUIC + our DTLS
construction); the `GambitContext`/`compute_gambit` delivery path; the `boring2` dependency +
engine-capability-split; and **the `H2Tls` bootstrap path is flint itself.**

### 6.2 Genuinely new code

New anchor families (`WebrtcChrome{major}`/`WebrtcFirefox{major}`/`WebrtcMessenger`, `Chrome137Quic`);
new layers `Stun` + `DtlsClientHello` + QUIC Initial/version/transport-parameters shaping; the
"JA4-for-DTLS" construction (`ANCHOR_DTLS_FP`); QUIC Initial + header protection + version negotiation;
the DTLS record layer + HelloVerifyRequest cookie; the STUN/ICE opening (also `puncher`'s `Probe`);
`DtlsConnectionIdOnly`; the entropy-borrowing/duration-rotation policy; and the Warren plumbing
(`Link`/`Transport`/`Probe` traits, `link.max_payload()`, the signed-Signal/capability records,
`NodeId = hash(node_pubkey)`).

### 6.3 Phased plan (each phase green and shippable on its own)

- **Phase 0 — Noise-in-core (baseline transport crypto). ✅ Built (#50).** `NoiseLink` (Noise **XX**
  via `snow`) as a second `Link` over the *existing* punched socket, + `NodeId = hash(node_pubkey)`
  self-certifying identity, the per-connection X25519 static bound to the Ed25519 id by a signed
  `NodeCert`, and the dialer pinning `hash(peer ed_pub) == target`. The single largest security win —
  closes the plaintext/on-path-injection gap today — with *no* cover work. Residential↔residential
  only (§4.4). Shipped deviations from this sketch: **XX only** (IK deferred — the dialer has no
  peer static yet, that's Phase 2's signed announce); **snow *stateless* transport + an explicit
  per-datagram nonce** so loss/reorder can't desync the cipher under selective-repeat; **Elligator
  deferred** (residential↔residential is under the FET radar). Gate (all green): two ids complete XX
  over a lossy link and a real `transfer` recovers byte-for-byte; a wrong-id dial fails; injected and
  tampered datagrams are rejected by AEAD.
- **Phase 1 — the `Link`/`Transport` seam.** Promote `transfer::Link` into `crates/link`, add
  `Transport` + `max_payload()`, generalize `puncher`'s probe bytes behind `Probe` (default unchanged).
  `PlainUdp` + `NoiseLink` are the first two. No default-path change. Gate: existing tests pass through
  the seam.
- **Phase 2 — signed Signal + capability tokens.** Independent of transports; cheap; closes a real
  spoofing/redirection hole and *pre-builds the identity binding Phase 4 needs.* Keep routing RPC
  Mainline-shaped (signature material in opaque values). Gate: a forged Signal / cross-id announce is
  rejected; blinded-topic + epoch flows still work.
- **Phase 3 — flint bootstrap: `H2Tls` (required) then `QuicH3` (preferred).** Ship the real-Chrome-JA4
  TLS-1.3/H2-over-TCP-443 path first (it *is* flint) so bootstrap survives a whitelist shutdown; then add
  the QUIC connector + `Chrome137Quic` anchor + JA4Q + Initial packet protection/version negotiation.
  Gate: a config fetch through a CDN-edge dial with a Chrome-matched fingerprint; ECH-off composition
  under a simulated ESNI block; the H2 path succeeding when UDP/443 is dropped.
- **Phase 4 — WebRTC opening book (peer path; hardest; last).** `Stun`/`DtlsClientHello` layers,
  browser/`covert-dtls`-derived DTLS anchor + `ANCHOR_DTLS_FP` drift pin, `DtlsRandomizeExtOrder`
  constrained to the anchor cipher set, STUN-as-punch in `puncher`, deterministic DTLS-client
  tiebreaker, DTLS-fingerprint identity binding via the Phase-2 signed Signal. Ship the *opening* first
  (no middlegame shaping); add `DtlsConnectionIdOnly`; add entropy-borrowing/duration-rotation only if a
  deployment reports flow classification. Gate: a peer link opens with a browser-matched DTLS ClientHello
  + spec-correct ICE, completes `transfer`, and a captured opening fingerprints as the pinned anchor.

**Rationale:** Phases 0–2 are all-upside, cover-independent hardening you want regardless of which books
ship, and they de-risk the hard parts (Phase 4's identity binding *is* Phase 2's signed Signal). Phase 3
is high-reuse/low-new-risk; the TCP-443 sibling is nearly free. Phase 4 is highest new-risk, so it goes
last, ships opening-only first, and should be prototyped against a real browser capture + a real censor
testbed before it's trusted.

## The flags — what the research says this direction must accept

1. **The WebRTC opening book defeats the *deployed* DTLS-ClientHello JA3/JA4 rule** (which exists — TSPU
   broke Snowflake this way 2026-03-30), **not a WebRTC-*conformance* adversary** (`2016-fifield`).
   Without a real media/ICE stack you match the opening's fingerprint, not the session's semantics.
2. **The opening-book wager loses to a flow classifier**, now cheap (AEGIS F1 0.9952, `2026-ferrel-aegis`)
   and on the Geedge/ML trajectory. A bulk swarm that opens like a call flows nothing like one.
   Genuine human-entropy multiplexing + duration rotation is what works; the base-rate escape
   (near-zero precision at λ>10⁶) is the bound that keeps it survivable.
3. **QUIC/H3 fails in an Iran-style whitelist shutdown** (`2025-aryapour`). The bootstrap plane
   *requires* a real-H2-over-TCP-443 sibling (flint), not just a QUIC path.
4. **The WebRTC cover population may be too thin to hide in** on many networks (`2016-fifield`: 7 DTLS
   handshakes/day at LBNL). A per-deployment judgement.
5. **The Noise bare-UDP fallback is look-like-nothing and dies to FET on any monitored/datacenter range**
   (`2023-wu`). Residential↔residential baseline only; the printable-preamble is a patch. The
   flint/WebRTC books exist precisely so Warren isn't shipping look-like-nothing where it's watched.

**The one durable lever** across FET, flow-ML, whitelisting, anomaly detection, and probing is the
censor's false-positive/collateral-cost ceiling: **blend into large, high-value, human-paced cover, and
byte-level randomness stops mattering.** That is the deepest justification for the whole direction — and
it names the two hardest truths it lives with: the opening is where "be real" pays off, and the
middlegame is where it runs out.
