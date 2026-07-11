//! The peer request protocol: how one peer asks another, over a punched channel,
//! to serve a signed feed or a content-addressed blob.
//!
//! A one-byte request kind prefixes the exchange. `warren` reserves `REQ_FEED`
//! (0) and `REQ_BLOB` (1); an application may define its own additional kinds and
//! dispatch them in its own accept loop (Murmur, for instance, adds a moderation-
//! list kind). Feed requests reply with the server's 32-byte feed public key —
//! the trust anchor every downloaded block is verified against — then stream the
//! log; blob requests stream the (content-addressed, self-verifying) blob.

use driver::{Channel, Node};
use swarm::NodeId;

/// Request the peer's signed feed. The peer replies with its 32-byte feed public
/// key, then serves the feed.
pub const REQ_FEED: u8 = 0;
/// Request a blob by its (already-known) content id.
pub const REQ_BLOB: u8 = 1;
/// Request a *specific* feed by key: this byte is followed by the 32-byte feed
/// public key, and the peer serves that feed whether it's the peer's own or a
/// [`feed::Replica`] it mirrors. (Applications choose their own additional kinds;
/// `warren` reserves 0, 1, and 3.)
pub const REQ_FEED_KEY: u8 = 3;

/// Serve our feed to a peer that asked for it: send our feed public key (the trust
/// anchor) first, then stream the log. Returns `false` on a broken channel.
pub async fn serve_feed(
    channel: &mut Channel,
    feed_pubkey: &crypto::PublicKey,
    log: &feed::Log,
    cfg: &transfer::Config,
) -> bool {
    if channel.send(&feed_pubkey.to_bytes()).await.is_err() {
        return false;
    }
    transfer::serve_feed(channel, log, cfg).await.is_ok()
}

/// Serve our feed to a **live subscriber**: send our feed key, then hold the
/// connection open and push new blocks as they're appended (see
/// [`transfer::serve_feed_tail`]). A superset of [`serve_feed`] — a batch client
/// that never polls with `Tail` is served identically — so an accept loop can use
/// this for every feed request. Signal `appended` on each append to `log`.
pub async fn serve_feed_tail(
    channel: &mut Channel,
    feed_pubkey: &crypto::PublicKey,
    log: &std::sync::Mutex<feed::Log>,
    appended: &tokio::sync::Notify,
    cfg: &transfer::Config,
) -> bool {
    if channel.send(&feed_pubkey.to_bytes()).await.is_err() {
        return false;
    }
    transfer::serve_feed_tail(channel, log, appended, cfg)
        .await
        .is_ok()
}

/// Serve a blob to a peer that asked for it.
pub async fn serve_blob(
    channel: &mut Channel,
    store: &blob::Store,
    cfg: &transfer::Config,
) -> bool {
    transfer::serve_blob(channel, store, cfg).await.is_ok()
}

/// Connect to `peer`, do the feed handshake (send `req`, receive the peer's 32-byte
/// feed key), then **live-tail** its feed from block `from`: deliver each new block
/// via `on_block` as it's appended, verified against the served key. Runs until the
/// channel breaks (or the future is dropped). The peer must serve with
/// [`serve_feed_tail`].
pub async fn subscribe_feed<F>(
    node: &Node,
    peer: NodeId,
    req: u8,
    from: u64,
    cfg: &transfer::Config,
    on_block: F,
) -> Result<(), String>
where
    F: FnMut(u64, Vec<u8>),
{
    let conn = node
        .connect(peer)
        .await
        .map_err(|e| format!("connect: {e:?}"))?;
    let mut ch = conn.channel.ok_or("no data channel")?;
    ch.send(&[req]).await.map_err(|e| format!("send: {e}"))?;

    let mut buf = [0u8; 64];
    // Bound the handshake reply: a provider we reached but that never answers (a
    // dead-but-reachable peer) must not stall the caller — in a failover loop it
    // would otherwise wedge the whole subscription on one silent provider.
    let n = match tokio::time::timeout(cfg.request_timeout * 2, ch.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(format!("recv: {e}")),
        Err(_) => return Err("handshake timed out".to_string()),
    };
    if n < 32 {
        return Err("no feed key in handshake".to_string());
    }
    let pk_bytes: [u8; 32] = buf[..32].try_into().map_err(|_| "bad feed key")?;
    let pubkey = crypto::PublicKey::from_bytes(&pk_bytes).map_err(|_| "bad feed key")?;
    transfer::subscribe_feed(&mut ch, pubkey, from, cfg, on_block)
        .await
        .map_err(|e| format!("{e:?}"))
}

/// Live-tail a *specific* feed `feed_key` from `provider` — which may be the feed's
/// author (serving its own log) or a mirror (serving a [`feed::Replica`] of it).
/// Sends [`REQ_FEED_KEY`] + the target key; the provider replies with the key it's
/// serving, which must match, then streams the tail (every block verified against
/// `feed_key`). This is what makes swarm-failover subscription work: the caller
/// can point it at any provider that announced the feed's topic.
pub async fn subscribe_feed_by_key<F>(
    node: &Node,
    provider: NodeId,
    feed_key: crypto::PublicKey,
    from: u64,
    cfg: &transfer::Config,
    on_block: F,
) -> Result<(), String>
where
    F: FnMut(u64, Vec<u8>),
{
    let conn = node
        .connect(provider)
        .await
        .map_err(|e| format!("connect: {e:?}"))?;
    let mut ch = conn.channel.ok_or("no data channel")?;
    let key_bytes = feed_key.to_bytes();
    let mut req = Vec::with_capacity(1 + key_bytes.len());
    req.push(REQ_FEED_KEY);
    req.extend_from_slice(&key_bytes);
    ch.send(&req).await.map_err(|e| format!("send: {e}"))?;

    // The provider echoes the feed key it's about to serve; it must be ours.
    let mut buf = [0u8; 64];
    // Bound the handshake reply: a provider we reached but that never answers (a
    // dead-but-reachable peer) must not stall the caller — in a failover loop it
    // would otherwise wedge the whole subscription on one silent provider.
    let n = match tokio::time::timeout(cfg.request_timeout * 2, ch.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(format!("recv: {e}")),
        Err(_) => return Err("handshake timed out".to_string()),
    };
    if n < 32 || buf[..32] != key_bytes[..] {
        return Err("provider does not serve the requested feed".to_string());
    }
    transfer::subscribe_feed(&mut ch, feed_key, from, cfg, on_block)
        .await
        .map_err(|e| format!("{e:?}"))
}

/// Keep a mirror's [`feed::Replica`] of `feed_key` current: handshake by key with
/// `provider`, then live-tail into `into`, firing `appended` on each growth (so our
/// own downstream subscribers are pushed the new blocks at once). The counterpart
/// to [`subscribe_feed_by_key`] for a store-and-forward mirror. Returns on channel
/// error; the caller re-connects (failing over across the feed's providers).
pub async fn replicate_feed_by_key(
    node: &Node,
    provider: NodeId,
    feed_key: crypto::PublicKey,
    into: &std::sync::Mutex<feed::Replica>,
    appended: &tokio::sync::Notify,
    cfg: &transfer::Config,
) -> Result<(), String> {
    let conn = node
        .connect(provider)
        .await
        .map_err(|e| format!("connect: {e:?}"))?;
    let mut ch = conn.channel.ok_or("no data channel")?;
    let key_bytes = feed_key.to_bytes();
    let mut req = Vec::with_capacity(1 + key_bytes.len());
    req.push(REQ_FEED_KEY);
    req.extend_from_slice(&key_bytes);
    ch.send(&req).await.map_err(|e| format!("send: {e}"))?;

    let mut buf = [0u8; 64];
    // Bound the handshake reply: a provider we reached but that never answers (a
    // dead-but-reachable peer) must not stall the caller — in a failover loop it
    // would otherwise wedge the whole subscription on one silent provider.
    let n = match tokio::time::timeout(cfg.request_timeout * 2, ch.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(format!("recv: {e}")),
        Err(_) => return Err("handshake timed out".to_string()),
    };
    if n < 32 || buf[..32] != key_bytes[..] {
        return Err("provider does not serve the requested feed".to_string());
    }
    transfer::replicate_feed(&mut ch, feed_key, into, appended, cfg)
        .await
        .map_err(|e| format!("{e:?}"))
}

/// Bootstrap a [`feed::Replica`] of `feed_key` from `provider` — the one-shot full
/// download a mirror does before it starts live-tailing. Handshakes by key (so the
/// provider may be the author or another mirror), downloads the whole feed with its
/// signed head, and builds a `Replica` (which self-verifies: wrong key, a doctored
/// block, or a truncated log all yield `None`). Feed a live `replicate_feed` from
/// the returned replica to keep it current.
pub async fn fetch_replica(
    node: &Node,
    provider: NodeId,
    feed_key: crypto::PublicKey,
    cfg: &transfer::Config,
) -> Option<feed::Replica> {
    let conn = node.connect(provider).await.ok()?;
    let mut ch = conn.channel?;
    let key_bytes = feed_key.to_bytes();
    let mut req = Vec::with_capacity(1 + key_bytes.len());
    req.push(REQ_FEED_KEY);
    req.extend_from_slice(&key_bytes);
    ch.send(&req).await.ok()?;

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(cfg.request_timeout * 2, ch.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n < 32 || buf[..32] != key_bytes[..] {
        return None;
    }
    let (head, blocks) = transfer::download_feed_full(&mut ch, feed_key, cfg)
        .await
        .ok()?;
    feed::Replica::new(feed_key, head?, blocks)
}

/// Connect to `peer`, send the feed-style request kind `req`, receive the peer's
/// 32-byte feed public key, and download + verify the feed it serves. Returns the
/// raw signed blocks plus the key they were verified against. Used both for the
/// standard [`REQ_FEED`] and for app-defined feed-shaped kinds (e.g. a signed
/// moderation list).
pub async fn fetch_feed(
    node: &Node,
    peer: NodeId,
    req: u8,
    cfg: &transfer::Config,
) -> Option<(Vec<Vec<u8>>, crypto::PublicKey)> {
    let conn = node.connect(peer).await.ok()?;
    let mut ch = conn.channel?;
    ch.send(&[req]).await.ok()?;

    let mut buf = [0u8; 64];
    let n = ch.recv(&mut buf).await.ok()?;
    if n < 32 {
        return None;
    }
    let pk_bytes: [u8; 32] = buf[..32].try_into().ok()?;
    let pubkey = crypto::PublicKey::from_bytes(&pk_bytes).ok()?;
    let blocks = transfer::download_feed(&mut ch, pubkey, cfg).await.ok()?;
    Some((blocks, pubkey))
}

/// Open blob channels to several providers of `blob_hash` for a swarm download:
/// the known feed provider plus everyone announcing `content_topic`. Each returned
/// channel has already sent the [`REQ_BLOB`] header, ready to hand to `transfer`.
pub async fn gather_blob_channels(
    node: &Node,
    content_topic: NodeId,
    feed_provider: Option<NodeId>,
    max: usize,
) -> Vec<Channel> {
    let me = node.id();
    let mut ids: Vec<NodeId> = Vec::new();
    if let Some(p) = feed_provider {
        if p != me {
            ids.push(p);
        }
    }
    if let Ok(contacts) = node.lookup(content_topic).await {
        for c in contacts {
            if c.id != me && !ids.contains(&c.id) {
                ids.push(c.id);
            }
        }
    }
    let mut channels = Vec::new();
    for id in ids.into_iter().take(max) {
        if let Ok(conn) = node.connect(id).await {
            if let Some(ch) = conn.channel {
                if ch.send(&[REQ_BLOB]).await.is_ok() {
                    channels.push(ch);
                }
            }
        }
    }
    channels
}
