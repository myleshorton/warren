//! The session engine: join a PSK channel and publish / discover records, fetch /
//! stream blobs, and mirror — all content-agnostic.
//!
//! A `Session` owns the node, the signed feed log, the blob store, the feed
//! identity, and the channel keys, and exposes the data-plane operations an
//! application drives. It is **runtime-agnostic** (its methods are `async`; the
//! app supplies the executor) and carries no app concerns: telemetry, moderation,
//! and any UI/FFI types live in the application, which layers them on top of these
//! operations. Murmur is one such application (short video); a chat client would
//! be another.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Mutex as AsyncMutex;

use crate::record::{Enc, Record};
use crate::{channel, protocol, store, util};

/// How many providers to swarm a blob from at once (origin + mirrors + seeders).
pub const MAX_SOURCES: usize = 5;
/// A viewer reseeds clips it streams, but only ones this small, and only while it
/// holds fewer than [`RESEED_HELD_CAP`] blobs — bounds so a device doesn't cache
/// unboundedly.
const RESEED_MAX_BYTES: usize = 16 * 1024 * 1024;
const RESEED_HELD_CAP: usize = 96;
/// Backoff between failover rounds when a subscribe/mirror loop has tried every
/// known provider of a feed, so it re-looks-up at a bounded rate instead of spinning.
const RESUBSCRIBE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

/// The channel keys + topic domains a session runs under. `content_key` empty ⇒ a
/// blind node that can discover, cache, and serve ciphertext but cannot decrypt.
#[derive(Clone)]
pub struct Keys {
    pub channel_psk: Vec<u8>,
    pub content_key: Vec<u8>,
    /// App topic namespace for discovery, e.g. `b"myapp:channel:v1"`.
    pub channel_domain: Vec<u8>,
    /// App topic namespace for content, e.g. `b"myapp:content:v1"`.
    pub content_domain: Vec<u8>,
    /// App topic namespace for feed discovery, e.g. `b"myapp:feed:v1"` — the domain
    /// under which a feed's author + mirrors announce so a subscriber finds them.
    pub feed_domain: Vec<u8>,
    /// Domain separating the content KEK derivation, e.g. `b"myapp:content-kek:v1"`.
    pub kek_domain: Vec<u8>,
}

/// What a discovery pass turned up.
pub struct Discovered {
    /// Each discovered record, its author's feed key, and the node that served it.
    pub records: Vec<(Record, crypto::PublicKey, swarm::NodeId)>,
    /// The members found online (including ourselves) — for the app's bootstrap
    /// cache; the caller filters out its own id.
    pub members: Vec<swarm::Contact>,
    /// Every member we connected to and downloaded a feed from, with its node id +
    /// feed key — **including members whose feed was empty**. An app resolving a
    /// list/label author by feed key (e.g. a moderation list published by someone
    /// with no posts of their own) needs these, not just the record authors.
    pub reached: Vec<(swarm::NodeId, crypto::PublicKey)>,
    /// How many members we connected to and downloaded a feed from.
    pub connected: usize,
}

/// A running session over one channel. Cheap to `clone` — every field is a handle
/// (the node, `Arc`-shared log/store/held/clip-keys, a copied key) — so a clone is
/// the *same* session, which lets an app move one into a spawned task.
#[derive(Clone)]
pub struct Session {
    /// The DHT node, exposed so the app can announce + run its own accept loop.
    pub node: driver::Node,
    /// The signed feed log. A **sync** mutex, not async: it's locked briefly per
    /// operation and never held across an `.await`, so a live-tail serve (which
    /// locks per reply, forever) can't block appends.
    log: Arc<StdMutex<feed::Log>>,
    store: Arc<AsyncMutex<blob::Store>>,
    feed_pubkey: crypto::PublicKey,
    keys: Keys,
    data_dir: PathBuf,
    held: Arc<StdMutex<Vec<crypto::Hash>>>,
    clip_keys: Arc<StdMutex<HashMap<String, Enc>>>,
    /// Fired on every append to `log` so a live-tail serve wakes and pushes at once.
    appended: Arc<tokio::sync::Notify>,
    /// Feeds we mirror on behalf of other authors, keyed by feed-key hex: a verified
    /// [`feed::Replica`] plus the `Notify` fired when it grows (so our own live-tail
    /// serve pushes the new blocks to downstream subscribers). This is the blind-
    /// mirror store-and-forward layer — we keep an author's feed available and
    /// tailable even while the author is offline.
    mirrored: Arc<StdMutex<HashMap<String, Mirror>>>,
}

/// A mirrored feed: the replica we keep current, and the signal fired when it grows.
type Mirror = (Arc<StdMutex<feed::Replica>>, Arc<tokio::sync::Notify>);

impl Session {
    /// Build a session over already-loaded state (see [`store::rebuild`] for the
    /// log/store and [`store::load_or_create_seed`] for the identity).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: driver::Node,
        log: Arc<StdMutex<feed::Log>>,
        store: Arc<AsyncMutex<blob::Store>>,
        feed_pubkey: crypto::PublicKey,
        keys: Keys,
        data_dir: PathBuf,
        held: Arc<StdMutex<Vec<crypto::Hash>>>,
        clip_keys: Arc<StdMutex<HashMap<String, Enc>>>,
    ) -> Self {
        Self {
            node,
            log,
            store,
            feed_pubkey,
            keys,
            data_dir,
            held,
            clip_keys,
            appended: Arc::new(tokio::sync::Notify::new()),
            mirrored: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// Shared feed log — the app's accept loop serves it (via `serve_feed_tail`,
    /// paired with [`Self::appended`]). Locked per operation, never across `.await`.
    pub fn log(&self) -> Arc<StdMutex<feed::Log>> {
        self.log.clone()
    }
    /// The append signal to pass to `serve_feed_tail`; fired whenever we publish, so
    /// a live subscriber is pushed the new block immediately.
    pub fn appended(&self) -> Arc<tokio::sync::Notify> {
        self.appended.clone()
    }
    /// Shared blob store — the app's accept loop serves from it.
    pub fn store(&self) -> Arc<AsyncMutex<blob::Store>> {
        self.store.clone()
    }
    /// The blobs we can serve, so the app can advertise their content topics in its
    /// re-announce loop.
    pub fn held(&self) -> Arc<StdMutex<Vec<crypto::Hash>>> {
        self.held.clone()
    }
    /// Our feed public key (the trust anchor peers verify our feed against).
    pub fn feed_pubkey(&self) -> crypto::PublicKey {
        self.feed_pubkey
    }

    /// The current discovery epoch.
    pub fn current_epoch() -> u64 {
        channel::current_epoch()
    }
    /// This channel's discovery topic at `epoch`.
    pub fn channel_topic(&self, epoch: u64) -> swarm::NodeId {
        channel::channel_topic(&self.keys.channel_domain, &self.keys.channel_psk, epoch)
    }
    /// The content topic a `blob` is announced/looked-up under.
    pub fn content_topic(&self, blob: &[u8]) -> swarm::NodeId {
        channel::content_topic(&self.keys.content_domain, blob)
    }
    /// The discovery topic for a feed keyed by its owner's `feed_key` bytes — where
    /// the author and every mirror announce, so a subscriber finds all providers.
    pub fn feed_topic(&self, feed_key: &[u8]) -> swarm::NodeId {
        channel::feed_topic(&self.keys.feed_domain, feed_key)
    }
    /// Our own feed's discovery topic — announce it so subscribers can tail us.
    pub fn own_feed_topic(&self) -> swarm::NodeId {
        self.feed_topic(&self.feed_pubkey.to_bytes())
    }
    /// The feed topics of every feed we currently mirror — announce these too, so a
    /// subscriber can fail over to us when the author (or another mirror) drops.
    pub fn mirror_topics(&self) -> Vec<swarm::NodeId> {
        self.mirrored
            .lock()
            .expect("mirrored")
            .keys()
            .filter_map(|hex| util::from_hex(hex).map(|b| self.feed_topic(&b)))
            .collect()
    }

    /// The channel content key-encryption-key. `None` for a blind node.
    fn kek(&self) -> Option<[u8; 32]> {
        if self.keys.content_key.is_empty() {
            None
        } else {
            Some(crypto::seal::derive_key(
                &self.keys.content_key,
                &self.keys.kek_domain,
            ))
        }
    }

    /// Unwrap a blob's content key + nonce for decryption. `None` for a plaintext
    /// blob (no envelope), a blind node, or a wrapped key that doesn't open under
    /// our channel key.
    fn clip_cipher(&self, id: &str) -> Option<([u8; 32], [u8; 24])> {
        let kek = self.kek()?;
        let enc = self.clip_keys.lock().expect("clip_keys").get(id).cloned()?;
        let nonce: [u8; 24] = util::bytes_from_hex(&enc.n)?;
        let wrap_nonce: [u8; 24] = util::bytes_from_hex(&enc.wn)?;
        let wrapped = util::from_hex(&enc.wk)?;
        let key = crypto::seal::unwrap_key(&kek, &wrap_nonce, &wrapped)?;
        Some((key, nonce))
    }

    /// Announce that we hold `blob_hash` under its content topic right now, so it's
    /// swarm-discoverable immediately rather than at the next re-announce round.
    pub async fn announce_content(&self, blob_hash: crypto::Hash) {
        let _ = self.node.announce(self.content_topic(&blob_hash)).await;
    }

    /// Publish a record with a blob payload: seal + wrap the payload under the
    /// content KEK (unless blind), content-address the ciphertext, append the signed
    /// record, persist, hold + announce. Returns the completed record (with `blob`,
    /// `size`, and `enc` filled in). The caller supplies `content_type` and any
    /// app-specific `meta`.
    pub async fn publish(
        &self,
        content_type: String,
        meta: serde_json::Map<String, serde_json::Value>,
        payload: Vec<u8>,
    ) -> std::io::Result<Record> {
        let (stored, enc) = match self.kek() {
            Some(kek) => {
                let sealed = crypto::seal::seal(&payload);
                let (wrap_nonce, wrapped) = crypto::seal::wrap_key(&kek, &sealed.key);
                let enc = Enc {
                    n: util::to_hex(&sealed.nonce),
                    wn: util::to_hex(&wrap_nonce),
                    wk: util::to_hex(&wrapped),
                };
                (sealed.ciphertext, Some(enc))
            }
            None => (payload.clone(), None),
        };

        let blob_hex = {
            let mut store = self.store.lock().await;
            let manifest = store.add(&stored);
            let id = manifest.id();
            store.put(manifest.encode());
            util::to_hex(&id)
        };

        let record = Record {
            author: util::to_hex(&self.feed_pubkey.to_bytes()),
            created_at: util::now_secs(),
            content_type,
            blob: Some(blob_hex.clone()),
            size: payload.len() as u64,
            body: None,
            meta,
            enc: enc.clone(),
            ..Default::default()
        };
        // Never append an empty/garbage block on a serialize error — that would
        // corrupt the signed log. (A plain Record can't fail to serialize, but treat
        // it as an error rather than silently persisting nonsense.)
        let line = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.log
            .lock()
            .expect("feed log")
            .append(line.clone().into_bytes());
        self.appended.notify_waiters(); // wake any live-tail subscribers
        store::append_record(&self.data_dir, &blob_hex, &stored, &line)?;

        if let Some(hash) = util::bytes_from_hex::<32>(&blob_hex) {
            self.held.lock().expect("held").push(hash);
            self.announce_content(hash).await;
        }
        if let Some(enc) = enc {
            self.clip_keys
                .lock()
                .expect("clip_keys")
                .insert(blob_hex, enc);
        }
        Ok(record)
    }

    /// Publish a **body-only** record (no blob) — a chat message, a comment, any small
    /// inline payload. Fills in author + timestamp, persists the line, appends the
    /// signed block, and fires `appended` so live subscribers are pushed it at once.
    /// `clock`/`lamport` carry the multi-writer merge position (see [`crate::merge`]);
    /// pass empty/`0` for content that needs no cross-writer ordering.
    ///
    /// The body is **not encrypted** — even in a channel with a content key. Unlike
    /// [`Self::publish`], which seals its blob payload under the content KEK,
    /// `publish_body` writes the body in the clear in the signed record (as record
    /// `meta` already rides), so a blind mirror replicating the feed can read it. Keep
    /// secrets out of it.
    pub async fn publish_body(
        &self,
        content_type: String,
        body: String,
        meta: serde_json::Map<String, serde_json::Value>,
        clock: std::collections::BTreeMap<String, u64>,
        lamport: u64,
    ) -> std::io::Result<Record> {
        let record = Record {
            author: util::to_hex(&self.feed_pubkey.to_bytes()),
            created_at: util::now_secs(),
            content_type,
            blob: None,
            size: 0,
            body: Some(body),
            meta,
            enc: None,
            clock,
            lamport,
        };
        let line = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // Persist first, so a returned `Err` means "not published": only after the
        // durable append do we mutate the in-memory log and notify live subscribers
        // (the log append is infallible, and rebuild replays exactly this line).
        store::append_line(&self.data_dir, &line)?;
        self.log.lock().expect("feed log").append(line.into_bytes());
        self.appended.notify_waiters(); // wake any live-tail subscribers
        Ok(record)
    }

    /// Live-tail a feed by its owner's `feed_key`, from block `from`, delivering each
    /// new block via `on_block` as it's appended. Finds **every** provider of the feed
    /// (its author plus any mirrors) via the feed topic and tails from one, **failing
    /// over** to another whenever a provider drops — so a subscription survives the
    /// author going offline as long as a mirror is up. Every block is verified against
    /// `feed_key`. Runs until the future is dropped/aborted; a real-time app (chat)
    /// spawns one per feed it follows and merges the streams. Providers must serve
    /// with [`Self::serve_by_key`] (Murmur's accept loop does).
    pub async fn subscribe<F>(
        &self,
        feed_key: crypto::PublicKey,
        from: u64,
        mut on_block: F,
    ) -> Result<(), String>
    where
        F: FnMut(u64, Vec<u8>),
    {
        let cfg = transfer::Config::default();
        let me = self.node.id();
        let topic = self.feed_topic(&feed_key.to_bytes());
        let mut cursor = from;
        loop {
            let providers = self.node.lookup(topic).await.unwrap_or_default();
            for p in providers {
                if p.id == me {
                    continue;
                }
                let start = cursor;
                let _ = protocol::subscribe_feed_by_key(
                    &self.node,
                    p.id,
                    feed_key,
                    start,
                    &cfg,
                    |i, b| {
                        cursor = cursor.max(i + 1);
                        on_block(i, b);
                    },
                )
                .await;
            }
            // All providers exhausted (or none online) — back off before re-looking-up.
            tokio::time::sleep(RESUBSCRIBE_BACKOFF).await;
        }
    }

    /// Serve the feed `feed_key` to a subscriber — the accept-loop counterpart to
    /// [`Self::subscribe`], dispatched on a [`protocol::REQ_FEED_KEY`] request. Serves
    /// our own log if `feed_key` is ours, or a [`feed::Replica`] if we mirror it (see
    /// [`Self::mirror_feed`]); either way it live-tails (holds the connection open and
    /// pushes new blocks). `false` if we serve neither.
    pub async fn serve_by_key(
        &self,
        channel: &mut driver::Channel,
        feed_key: crypto::PublicKey,
        cfg: &transfer::Config,
    ) -> bool {
        if feed_key == self.feed_pubkey {
            return protocol::serve_feed_tail(
                channel,
                &self.feed_pubkey,
                &self.log,
                &self.appended,
                cfg,
            )
            .await;
        }
        let hex = util::to_hex(&feed_key.to_bytes());
        let entry = self.mirrored.lock().expect("mirrored").get(&hex).cloned();
        if let Some((replica, appended)) = entry {
            if channel.send(&feed_key.to_bytes()).await.is_err() {
                return false;
            }
            return transfer::serve_feed_tail(channel, &*replica, &appended, cfg)
                .await
                .is_ok();
        }
        false
    }

    /// Begin mirroring `feed_key` on behalf of its author: bootstrap a **verified**
    /// replica from `provider` (a one-shot full download — a doctored or truncated
    /// feed fails to build one), register it, and announce ourselves under the feed's
    /// topic so subscribers can find + fail over to us. Returns the replica handle and
    /// its growth signal, which the app pairs with [`Self::run_mirror`] (spawned) to
    /// keep the replica live. Idempotent: a feed we already mirror returns its handles.
    pub async fn mirror_feed(
        &self,
        provider: swarm::NodeId,
        feed_key: crypto::PublicKey,
    ) -> Option<Mirror> {
        let hex = util::to_hex(&feed_key.to_bytes());
        if let Some(entry) = self.mirrored.lock().expect("mirrored").get(&hex).cloned() {
            return Some(entry);
        }
        let replica =
            protocol::fetch_replica(&self.node, provider, feed_key, &transfer::Config::default())
                .await?;
        let entry: Mirror = (
            Arc::new(StdMutex::new(replica)),
            Arc::new(tokio::sync::Notify::new()),
        );
        self.mirrored
            .lock()
            .expect("mirrored")
            .insert(hex, entry.clone());
        let _ = self
            .node
            .announce(self.feed_topic(&feed_key.to_bytes()))
            .await;
        Some(entry)
    }

    /// Keep a mirrored feed current, forever: fail over across the feed's providers
    /// (author + other mirrors), live-tailing new blocks into `replica` and firing
    /// `appended` so our own downstream subscribers are pushed at once. Spawn this
    /// after [`Self::mirror_feed`]; the app owns the task and aborts it to stop.
    pub async fn run_mirror(
        &self,
        feed_key: crypto::PublicKey,
        replica: Arc<StdMutex<feed::Replica>>,
        appended: Arc<tokio::sync::Notify>,
    ) {
        let cfg = transfer::Config::default();
        let me = self.node.id();
        let topic = self.feed_topic(&feed_key.to_bytes());
        loop {
            let providers = self.node.lookup(topic).await.unwrap_or_default();
            for p in providers {
                if p.id == me {
                    continue;
                }
                let _ = protocol::replicate_feed_by_key(
                    &self.node, p.id, feed_key, &replica, &appended, &cfg,
                )
                .await;
            }
            tokio::time::sleep(RESUBSCRIBE_BACKOFF).await;
        }
    }

    /// Discover the channel: look up members (current + previous epoch), download
    /// each member's feed, and return the records + who served them. Records each
    /// record's encryption envelope for later decryption. Applies **no** filtering —
    /// the app layers its own (e.g. moderation) on the result.
    pub async fn discover(&self) -> Discovered {
        let cfg = transfer::Config::default();
        let e = channel::current_epoch();
        let mut members = self
            .node
            .lookup(self.channel_topic(e))
            .await
            .unwrap_or_default();
        if e > 0 {
            for c in self
                .node
                .lookup(self.channel_topic(e - 1))
                .await
                .unwrap_or_default()
            {
                if !members.iter().any(|m| m.id == c.id) {
                    members.push(c);
                }
            }
        }

        let me = self.node.id();
        let mut records = Vec::new();
        let mut reached = Vec::new();
        let mut clip_keys = Vec::new();
        for member in &members {
            if member.id == me {
                continue;
            }
            if let Some((blocks, pubkey)) =
                protocol::fetch_feed(&self.node, member.id, protocol::REQ_FEED, &cfg).await
            {
                reached.push((member.id, pubkey));
                for b in blocks {
                    if let Ok(rec) = serde_json::from_slice::<Record>(&b) {
                        if let (Some(blob), Some(enc)) = (&rec.blob, &rec.enc) {
                            clip_keys.push((blob.clone(), enc.clone()));
                        }
                        records.push((rec, pubkey, member.id));
                    }
                }
            }
        }
        if !clip_keys.is_empty() {
            self.clip_keys.lock().expect("clip_keys").extend(clip_keys);
        }
        let connected = reached.len();
        Discovered {
            records,
            members,
            reached,
            connected,
        }
    }

    /// Fetch a blob's plaintext by hex id: served locally if held, otherwise
    /// swarmed from every provider announcing it (origin + mirrors), then decrypted.
    /// `None` if no provider has it or the swarm download fails.
    pub async fn fetch(&self, blob_hex: &str, provider: Option<swarm::NodeId>) -> Option<Vec<u8>> {
        let blob_hash: crypto::Hash = util::bytes_from_hex::<32>(blob_hex)?;
        let cipher = self.clip_cipher(blob_hex);
        let raw = if let Some(bytes) = self.local_blob(&blob_hash).await {
            bytes
        } else {
            let channels = protocol::gather_blob_channels(
                &self.node,
                self.content_topic(&blob_hash),
                provider,
                MAX_SOURCES,
            )
            .await;
            if channels.is_empty() {
                return None;
            }
            transfer::download_blob_swarm(channels, blob_hash, &transfer::Config::default())
                .await
                .ok()?
        };
        Some(match cipher {
            Some((key, nonce)) => crypto::seal::open(&key, &nonce, &raw),
            None => raw,
        })
    }

    /// Stream a blob's chunks in playback order to `on_chunk` (decrypted as they
    /// arrive — the cipher is seekable, so progressive playback survives). Served
    /// locally if held, otherwise swarmed. On a complete remote fetch it **reseeds**
    /// the (verified) ciphertext — stores it and re-announces the content topic — so
    /// the next viewer can swarm from us too.
    pub async fn stream<F>(
        &self,
        blob_hex: &str,
        provider: Option<swarm::NodeId>,
        window: usize,
        on_chunk: F,
    ) -> Result<(), String>
    where
        F: Fn(u64, Vec<u8>) + Send,
    {
        let blob_hash: crypto::Hash = util::bytes_from_hex::<32>(blob_hex).ok_or("bad id")?;
        let window = window.max(1);
        let cipher = self.clip_cipher(blob_hex);

        // Local path — deliver in order, no network.
        if let Some(chunks) = self.local_chunks(&blob_hash).await {
            let mut offset = 0u64;
            for (i, mut bytes) in chunks.into_iter().enumerate() {
                if let Some((key, nonce)) = cipher {
                    crypto::seal::xor_keystream(&key, &nonce, offset, &mut bytes);
                }
                offset += bytes.len() as u64;
                on_chunk(i as u64, bytes);
            }
            return Ok(());
        }

        // Remote → swarm the blob from every provider, in order, reseeding on success.
        let reseed = self.held.lock().expect("held").len() < RESEED_HELD_CAP;
        let acc: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(reseed.then(Vec::new)));
        let acc_cb = acc.clone();
        let channels = protocol::gather_blob_channels(
            &self.node,
            self.content_topic(&blob_hash),
            provider,
            MAX_SOURCES,
        )
        .await;
        if channels.is_empty() {
            return Err("no provider".to_string());
        }
        let offset = AtomicU64::new(0);
        let result = transfer::download_blob_stream(
            channels,
            blob_hash,
            &transfer::Config::default(),
            window,
            move |i, bytes| {
                // Accumulate the ciphertext (pre-decrypt) for reseeding.
                {
                    let mut g = acc_cb.lock().expect("acc");
                    if let Some(buf) = g.as_mut() {
                        if buf.len() + bytes.len() <= RESEED_MAX_BYTES {
                            buf.extend_from_slice(bytes);
                        } else {
                            *g = None; // too big; skip reseeding this clip
                        }
                    }
                }
                let mut b = bytes.to_vec();
                if let Some((key, nonce)) = cipher {
                    let off = offset.fetch_add(b.len() as u64, Ordering::Relaxed);
                    crypto::seal::xor_keystream(&key, &nonce, off, &mut b);
                }
                on_chunk(i as u64, b);
            },
        )
        .await
        .map_err(|e| format!("{e:?}"));

        if result.is_ok() {
            let ciphertext = acc.lock().expect("acc").take(); // drop guard before await
            if let Some(ct) = ciphertext {
                let mut s = self.store.lock().await;
                let m = s.add(&ct);
                s.put(m.encode());
                drop(s);
                self.held.lock().expect("held").push(blob_hash);
                self.announce_content(blob_hash).await;
            }
        }
        result
    }

    /// Mirror one blob: swarm it as **raw ciphertext**, store it, and hold +
    /// announce it as a source. Returns whether it was newly cached. The bytes stay
    /// encrypted — a blind mirror adds availability without ever serving plaintext.
    pub async fn cache_blob(&self, blob_hex: &str, provider: Option<swarm::NodeId>) -> bool {
        let Some(blob_hash) = util::bytes_from_hex::<32>(blob_hex) else {
            return false;
        };
        if self.held.lock().expect("held").contains(&blob_hash) {
            return false;
        }
        let channels = protocol::gather_blob_channels(
            &self.node,
            self.content_topic(&blob_hash),
            provider,
            MAX_SOURCES,
        )
        .await;
        if channels.is_empty() {
            return false;
        }
        let Ok(ciphertext) =
            transfer::download_blob_swarm(channels, blob_hash, &transfer::Config::default()).await
        else {
            return false;
        };
        {
            let mut store = self.store.lock().await;
            let manifest = store.add(&ciphertext);
            store.put(manifest.encode());
        }
        self.held.lock().expect("held").push(blob_hash);
        self.announce_content(blob_hash).await;
        true
    }

    /// Reassemble a blob from our local store, if we hold its manifest + chunks.
    async fn local_blob(&self, blob_hash: &crypto::Hash) -> Option<Vec<u8>> {
        let store = self.store.lock().await;
        let manifest = blob::Manifest::decode(store.get(blob_hash)?).ok()?;
        store.reassemble(&manifest)
    }

    /// The blob's chunks in playback order, if we hold its manifest + every chunk.
    async fn local_chunks(&self, blob_hash: &crypto::Hash) -> Option<Vec<Vec<u8>>> {
        let store = self.store.lock().await;
        let manifest = blob::Manifest::decode(store.get(blob_hash)?).ok()?;
        let mut chunks = Vec::with_capacity(manifest.chunks.len());
        for hash in &manifest.chunks {
            chunks.push(store.get(hash)?.to_vec());
        }
        Some(chunks)
    }
}
