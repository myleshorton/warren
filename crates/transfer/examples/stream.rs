//! A live, watchable end-to-end demo of the whole Warren stack, on loopback but
//! over real UDP sockets — no mocks, no server.
//!
//!   cargo run -p transfer --example stream
//!
//! A publisher writes a short "video" as a signed feed and announces it on the
//! DHT under a *blinded, rotating topic* — conceptually `H(feed_key ‖ epoch)`
//! (concretely `crypto`'s per-epoch keyed-BLAKE3 `blinded_topic`), not the
//! cleartext key. A viewer, knowing only the feed key, computes the same topic,
//! looks it up to discover *who* serves the content, punches a direct connection
//! to that node, and streams the video back — verifying every frame against the
//! publisher's signature.
//!
//! Two censorship properties are visible in the log:
//!  * the publisher's DHT node id is random, so the feed key is not a node id —
//!    dialing the key directly reaches no one (node-id decoupling);
//!  * discovery goes through the blinded topic, so a DHT crawler who does not
//!    hold the feed key sees only an opaque id that rotates every epoch. (A censor
//!    who *does* hold the key can still recompute it — hiding it from them is the
//!    PSK-blinded variant's job, not shown here.)

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crypto::{epoch, Keypair};
use driver::Node;
use feed::Log;
use swarm::sim::Rng;
use swarm::NodeId;
use tokio::time::timeout;
use transfer::{download_feed, serve_feed, Config};

const LO: &str = "127.0.0.1:0";
const T: Duration = Duration::from_secs(20);
/// How long a topic stays fixed before rotating. Tunable: shorter tightens the
/// window a crawler gets but adds re-announce churn. An hour is a demo value.
const EPOCH_LEN_SECS: u64 = 3600;
/// How often to re-announce — well under `EPOCH_LEN_SECS`, so the publisher stays
/// discoverable as the DHT churns and rolls smoothly across each epoch boundary.
const REANNOUNCE_INTERVAL: Duration = Duration::from_secs(900);

/// First six bytes of an id as hex, for readable logging.
fn short(bytes: &[u8]) -> String {
    bytes.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let lo = LO.parse().unwrap();
    println!("=== Warren: streaming a signed feed across a serverless network ===\n");

    // --- A small DHT backbone -------------------------------------------------
    print!("[network] bringing up a 7-node DHT on loopback (1 bootstrap + 6 peers)... ");
    let mut rng = Rng::new(0x5EED);
    let boot = Node::bind(lo, rng.node_id()).await?;
    let mut backbone = Vec::new();
    for _ in 0..6 {
        let n = Node::bind(lo, rng.node_id()).await?;
        n.add_contact(boot.contact()).await?;
        timeout(T, n.bootstrap()).await??;
        backbone.push(n);
    }
    let bootstrap = boot.contact();
    println!("up.");

    // --- Publisher ------------------------------------------------------------
    let feed_kp = Keypair::from_seed(&[42u8; 32]);
    let feed_pk = feed_kp.public();
    // The feed key is the video id and the content key you verify against. The
    // node id is random — the key is not the publisher's node id. Content is
    // discovered under a blinded topic that rotates with the epoch, not the key.
    let node_id = rng.node_id();
    assert_ne!(
        node_id.as_bytes(),
        &feed_pk.to_bytes(),
        "the publisher's node id is independent of the feed key"
    );
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs();
    let ep = epoch(now_secs, EPOCH_LEN_SECS);
    let topic = |e: u64| NodeId::from_bytes(feed_pk.blinded_topic(e));

    // Each "frame" is ~40 KiB — larger than a single UDP datagram — so streaming
    // it exercises the transport's fragmentation: every block is split across
    // many datagrams and reassembled (then verified) on the viewer's side.
    let frames: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            let mut frame = format!("frame {i:02}: ").into_bytes();
            frame.resize(40_000, i);
            frame
        })
        .collect();
    let total_bytes: usize = frames.iter().map(Vec::len).sum();

    let mut log = Log::new(feed_kp);
    for frame in &frames {
        log.append(frame.clone());
    }
    let log = Arc::new(log);

    println!(
        "[publish] feed key    0x{}…  (the video id and the key every frame is verified against)",
        short(feed_pk.as_bytes())
    );
    println!(
        "[publish] node id     0x{}…  (random — the feed key is not this node's id)",
        short(node_id.as_bytes())
    );
    println!(
        "[publish] blinded topic 0x{}…  (derived from the feed key for epoch {ep}; a crawler without the key sees only this, and it rotates each epoch)",
        short(topic(ep).as_bytes())
    );
    println!(
        "[publish] wrote {} frames ({} KiB total, ~{} KiB each — a frame is larger than one datagram) to a signed feed",
        frames.len(),
        total_bytes / 1024,
        total_bytes / frames.len() / 1024,
    );

    let publisher = Node::bind(lo, node_id).await?;
    publisher.add_contact(bootstrap).await?;
    timeout(T, publisher.bootstrap()).await??;
    // Keep re-announcing rather than announcing once: the node id (reachability,
    // so a coordinated connect can reach it) plus the current and next epoch's
    // blinded topic (boundary overlap). The closure recomputes the epoch from the
    // wall clock each round, so the announces follow the rotation on their own;
    // holding `_announcer` keeps the loop alive for the run.
    let _announcer = timeout(
        T,
        publisher.keep_announced(REANNOUNCE_INTERVAL, move || {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before 1970")
                .as_secs();
            let e = epoch(now, EPOCH_LEN_SECS);
            vec![
                node_id,
                NodeId::from_bytes(feed_pk.blinded_topic(e)),
                NodeId::from_bytes(feed_pk.blinded_topic(e + 1)),
            ]
        }),
    )
    .await?;
    println!(
        "[publish] announced (and re-announcing every {}s): reachable as node 0x{}…, serving under blinded topics for epochs {ep} and {}",
        REANNOUNCE_INTERVAL.as_secs(),
        short(node_id.as_bytes()),
        ep + 1
    );

    // Serve one inbound viewer.
    let serve_log = log.clone();
    let serve_node = publisher.clone();
    tokio::spawn(async move {
        if let Ok(mut channel) = serve_node.next_incoming().await {
            let _ = serve_feed(&mut channel, &serve_log, &Config::default()).await;
        }
    });

    // --- Viewer ---------------------------------------------------------------
    println!("\n[viewer]  knows only the feed key. Joining the DHT...");
    let viewer = Node::bind(lo, rng.node_id()).await?;
    viewer.add_contact(bootstrap).await?;
    timeout(T, viewer.bootstrap()).await??;

    // Decoupling, made visible: the feed key is not a node id, so dialing it
    // directly (what a censor who scraped the key would try) reaches no one.
    println!("[viewer]  the feed key is not a node id — dialing it directly finds no publisher:");
    let by_key = timeout(T, viewer.connect(NodeId::from_bytes(feed_pk.to_bytes()))).await??;
    println!("[viewer]  → {:?}", by_key.outcome);

    // The real path: compute the same blinded topic from the feed key and look it
    // up (current + previous epoch, for boundary overlap), then connect to the
    // discovered random-id provider.
    let viewer_ep = epoch(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before 1970")
            .as_secs(),
        EPOCH_LEN_SECS,
    );
    println!(
        "[viewer]  deriving the blinded topic from the feed key for epoch {viewer_ep} = 0x{}… and looking it up (+ previous epoch)...",
        short(topic(viewer_ep).as_bytes())
    );
    // Always query both the current and previous epoch and merge — the publisher
    // might be present under one but not the other (partial DHT replication), and
    // `saturating_sub` keeps epoch 0 from underflowing.
    let mut providers = timeout(T, viewer.lookup(topic(viewer_ep))).await??;
    for c in timeout(T, viewer.lookup(topic(viewer_ep.saturating_sub(1)))).await?? {
        if !providers.iter().any(|p| p.id == c.id) {
            providers.push(c);
        }
    }
    let provider = providers
        .iter()
        .find(|c| c.id == node_id)
        .ok_or("no provider announced under the blinded topic")?;
    println!(
        "[viewer]  found provider node 0x{}… — connecting and hole-punching a direct channel...",
        short(provider.id.as_bytes())
    );
    let conn = timeout(T, viewer.connect(provider.id)).await??;
    let outcome = conn.outcome;
    let mut channel = conn.channel.ok_or_else(|| {
        format!("connect resolved {outcome:?} with no data channel (a Relayed outcome yields none by design)")
    })?;
    println!("[viewer]  connected: {outcome:?} — a direct path, no server relaying");

    println!("[viewer]  streaming frames over the punched channel — each split across datagrams, reassembled, and verified...");
    let received = timeout(T, download_feed(&mut channel, feed_pk, &Config::default())).await??;

    // --- Result ---------------------------------------------------------------
    let ok = received == frames;
    let got_bytes: usize = received.iter().map(Vec::len).sum();
    println!(
        "[viewer]  ✓ received {}/{} frames ({} bytes), every frame verified against the publisher's signature",
        received.len(),
        frames.len(),
        got_bytes
    );
    println!(
        "\n[done]    the viewer reconstructed the exact video with no server in the path: {}",
        if ok { "match ✓" } else { "MISMATCH ✗" }
    );
    if !ok {
        return Err("reconstructed video did not match".into());
    }
    Ok(())
}
