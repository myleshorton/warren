//! A live, watchable end-to-end demo of the whole Warren stack, on loopback but
//! over real UDP sockets — no mocks, no server.
//!
//!   cargo run -p transfer --example stream
//!
//! A publisher writes a short "video" as a signed feed and announces it on the
//! DHT under its key. A viewer, knowing only that key, discovers the publisher,
//! punches a direct connection, and streams the video back — verifying every
//! frame against the publisher's signature. The feed's public key is both the
//! video's id and the publisher's address (as in Hypercore), so one key does
//! both jobs.

use std::sync::Arc;
use std::time::Duration;

use crypto::Keypair;
use driver::Node;
use feed::Log;
use swarm::sim::Rng;
use swarm::NodeId;
use tokio::time::timeout;
use transfer::{download_feed, serve_feed, Config};

const LO: &str = "127.0.0.1:0";
const T: Duration = Duration::from_secs(20);

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
    let node_id = NodeId::from_bytes(feed_pk.to_bytes());
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

    let key_hex: String = feed_pk.to_bytes()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("[publish] feed key 0x{key_hex}…  (this key is both the video id and the publisher's DHT address)");
    println!(
        "[publish] wrote {} frames ({} KiB total, ~{} KiB each — a frame is larger than one datagram) to a signed feed",
        frames.len(),
        total_bytes / 1024,
        total_bytes / frames.len() / 1024,
    );

    let publisher = Node::bind(lo, node_id).await?;
    publisher.add_contact(bootstrap).await?;
    timeout(T, publisher.bootstrap()).await??;
    timeout(T, publisher.announce(node_id)).await??;
    println!(
        "[publish] announced on the DHT at {}",
        publisher.local_addr()
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

    println!("[viewer]  discovering the publisher by key and hole-punching a connection...");
    let conn = timeout(T, viewer.connect(node_id)).await??;
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
