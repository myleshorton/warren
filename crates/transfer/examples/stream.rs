//! A live, watchable end-to-end demo of the whole Warren stack, on loopback but
//! over real UDP sockets — no mocks, no server.
//!
//!   cargo run -p transfer --example stream
//!
//! A publisher writes a short "video" as a signed feed and announces it on the
//! DHT under a *topic* (the feed's public key). A viewer, knowing only that key,
//! looks the topic up to discover *who* serves it, punches a direct connection to
//! that node, and streams the video back — verifying every frame against the
//! publisher's signature.
//!
//! The feed's public key is the video's id and its discovery topic, but the
//! publisher's DHT node id is *random and independent*. So the key does not
//! double as a network locator: a censor who scraped it cannot turn it into the
//! publisher's node address — the demo shows a connect-by-key finding nothing
//! before the topic lookup reveals the real (random-id) provider.

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
    // The feed key is the video id and the discovery topic. The node id is
    // random — deliberately unrelated to the key — so knowing the key doesn't
    // reveal (or locate) the publisher's node.
    let topic = NodeId::from_bytes(feed_pk.to_bytes());
    let node_id = rng.node_id();
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
        "[publish] feed key  0x{}…  (the video id and the discovery topic)",
        short(&topic.as_bytes()[..])
    );
    println!(
        "[publish] node id   0x{}…  (random — unrelated to the key, so the key doesn't point here)",
        short(&node_id.as_bytes()[..])
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
    // Two announces: register the node so a coordinated connect can reach it, and
    // register the content under its topic so a viewer can discover who serves it.
    timeout(T, publisher.announce(node_id)).await??;
    timeout(T, publisher.announce(topic)).await??;
    println!(
        "[publish] announced: reachable as node 0x{}…, serving the feed under topic 0x{}…",
        short(&node_id.as_bytes()[..]),
        short(&topic.as_bytes()[..])
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

    // Decoupling, made visible: trying to reach the feed key *as a node* — what a
    // censor who only scraped the key would do — finds no one, because the key is
    // not a node address.
    println!("[viewer]  first, treating the feed key as a node address (as a censor would)...");
    let by_key = timeout(T, viewer.connect(topic)).await??;
    println!(
        "[viewer]  → {:?}: the key is not a locator; you can't reach the publisher by it",
        by_key.outcome
    );

    // The real path: look the topic up to learn which node serves the content,
    // then connect to that node by its (random) id and punch a channel.
    println!("[viewer]  now looking the feed key up as a topic to discover who serves it...");
    let providers = timeout(T, viewer.lookup(topic)).await??;
    let provider = providers
        .iter()
        .find(|c| c.id == node_id)
        .ok_or("no provider announced under the topic")?;
    println!(
        "[viewer]  found provider node 0x{}… — connecting and hole-punching a direct channel...",
        short(&provider.id.as_bytes()[..])
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
