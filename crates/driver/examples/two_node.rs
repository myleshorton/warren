//! Two real UDP nodes discover and connect over the DHT — on loopback, in one
//! process, but over actual sockets (not the simulator).
//!
//! Run with: `cargo run -p driver --example two_node`

use driver::{open_channel, DataListener, Node, PunchConfig};
use swarm::sim::Rng;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let lo = "127.0.0.1:0".parse().unwrap();
    let mut rng = Rng::new(0xD00D);

    // A small backbone the two peers bootstrap off.
    let boot = Node::bind(lo, rng.node_id()).await?;
    println!("bootstrap node at {}", boot.local_addr());

    // Held for the rest of the run so the backbone stays up.
    let mut backbone = Vec::new();
    for _ in 0..5 {
        let n = Node::bind(lo, rng.node_id()).await?;
        n.add_contact(boot.contact()).await?;
        n.bootstrap().await?;
        backbone.push(n);
    }

    // Server announces under its own id.
    let server = Node::bind(lo, rng.node_id()).await?;
    server.add_contact(boot.contact()).await?;
    server.bootstrap().await?;
    server.announce(server.id()).await?;
    println!(
        "server {:?} announced at {}",
        server.id(),
        server.local_addr()
    );

    // Client discovers and connects to the server by id.
    let client = Node::bind(lo, rng.node_id()).await?;
    client.add_contact(boot.contact()).await?;
    client.bootstrap().await?;

    let found = client.lookup(server.id()).await?;
    println!(
        "client looked up server id -> {} record(s), server present: {}",
        found.len(),
        found.iter().any(|c| c.id == server.id())
    );

    let outcome = client.connect(server.id()).await?;
    println!("client connected to server over real UDP -> {outcome:?}");

    // Now turn that into a live data channel: the server stands up a listener,
    // the client punches a channel to it, and they exchange application bytes.
    let listener = DataListener::bind("127.0.0.1:0".parse().unwrap()).await?;
    let data_addr = listener.local_addr()?;
    let cfg = PunchConfig::default();
    let accept = tokio::spawn(async move { listener.accept(&cfg).await });

    let chan = open_channel(
        "127.0.0.1:0".parse().unwrap(),
        data_addr,
        &PunchConfig::default(),
    )
    .await?
    .expect("channel established");
    let server_chan = accept.await??.expect("server channel");

    chan.send(b"hello over the punched channel").await?;
    let mut buf = [0u8; 64];
    let n = server_chan.recv(&mut buf).await?;
    println!(
        "server received {} bytes: {:?}",
        n,
        String::from_utf8_lossy(&buf[..n])
    );
    Ok(())
}
