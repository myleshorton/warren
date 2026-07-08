//! Two real UDP nodes discover and connect over the DHT — on loopback, in one
//! process, but over actual sockets (not the simulator).
//!
//! Run with: `cargo run -p driver --example two_node`

use driver::Node;
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
    Ok(())
}
