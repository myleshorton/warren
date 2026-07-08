//! Data channels over real UDP: discover + coordinate via the DHT, then punch a
//! live channel and exchange application bytes.
//!
//! This closes the loop from "connect reports an outcome" to "connect yields a
//! usable connection". On loopback every node is reachable, so the DHT connect
//! resolves `Direct` and the channel is a direct dial; the data-socket address
//! is exchanged here in-test (carrying it through the DHT signaling so a bare
//! `connect(id)` returns the channel for arbitrary NATed peers is the remaining
//! glue).

use std::net::SocketAddr;
use std::time::Duration;

use driver::{open_channel, ConnectOutcome, DataListener, Node, PunchConfig};
use swarm::sim::Rng;
use tokio::time::timeout;

const LO: &str = "127.0.0.1:0";
// Comfortably longer than the punch's own `overall` (5s) so this outer guard
// can't fire just before a legitimate establishment completes.
const T: Duration = Duration::from_secs(15);

#[tokio::test]
async fn data_channel_over_real_udp() {
    // A bound data listener stands in for the "server" data endpoint.
    let listener = DataListener::bind(LO.parse().unwrap()).await.unwrap();
    let server_data = listener.local_addr().unwrap();

    // One config drives both sides so dial and accept can't diverge; `Config` is
    // `Copy`, so the accept task takes its own copy and we still borrow it below.
    let cfg = PunchConfig::default();
    // peer_host is the *dialer's* host: the client binds here, and the listener
    // only accepts a punch coming from it.
    let client_bind: SocketAddr = LO.parse().unwrap();
    let peer_host = client_bind.ip();
    let accept = tokio::spawn(async move { listener.accept(peer_host, &cfg).await });

    let client = open_channel(client_bind, server_data, &cfg)
        .await
        .unwrap()
        .expect("client should punch a channel");
    let server = timeout(T, accept)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .expect("server should accept a channel");

    // Application bytes flow both ways over the punched channel.
    client.send(b"hello").await.unwrap();
    let mut buf = [0u8; 32];
    let n = timeout(T, server.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"hello");

    server.send(b"world").await.unwrap();
    let n = timeout(T, client.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"world");
}

#[tokio::test]
async fn discover_coordinate_then_open_channel() {
    // Full path: A discovers B and coordinates reachability over the DHT, then
    // opens a real data channel to B and exchanges bytes.
    let lo = LO.parse().unwrap();
    let mut rng = Rng::new(0xC0FFEE);
    let boot = Node::bind(lo, rng.node_id()).await.unwrap();

    let mut peers = Vec::new();
    for _ in 0..6 {
        let n = Node::bind(lo, rng.node_id()).await.unwrap();
        n.add_contact(boot.contact()).await.unwrap();
        timeout(T, n.bootstrap()).await.unwrap().unwrap();
        peers.push(n);
    }
    let server = &peers[0];
    let client = &peers[1];

    // B announces and stands up a data listener; A discovers B and confirms it
    // is reachable via the DHT.
    timeout(T, server.announce(server.id()))
        .await
        .unwrap()
        .unwrap();
    let listener = DataListener::bind(lo).await.unwrap();
    let server_data = listener.local_addr().unwrap();
    // Single config for both sides (see note in `data_channel_over_real_udp`).
    let cfg = PunchConfig::default();
    // peer_host is the dialer's host — the client opens the channel from `lo`.
    let peer_host = lo.ip();
    let accept = tokio::spawn(async move { listener.accept(peer_host, &cfg).await });

    let outcome = timeout(T, client.connect(server.id()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome, ConnectOutcome::Direct);

    // Reachability confirmed over the DHT — now open the actual data channel.
    let a = open_channel(lo, server_data, &cfg)
        .await
        .unwrap()
        .expect("client channel");
    let b = timeout(T, accept)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .expect("server channel");

    a.send(b"ping").await.unwrap();
    let mut buf = [0u8; 32];
    let n = timeout(T, b.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"ping");
}
