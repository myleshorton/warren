//! Data channels over real UDP, at two layers.
//!
//! `data_channel_over_real_udp` drives the standalone puncher API directly
//! (`open_channel` / `DataListener`). `connect_yields_a_live_channel` drives the
//! full path: a single `connect(id)` discovers the peer, coordinates
//! reachability through a DHT coordinator, and punches a live channel — with no
//! out-of-band address exchange (the data-socket addresses ride the DHT
//! signaling). On loopback every node is reachable, so the connect resolves
//! `Direct`.

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
async fn connect_yields_a_live_channel() {
    // The whole path in a single call: A discovers B, coordinates reachability
    // through a DHT coordinator, punches a data channel, and exchanges bytes —
    // no out-of-band address exchange. B receives its side via `next_incoming`.
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

    // B announces so A can find it, and awaits an inbound channel.
    timeout(T, server.announce(server.id()))
        .await
        .unwrap()
        .unwrap();
    let server_id = server.id();
    let server_handle = server.clone();
    let incoming = tokio::spawn(async move { server_handle.next_incoming().await });

    // One connect: discover + coordinate + punch → a live channel.
    let conn = timeout(T, client.connect(server_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.outcome, ConnectOutcome::Direct);
    let client_chan = conn.channel.expect("connect should yield a channel");
    let server_chan = timeout(T, incoming)
        .await
        .unwrap()
        .unwrap()
        .expect("server should receive an inbound channel");

    // Application bytes flow both ways over the punched channel.
    client_chan.send(b"ping").await.unwrap();
    let mut buf = [0u8; 32];
    let n = timeout(T, server_chan.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"ping");

    server_chan.send(b"pong").await.unwrap();
    let n = timeout(T, client_chan.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"pong");
}
