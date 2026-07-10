//! Data channels over real UDP, at two layers.
//!
//! `data_channel_over_real_udp` drives the standalone puncher API directly
//! (`open_channel` / `DataListener`). `connect_yields_a_live_channel` drives the
//! full path: a single `connect(id)` discovers the peer, coordinates
//! reachability through a DHT coordinator, and punches a live channel — with no
//! out-of-band address exchange (the data-socket addresses ride the DHT
//! signaling). On loopback every node is reachable, so a default connect resolves
//! `Direct`; `connect_punches_a_channel_for_symmetric_nat` forces a
//! Consistent↔Random pairing so it resolves `Punched` and runs the birthday
//! punch instead.

use std::net::SocketAddr;
use std::time::Duration;

use driver::{
    open_channel, BirthdayParams, ConnectOutcome, DataListener, Firewall, Node, PunchConfig,
    PunchTuning,
};
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

#[tokio::test]
async fn connect_punches_a_channel_for_symmetric_nat() {
    // Force a Consistent↔Random pairing so the connect resolves `Punched`: the
    // Consistent client sprays random ports, the Random server opens many
    // sockets, and a probe collides — the birthday punch, end to end over
    // loopback (a bounded port range + fast timing keeps it quick and reliable,
    // the OS port space standing in for a symmetric NAT's external ports).
    let tuning = PunchTuning {
        config: PunchConfig::fast(),
        birthday: BirthdayParams {
            range: (20_000, 30_000),
            sockets: 256,
            probes: 5_000,
        },
        port_mapping: false,
    };
    let lo = LO.parse().unwrap();
    let mut rng = Rng::new(0xB1D7A);
    let boot = Node::bind_with(lo, rng.node_id(), tuning).await.unwrap();

    let mut peers = Vec::new();
    for _ in 0..6 {
        let n = Node::bind_with(lo, rng.node_id(), tuning).await.unwrap();
        n.add_contact(boot.contact()).await.unwrap();
        timeout(T, n.bootstrap()).await.unwrap().unwrap();
        peers.push(n);
    }
    let server = &peers[0];
    let client = &peers[1];
    client.set_firewall(Firewall::Consistent).await.unwrap();
    server.set_firewall(Firewall::Random).await.unwrap();

    timeout(T, server.announce(server.id()))
        .await
        .unwrap()
        .unwrap();
    let server_id = server.id();
    let server_handle = server.clone();
    let incoming = tokio::spawn(async move { server_handle.next_incoming().await });

    let conn = timeout(T, client.connect(server_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.outcome, ConnectOutcome::Punched);
    let client_chan = conn.channel.expect("birthday punch should yield a channel");
    let server_chan = timeout(T, incoming)
        .await
        .unwrap()
        .unwrap()
        .expect("server should receive a punched channel");

    client_chan.send(b"punch").await.unwrap();
    let mut buf = [0u8; 32];
    let n = timeout(T, server_chan.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"punch");
}

#[tokio::test]
async fn bind_with_rejects_an_invalid_birthday_range() {
    // A bad range must be rejected at construction, not panic the node task when
    // a Punched connect later reaches the spray/open primitives.
    let tuning = PunchTuning {
        config: PunchConfig::default(),
        birthday: BirthdayParams {
            range: (30_000, 20_000), // start >= end
            sockets: 256,
            probes: 1750,
        },
        port_mapping: false,
    };
    let err = match Node::bind_with(LO.parse().unwrap(), Rng::new(1).node_id(), tuning).await {
        Ok(_) => panic!("an invalid range must be rejected"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}
