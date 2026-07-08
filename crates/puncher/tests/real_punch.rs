//! Hole punching over real `tokio` UDP sockets on loopback.
//!
//! The direct case is fully faithful (no NAT changes a direct dial). The
//! birthday case reproduces a symmetric NAT's essential property on one host:
//! the random side binds many sockets to unpredictable ports and never sends
//! first, so the spraying side can't observe them and must find one by chance —
//! a real port-collision search over real sockets, governed by the same
//! birthday math the `swarm` model verifies.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use puncher::{accept, connect_to, open_birthday_sockets, spray, Config, Established};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(LO, port)
}

/// After a punch, application bytes flow *both* ways over the punched path.
async fn assert_bidirectional(a: &Established, b: &Established) {
    send_and_receive(a, b, b"ping").await;
    send_and_receive(b, a, b"pong").await;
}

/// `from` sends `payload` to the peer it punched to (`from.peer`, i.e. `to`'s
/// address); `to` receives it, skipping any leftover handshake control bytes.
async fn send_and_receive(from: &Established, to: &Established, payload: &[u8]) {
    use puncher::{ACK, PROBE};
    from.socket.send_to(payload, from.peer).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, src) = timeout(Duration::from_secs(1), async {
        loop {
            let (n, src) = to.socket.recv_from(&mut buf).await.unwrap();
            if !(n == 1 && (buf[0] == PROBE || buf[0] == ACK)) {
                break (n, src);
            }
        }
    })
    .await
    .expect("data should arrive over the punched path");
    assert_eq!(&buf[..n], payload);
    assert_eq!(src.port(), from.socket.local_addr().unwrap().port());
}

#[tokio::test]
async fn direct_simultaneous_open() {
    let sa = UdpSocket::bind(addr(0)).await.unwrap();
    let sb = UdpSocket::bind(addr(0)).await.unwrap();
    let aa = sa.local_addr().unwrap();
    let ba = sb.local_addr().unwrap();
    let cfg = Config::default();

    // Both sides dial each other simultaneously.
    let (ra, rb) = tokio::join!(connect_to(sa, ba, &cfg), connect_to(sb, aa, &cfg));
    let a = ra.unwrap().expect("A should connect");
    let b = rb.unwrap().expect("B should connect");
    assert_eq!(a.peer, ba);
    assert_eq!(b.peer, aa);
    assert_bidirectional(&a, &b).await;
}

#[tokio::test]
async fn dial_a_reachable_peer() {
    let server = UdpSocket::bind(addr(0)).await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = UdpSocket::bind(addr(0)).await.unwrap();
    let cfg = Config::default();

    // The reachable server listens; the client dials it.
    let (rs, rc) = tokio::join!(accept(server, &cfg), connect_to(client, server_addr, &cfg));
    let s = rs.unwrap().expect("server should accept");
    let c = rc.unwrap().expect("client should connect");
    assert_eq!(c.peer, server_addr);
    assert_bidirectional(&c, &s).await;
}

#[tokio::test]
async fn accept_ignores_spoofed_ack() {
    // The reachable side never leads with a PROBE, so an ACK reaching it has no
    // honest origin. A lone `[ACK]` byte must NOT establish a channel — otherwise
    // any host could spoof or race an inbound channel with a single datagram.
    // Only a PROBE (the dialer's lead) may establish; that path is covered by
    // `dial_a_reachable_peer`.
    let server = UdpSocket::bind(addr(0)).await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let cfg = Config {
        overall: Duration::from_millis(300),
        probe_interval: Duration::from_millis(50),
    };

    // Queue a spoofed ACK before accept even starts reading; loopback buffers it,
    // so accept is guaranteed to see (and reject) it rather than never observe it.
    let attacker = UdpSocket::bind(addr(0)).await.unwrap();
    attacker.send_to(&[puncher::ACK], server_addr).await.unwrap();

    let outcome = accept(server, &cfg).await.unwrap();
    assert!(
        outcome.is_none(),
        "a lone ACK must not establish an inbound channel"
    );
}

#[tokio::test]
async fn birthday_punch_over_real_sockets() {
    // Random side: 256 sockets at unpredictable ports in a range chosen below
    // both common OS ephemeral ranges (Linux 32768+, macOS 49152+), so parallel
    // tests' ephemeral sockets don't land in it. spray also skips its own port
    // and only accepts a control reply from the target host, so a stray hit on
    // an unrelated socket can't establish. The collision is real UDP.
    let range = (20_000u16, 30_000u16);
    let cfg = Config::fast();

    let random = open_birthday_sockets(LO, LO, range, 256, 0xB1_2345, &cfg);
    let consistent = spray(addr(0), LO, range, 5_000, 0x5B_9876, &cfg);

    let (rr, rc) = tokio::join!(random, consistent);
    let r = rr
        .unwrap()
        .expect("random side should receive a sprayed probe");
    let c = rc.unwrap().expect("spraying side should land a probe");
    // The sprayed hit and the receiving socket are the same port.
    assert_eq!(c.peer.port(), r.socket.local_addr().unwrap().port());
    assert_bidirectional(&c, &r).await;
}
