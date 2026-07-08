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

/// After a punch, the two ends can actually exchange application bytes. `a`
/// sends to the peer it punched to (`a.peer`, which is `b`'s address).
async fn assert_bidirectional(a: &Established, b: &Established) {
    use puncher::{ACK, PROBE};
    a.socket.send_to(b"ping", a.peer).await.unwrap();
    let mut buf = [0u8; 16];
    // Skip any leftover handshake control bytes still buffered on `b`.
    let (n, from) = timeout(Duration::from_secs(1), async {
        loop {
            let (n, from) = b.socket.recv_from(&mut buf).await.unwrap();
            if !(n == 1 && (buf[0] == PROBE || buf[0] == ACK)) {
                break (n, from);
            }
        }
    })
    .await
    .expect("data should arrive over the punched path");
    assert_eq!(&buf[..n], b"ping");
    assert_eq!(from.port(), a.socket.local_addr().unwrap().port());
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
async fn birthday_punch_over_real_sockets() {
    // Random side: 256 sockets at unpredictable ports in a range; the sprayer
    // never targets its own port (spray skips it), so a self-hit is impossible
    // wherever its ephemeral socket lands. Predictable side sprays the same
    // range. The collision is real UDP.
    let range = (30_000u16, 45_000u16);
    let cfg = Config::fast();

    let random = open_birthday_sockets(LO, range, 256, 0xB1_2345, &cfg);
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
