//! Deterministic network tests execute the production nomination transitions.
use super::*;
use std::collections::{HashMap, VecDeque};
use swarm::natbox::{NatBox, SocketId};
use swarm::Firewall;

struct NetworkEdge {
    inner: NatBox,
    socket: SocketId,
    outer: Option<NatBox>,
    outer_sockets: HashMap<u16, SocketId>,
}
impl NetworkEdge {
    fn new(kind: Firewall, host: &str, double: bool) -> Self {
        let mut inner = NatBox::new(kind, host.parse().unwrap());
        let socket = inner.open_socket();
        Self {
            inner,
            socket,
            outer: double.then(|| NatBox::new(kind, host.parse().unwrap())),
            outer_sockets: HashMap::new(),
        }
    }
    fn send(&mut self, to: SocketAddr) -> SocketAddr {
        let inner = self.inner.send(self.socket, to);
        match &mut self.outer {
            None => inner,
            Some(outer) => {
                let socket = *self
                    .outer_sockets
                    .entry(inner.port())
                    .or_insert_with(|| outer.open_socket());
                outer.send(socket, to)
            }
        }
    }
    fn receive(&self, to: SocketAddr, from: SocketAddr) -> bool {
        if to.ip() != self.inner.host() {
            return false;
        }
        let port = match &self.outer {
            None => to.port(),
            Some(outer) => {
                let Some(socket) = outer.recv(to.port(), from) else {
                    return false;
                };
                let Some((&port, _)) = self.outer_sockets.iter().find(|(_, id)| **id == socket)
                else {
                    return false;
                };
                port
            }
        };
        self.inner.recv(port, from) == Some(self.socket)
    }
}

fn run(a: Firewall, b: Firewall, double: bool, ipv6: bool, loss: bool) -> bool {
    let hosts = if ipv6 {
        ["2001:db8::1", "2001:db8::2"]
    } else {
        ["192.0.2.1", "192.0.2.2"]
    };
    let reflector: SocketAddr = if ipv6 {
        "[2001:db8::3]:9000"
    } else {
        "192.0.2.3:9000"
    }
    .parse()
    .unwrap();
    let mut edges = [
        NetworkEdge::new(a, hosts[0], double),
        NetworkEdge::new(b, hosts[1], double),
    ];
    let candidates = [edges[0].send(reflector), edges[1].send(reflector)];
    let mut states = [
        Nomination::new(&[candidates[1]], [7; 32], true),
        Nomination::new(&[candidates[0]], [7; 32], false),
    ];
    let mut queue = VecDeque::new();
    let mut packets = 0;
    let mut dropped_confirm = false;
    for round in 0..100 {
        for side in 0..2 {
            if states[side].established.is_none() {
                for (to, bytes) in states[side].probes() {
                    let from = edges[side].send(to);
                    queue.push_back((1 - side, to, from, bytes));
                }
            }
        }
        // Reverse alternate rounds to exercise asymmetric packet arrival order.
        for _ in 0..128 {
            let next = if round % 2 == 0 {
                queue.pop_front()
            } else {
                queue.pop_back()
            };
            let Some((side, to, from, bytes)) = next else {
                break;
            };
            packets += 1;
            if loss && (packets % 5 == 0 || (bytes[36] == CONFIRM && !dropped_confirm)) {
                dropped_confirm |= bytes[36] == CONFIRM;
                continue;
            }
            if edges[side].receive(to, from) {
                if let Some(reply) = states[side].receive(from, &bytes) {
                    let source = edges[side].send(from);
                    queue.push_back((1 - side, from, source, reply));
                }
            }
        }
        assert!(queue.len() < 128, "control exchange must remain bounded");
        if let (Some(to_b), Some(to_a)) = (states[0].established, states[1].established) {
            // Check the resulting data path, not just the handshake flags.
            let from_a = edges[0].send(to_b);
            let from_b = edges[1].send(to_a);
            assert!(edges[1].receive(to_b, from_a));
            assert!(edges[0].receive(to_a, from_b));
            assert_eq!(from_a, to_a);
            assert_eq!(from_b, to_b);
            return true;
        }
    }
    false
}

#[test]
fn nat_matrix_with_loss_reordering_double_nat_and_ipv6() {
    for a in [Firewall::Open, Firewall::Consistent, Firewall::Random] {
        for b in [Firewall::Open, Firewall::Consistent, Firewall::Random] {
            for double in [false, true] {
                for ipv6 in [false, true] {
                    for loss in [false, true] {
                        let expected = a == Firewall::Open
                            || b == Firewall::Open
                            || (a == Firewall::Consistent && b == Firewall::Consistent);
                        assert_eq!(
                            run(a, b, double, ipv6, loss),
                            expected,
                            "{a:?}/{b:?}, double={double}, ipv6={ipv6}, loss={loss}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn source_learning_requires_session_and_advertised_ip_and_pins_port() {
    let advertised: SocketAddr = "192.0.2.1:1000".parse().unwrap();
    let learned: SocketAddr = "192.0.2.1:2000".parse().unwrap();
    let stranger: SocketAddr = "192.0.2.2:2000".parse().unwrap();
    for initiator in [false, true] {
        let mut state = Nomination::new(&[advertised], [7; 32], initiator);
        assert!(state.receive(stranger, &packet([7; 32], PROBE)).is_none());
        assert!(state.receive(learned, &packet([8; 32], PROBE)).is_none());
        assert_eq!(state.selected, None);
        let control = if initiator { PROBE } else { SELECT };
        assert!(state.receive(learned, &packet([7; 32], control)).is_some());
        assert_eq!(state.selected, Some(learned));
        assert!(state
            .receive(advertised, &packet([7; 32], control))
            .is_none());
        assert_eq!(state.selected, Some(learned));
    }
}

#[test]
fn birthday_search_crosses_restrictive_symmetric_nat_in_both_roles() {
    // Use a full 64K port space: no artificially small collision window.
    for initiator_random in [false, true] {
        let mut successes = 0;
        for seed in 0..32u8 {
            let session = [seed; 32];
            let mut stable = NatBox::new(Firewall::Consistent, "192.0.2.1".parse().unwrap());
            let mut random = NatBox::new(Firewall::Random, "192.0.2.2".parse().unwrap());
            let reflector = "192.0.2.3:9000".parse().unwrap();
            let stable_socket = stable.open_socket();
            let stable_candidate = stable.send(stable_socket, reflector);
            let sockets: Vec<_> = (0..64).map(|_| random.open_socket()).collect();
            let random_candidate = random.send(sockets[0], reflector);
            let mut stable_state = Nomination::new(&[random_candidate], session, !initiator_random);
            let mut random_state = Nomination::new(&[stable_candidate], session, initiator_random);
            let mut selected_socket = None;
            // This outbound step is essential: merely binding does not open a NAT.
            for socket in sockets {
                random.send(socket, stable_candidate);
            }
            let mut search = PortSearch::new(session);
            for _ in 0..256 {
                for target in search.batch(&[random_candidate]) {
                    let from = stable.send(stable_socket, target);
                    let Some(socket) = random.recv(target.port(), from) else {
                        continue;
                    };
                    if selected_socket.is_some_and(|chosen| chosen != socket) {
                        continue;
                    }
                    let mut next = random_state.receive(from, &packet(session, PROBE));
                    let mut side_random = true;
                    for _ in 0..8 {
                        let Some(bytes) = next else {
                            break;
                        };
                        if side_random {
                            let from = random.send(socket, stable_candidate);
                            assert_eq!(
                                stable.recv(stable_candidate.port(), from),
                                Some(stable_socket)
                            );
                            next = stable_state.receive(from, &bytes);
                        } else {
                            let from = stable.send(stable_socket, target);
                            assert_eq!(random.recv(target.port(), from), Some(socket));
                            next = random_state.receive(from, &bytes);
                        }
                        if random_state.selected.is_some() {
                            selected_socket = Some(socket);
                        }
                        side_random = !side_random;
                    }
                    if stable_state.established.is_some() && random_state.established.is_some() {
                        break;
                    }
                }
                if stable_state.established.is_some() && random_state.established.is_some() {
                    successes += 1;
                    break;
                }
            }
        }
        assert!(
            successes >= 30,
            "only {successes}/32 seeded attempts succeeded"
        );
    }
}

#[test]
fn search_budget_and_strategy_selection_are_bounded() {
    let peers = [
        "192.0.2.1:1".parse().unwrap(),
        "192.0.2.1:2".parse().unwrap(),
        "[2001:db8::1]:3".parse().unwrap(),
    ];
    let mut search = PortSearch::new([5; 32]);
    let mut count = 0;
    for _ in 0..1000 {
        let batch = search.batch(&peers);
        assert!(batch.len() <= 64);
        assert!(batch
            .iter()
            .all(|address| address.port() >= 1024
                && peers.iter().any(|peer| peer.ip() == address.ip())));
        count += batch.len();
    }
    assert_eq!(count, 8192);
    assert_eq!(nat_strategy(true, false), NatStrategy::OpenMappings);
    assert_eq!(nat_strategy(false, true), NatStrategy::SearchPorts);
    assert_eq!(nat_strategy(true, true), NatStrategy::Direct);
    assert_eq!(nat_strategy(false, false), NatStrategy::Direct);
}

#[tokio::test]
async fn multi_socket_udp_nomination_agrees_in_both_dialing_directions() {
    for random_dials in [false, true] {
        let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let left_address = left.local_addr().unwrap();
        let right_address = right.local_addr().unwrap();
        let config = Config {
            overall: std::time::Duration::from_secs(2),
            probe_interval: std::time::Duration::from_millis(10),
        };
        let session = [6; 32];
        let peers_left = [right_address];
        let peers_right = [left_address];
        let (left, right) = tokio::join!(
            rendezvous_with_strategy(
                left,
                &peers_left,
                &config,
                session,
                random_dials,
                NatStrategy::OpenMappings
            ),
            rendezvous_with_strategy(
                right,
                &peers_right,
                &config,
                session,
                !random_dials,
                NatStrategy::SearchPorts
            ),
        );
        let left = left.unwrap().unwrap();
        let right = right.unwrap().unwrap();
        assert_eq!(left.peer, right.socket.local_addr().unwrap());
        assert_eq!(right.peer, left.socket.local_addr().unwrap());
    }
}
