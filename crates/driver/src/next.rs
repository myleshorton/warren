//! Explicit UDP driver for the replacement DHT. This does not change `driver::Node`.
mod direct;
mod managed_value;
mod mapping;
pub use managed_value::{ManagedValue, ValuePublicationConfig, ValuePublicationStatus};
pub use portmap::Gateway as MappingGateway;
mod state;
use crypto::Keypair;
use dht_next::{Action, Contact, Dht, Event, NodeId, Record, RoutingPolicy, Time};
pub use direct::{DirectChannel, DirectSocket};
use puncher::bind_udp as bind_socket;
pub use state::BootstrapState;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// DHT events and terminal driver status. Slow subscribers receive `Lagged` from
/// the bounded broadcast channel; events are never silently dropped for them.
#[derive(Clone, Debug)]
pub enum Notice {
    Dht(Box<Event>),
    IoError(io::ErrorKind),
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Core(dht_next::Error),
    Closed,
    TimedOut,
    NoPeers,
    EventsLagged(u64),
    ConflictingValues,
    NetworkChanged,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(e) => write!(f, "DHT operation failed: {e:?}"),
            Self::NetworkChanged => {
                f.write_str("local network changed; retry with a fresh session")
            }
            Self::Closed => f.write_str("DHT driver is closed"),
            Self::TimedOut => f.write_str("DHT operation timed out"),
            Self::NoPeers => f.write_str("no reachable DHT replicas"),
            Self::EventsLagged(n) => write!(f, "DHT subscriber missed {n} events"),
            Self::ConflictingValues => {
                f.write_str("newer signed value or conflicting values at the same sequence")
            }
        }
    }
}
impl std::error::Error for Error {}

/// Replica acknowledgements are remote claims, not proof of durable storage.
#[derive(Debug)]
pub struct StoreResult {
    pub key: NodeId,
    pub acknowledged: Vec<Contact>,
    pub rejected: Vec<Contact>,
    pub timed_out: Vec<Contact>,
}
/// The highest signed sequence observed among the responding replicas.
#[derive(Debug)]
pub struct FetchResult {
    pub value: Option<dht_next::Value>,
    pub responses: usize,
    pub attempted: usize,
    pub timed_out: bool,
}

type Operation = Box<dyn FnOnce(&mut Dht, Time) -> Vec<Action> + Send>;
enum Command {
    Apply(Operation),
    Stop(oneshot::Sender<()>),
    #[cfg(test)]
    ReceiveError(io::ErrorKind, oneshot::Sender<()>),
    Rebind(
        SocketAddr,
        Vec<Contact>,
        oneshot::Sender<io::Result<SocketAddr>>,
    ),
}
/// Current bind address and monotonically increasing local network generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkState {
    pub address: SocketAddr,
    pub generation: u64,
}
struct Inner {
    commands: mpsc::Sender<Command>,
    events: broadcast::Sender<Notice>,
    network: watch::Sender<NetworkState>,
    id: NodeId,
    inbound: Arc<AtomicU64>,
    managed_values: Arc<std::sync::Mutex<std::collections::BTreeSet<NodeId>>>,
    task: JoinHandle<()>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A shared handle to one socket and one DHT actor. Drop the final handle or call
/// `shutdown` to release the socket. Subscribe before starting an operation.
#[derive(Clone)]
pub struct Node {
    inner: Arc<Inner>,
}
impl Node {
    pub async fn bind(addr: SocketAddr, identity: Keypair, server: bool) -> io::Result<Self> {
        Self::bind_with_policy(addr, identity, server, RoutingPolicy::Diverse).await
    }
    pub async fn bind_with_policy(
        addr: SocketAddr,
        identity: Keypair,
        server: bool,
        policy: RoutingPolicy,
    ) -> io::Result<Self> {
        let socket = bind_socket(addr)?;
        let addr = socket.local_addr()?;
        let core = Dht::with_routing_policy(identity, Keypair::generate().seed(), server, policy);
        let id = core.id();
        let (commands, receiver) = mpsc::channel(128);
        let (events, _) = broadcast::channel(256);
        let (network, _) = watch::channel(NetworkState {
            address: addr,
            generation: 0,
        });
        let inbound = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(run(
            socket,
            core,
            receiver,
            events.clone(),
            network.clone(),
            inbound.clone(),
        ));
        Ok(Self {
            inner: Arc::new(Inner {
                commands,
                events,
                network,
                id,
                inbound,
                managed_values: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new())),
                task,
            }),
        })
    }
    pub fn id(&self) -> NodeId {
        self.inner.id
    }
    pub fn inbound_datagrams(&self) -> u64 {
        self.inner.inbound.load(Ordering::Relaxed)
    }
    pub async fn register(&self, coordinator: Contact, topic: NodeId) -> Result<(), Error> {
        self.apply(move |d, now| d.register(coordinator, topic, now).map(|a| ((), a)))
            .await
    }
    pub async fn cancel_lookup(&self, query: u64) -> Result<(), Error> {
        self.apply(move |d, _| {
            d.cancel_lookup(query);
            Ok(((), vec![]))
        })
        .await
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.network.borrow().address
    }
    pub fn network(&self) -> watch::Receiver<NetworkState> {
        self.inner.network.subscribe()
    }
    /// Refresh network state and restart active publications. The exact current
    /// address reuses its socket; other addresses bind before replacing it, so a
    /// failure leaves the old socket intact. Port zero requests a fresh port.
    pub async fn rebind(&self, address: SocketAddr, seeds: &[Contact]) -> io::Result<SocketAddr> {
        if seeds.len() > 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at most eight recovery seeds",
            ));
        }
        let (send, receive) = oneshot::channel();
        self.inner
            .commands
            .send(Command::Rebind(address, seeds.to_vec(), send))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DHT stopped"))?;
        receive
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DHT stopped"))?
    }
    pub fn subscribe(&self) -> broadcast::Receiver<Notice> {
        self.inner.events.subscribe()
    }

    async fn apply<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Dht, Time) -> Result<(T, Vec<Action>), dht_next::Error>
            + Send
            + 'static,
    ) -> Result<T, Error> {
        let (sender, receiver) = oneshot::channel();
        self.inner
            .commands
            .send(Command::Apply(Box::new(move |core, now| {
                // A canceled caller whose command has not started causes no effects.
                if sender.is_closed() {
                    return vec![];
                }
                match operation(core, now) {
                    Ok((value, actions)) => {
                        let _ = sender.send(Ok(value));
                        actions
                    }
                    Err(error) => {
                        let _ = sender.send(Err(Error::Core(error)));
                        vec![]
                    }
                }
            })))
            .await
            .map_err(|_| Error::Closed)?;
        receiver.await.map_err(|_| Error::Closed)?
    }
    pub async fn probe(&self, peer: Contact) -> Result<(), Error> {
        self.apply(move |d, now| d.probe(peer, now).map(|a| ((), a)))
            .await
    }
    pub async fn bootstrap(&self, seeds: &[Contact]) -> Result<u64, Error> {
        let seeds: Vec<_> = seeds
            .iter()
            .take(dht_next::MAX_CANDIDATES)
            .copied()
            .collect();
        self.apply(move |d, now| d.bootstrap(&seeds, now)).await
    }
    pub async fn lookup(&self, topic: NodeId, seeds: &[Contact]) -> Result<u64, Error> {
        let seeds: Vec<_> = seeds
            .iter()
            .take(dht_next::MAX_CANDIDATES)
            .copied()
            .collect();
        self.apply(move |d, now| d.lookup(topic, &seeds, now)).await
    }
    pub async fn publish(&self, topic: NodeId, seeds: &[Contact]) -> Result<(), Error> {
        if seeds.len() > 8 {
            return Err(Error::Core(dht_next::Error::Invalid));
        }
        let seeds = seeds.to_vec();
        self.apply(move |d, now| d.publish(topic, &seeds, now).map(|a| ((), a)))
            .await
    }
    pub async fn rotate_signaling_key(&self) -> Result<(), Error> {
        self.apply(|d, now| d.rotate_signaling_key(now).map(|()| ((), vec![])))
            .await
    }
    pub async fn unpublish(&self, topic: NodeId) -> Result<bool, Error> {
        self.apply(move |d, _| Ok((d.unpublish(topic), vec![])))
            .await
    }
    pub async fn put_value(
        &self,
        coordinator: Contact,
        value: dht_next::Value,
        cas: Option<u64>,
    ) -> Result<[u8; 32], Error> {
        let now = Time::new(
            0,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        if !value.verify(now) {
            return Err(Error::Core(dht_next::Error::Invalid));
        }
        self.apply(move |d, now| d.put_value(coordinator, value, cas, now))
            .await
    }
    pub async fn get_value(&self, coordinator: Contact, key: NodeId) -> Result<[u8; 32], Error> {
        self.apply(move |d, now| d.get_value(coordinator, key, now))
            .await
    }
    async fn replicas(&self, key: NodeId, seeds: &[Contact]) -> Result<Vec<Contact>, Error> {
        let mut events = self.subscribe();
        let query = self.lookup(key, seeds).await?;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if let Event::LookupDone {
                    query: id, closest, ..
                } = next_event(&mut events).await?
                {
                    if id == query {
                        let mut candidates = closest;
                        let mut peers = Vec::new();
                        while peers.len() < 3 {
                            let Some(peer) = dht_next::select_diverse_contact(&candidates, &peers)
                            else {
                                break;
                            };
                            candidates.retain(|c| *c != peer);
                            peers.push(peer);
                        }
                        return if peers.is_empty() {
                            Err(Error::NoPeers)
                        } else {
                            Ok(peers)
                        };
                    }
                }
            }
        })
        .await
        .map_err(|_| Error::TimedOut)?
    }
    /// Locate the key and prefer three responsive replicas on different networks. CAS is
    /// evaluated independently by each replica; inspect partial acknowledgements.
    pub async fn store(
        &self,
        value: dht_next::Value,
        cas: Option<u64>,
        seeds: &[Contact],
    ) -> Result<StoreResult, Error> {
        let now = Time::new(
            0,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        if !value.verify(now) || (cas.is_some() && matches!(value, dht_next::Value::Immutable(_))) {
            return Err(Error::Core(dht_next::Error::Invalid));
        }
        let key = value.key();
        let replicas = self.replicas(key, seeds).await?;
        self.store_replicas(value, cas, replicas).await
    }

    async fn store_replicas(
        &self,
        value: dht_next::Value,
        cas: Option<u64>,
        replicas: Vec<Contact>,
    ) -> Result<StoreResult, Error> {
        let key = value.key();
        let mut events = self.subscribe();
        let mut pending = std::collections::BTreeMap::new();
        let mut result = StoreResult {
            key,
            acknowledged: vec![],
            rejected: vec![],
            timed_out: vec![],
        };
        for peer in replicas {
            match self.put_value(peer, value.clone(), cas).await {
                Ok(request) => {
                    pending.insert(request, peer);
                }
                Err(_) => result.rejected.push(peer),
            }
        }
        let completion = tokio::time::timeout(Duration::from_secs(10), async {
            while !pending.is_empty() {
                match next_event(&mut events).await? {
                    Event::ValueStored {
                        request, stored, ..
                    } => {
                        if let Some(peer) = pending.remove(&request) {
                            if stored {
                                result.acknowledged.push(peer);
                            } else {
                                result.rejected.push(peer);
                            }
                        }
                    }
                    Event::RpcTimedOut(request) => {
                        if let Some(peer) = pending.remove(&request) {
                            result.timed_out.push(peer);
                        }
                    }
                    _ => {}
                }
            }
            Ok::<(), Error>(())
        })
        .await;
        // An event-channel failure leaves the issued writes indeterminate.
        let _ = completion;
        result.timed_out.extend(pending.into_values());
        Ok(result)
    }
    /// Read during iterative lookup. Immutable content completes on its first
    /// verified match; mutable reads compare the responding traversal frontier.
    /// Coverage and timeout fields do not establish global absence or freshness.
    pub async fn fetch(&self, key: NodeId, seeds: &[Contact]) -> Result<FetchResult, Error> {
        let seeds: Vec<_> = seeds
            .iter()
            .take(dht_next::MAX_CANDIDATES)
            .copied()
            .collect();
        let mut events = self.subscribe();
        let query = self
            .apply(move |d, now| d.lookup_value(key, &seeds, now))
            .await?;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if let Event::ValueLookupDone {
                    query: id, result, ..
                } = next_event(&mut events).await?
                {
                    if id != query {
                        continue;
                    }
                    if result.timed_out && result.responses == 0 {
                        return Err(Error::TimedOut);
                    }
                    if result.attempted == 0 {
                        return Err(Error::NoPeers);
                    }
                    if result.responses == 0 {
                        return Err(Error::TimedOut);
                    }
                    if result.conflicting {
                        return Err(Error::ConflictingValues);
                    }
                    return Ok(FetchResult {
                        value: result.value,
                        responses: result.responses,
                        attempted: result.attempted,
                        timed_out: result.timed_out,
                    });
                }
            }
        })
        .await
        .map_err(|_| Error::TimedOut)?
    }

    pub async fn providers_page(
        &self,
        coordinator: Contact,
        topic: NodeId,
        after: Option<NodeId>,
    ) -> Result<[u8; 32], Error> {
        self.apply(move |d, now| d.providers_page(coordinator, topic, after, now))
            .await
    }
    pub async fn signal_via(
        &self,
        records: &[Record],
        payload: Vec<u8>,
    ) -> Result<[u8; 32], Error> {
        if records.len() > dht_next::MAX_COORDINATORS
            || payload.len() > dht_next::protocol::MAX_SIGNAL
        {
            return Err(Error::Core(dht_next::Error::Invalid));
        }
        let records = records.to_vec();
        self.apply(move |d, now| d.signal_via(&records, payload, now))
            .await
    }
    pub async fn answer(&self, session: [u8; 32], payload: Vec<u8>) -> Result<(), Error> {
        if payload.len() > dht_next::protocol::MAX_SIGNAL {
            return Err(Error::Core(dht_next::Error::Invalid));
        }
        self.apply(move |d, now| d.answer(session, payload, now).map(|a| ((), a)))
            .await
    }
    /// Snapshot bounded live contact hints for storage by the application.
    pub async fn bootstrap_state(&self) -> Result<BootstrapState, Error> {
        self.apply(|d, now| Ok((BootstrapState::new(d.bootstrap_contacts(now)), vec![])))
            .await
    }
    /// Revalidate stored hints through a normal authenticated bootstrap lookup.
    /// Subscribe first and await the returned query's `LookupDone` event.
    pub async fn restore_bootstrap(&self, state: &BootstrapState) -> Result<u64, Error> {
        self.bootstrap(state.contacts()).await
    }
    pub async fn routing_len(&self) -> Result<usize, Error> {
        self.apply(|d, _| Ok((d.routing_len(), vec![]))).await
    }
    pub async fn shutdown(&self) -> Result<(), Error> {
        let (sender, receiver) = oneshot::channel();
        self.inner
            .commands
            .send(Command::Stop(sender))
            .await
            .map_err(|_| Error::Closed)?;
        receiver.await.map_err(|_| Error::Closed)
    }
}
async fn next_event(events: &mut broadcast::Receiver<Notice>) -> Result<Event, Error> {
    loop {
        match events.recv().await {
            Ok(Notice::Dht(event)) if matches!(*event, Event::NetworkChanged(_)) => {
                return Err(Error::NetworkChanged)
            }
            Ok(Notice::Dht(event)) => return Ok(*event),
            Ok(Notice::IoError(_)) => {}
            Ok(Notice::Stopped) | Err(broadcast::error::RecvError::Closed) => {
                return Err(Error::Closed)
            }
            Err(broadcast::error::RecvError::Lagged(n)) => return Err(Error::EventsLagged(n)),
        }
    }
}
fn time(start: Instant) -> Time {
    Time::new(
        start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

async fn run(
    mut socket: UdpSocket,
    mut core: Dht,
    mut commands: mpsc::Receiver<Command>,
    events: broadcast::Sender<Notice>,
    network: watch::Sender<NetworkState>,
    inbound: Arc<AtomicU64>,
) {
    let mut dual_stack = socket.local_addr().is_ok_and(|addr| addr.is_ipv6());
    let mut receive_enabled = true;
    let start = Instant::now();
    let mut buffer = [0; dht_next::protocol::MAX_PACKET + 1];
    let mut actions = core.maintain_routing(time(start));
    let mut stopped = None;
    'actor: loop {
        for action in actions {
            match action {
                Action::Send { to, bytes } => {
                    let destination = match (dual_stack, to) {
                        (true, SocketAddr::V4(v4)) => {
                            SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
                        }
                        _ => to,
                    };
                    if let Err(error) = socket.send_to(&bytes, destination).await {
                        let _ = events.send(Notice::IoError(error.kind()));
                    }
                }
                Action::Event(event) => {
                    let _ = events.send(Notice::Dht(event));
                }
            }
        }
        let deadline = core.poll_timeout();
        let timer = async {
            match deadline {
                Some(at) => {
                    tokio::time::sleep(Duration::from_millis(
                        at.saturating_sub(time(start).monotonic_ms).min(86_400_000),
                    ))
                    .await
                }
                None => std::future::pending().await,
            }
        };
        actions = tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Apply(operation)) => operation(&mut core, time(start)),
                Some(Command::Rebind(address, seeds, reply)) => {
                    if reply.is_closed() { vec![] } else {
                        let replacement = if socket.local_addr().ok() == Some(address) {
                            Ok(None)
                        } else { bind_socket(address).map(Some) };
                        match replacement {
                            Err(error) => { let _ = reply.send(Err(error)); vec![] }
                            Ok(replacement) => match core.network_changed(Keypair::generate().seed(), &seeds, time(start)) {
                                Ok(actions) => {
                                    if let Some(replacement) = replacement { socket = replacement; }
                                    let address = socket.local_addr().expect("bound UDP socket");
                                    receive_enabled = true;
                                    dual_stack = address.is_ipv6();
                                    network.send_modify(|state| { state.address = address; state.generation += 1; });
                                    let _ = reply.send(Ok(address));
                                    actions
                                }
                                Err(error) => { let _ = reply.send(Err(io::Error::other(format!("{error:?}")))); vec![] }
                            }
                        }
                    }
                }
                #[cfg(test)]
                Some(Command::ReceiveError(kind, reply)) => {
                    receive_enabled = transient_receive_error(kind);
                    let _ = reply.send(());
                    vec![]
                }
                Some(Command::Stop(reply)) => { stopped = Some(reply); break 'actor; }
                None => break 'actor,
            },
            packet = socket.recv_from(&mut buffer), if receive_enabled => match packet {
                Ok((len, from)) => {
                    inbound.fetch_add(1, Ordering::Relaxed);
                    let from = match from {
                        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().map_or(from, |v4| SocketAddr::new(v4.into(), v6.port())),
                        _ => from,
                    };
                    core.receive(from, &buffer[..len], time(start))
                },
                Err(error) => {
                    let _ = events.send(Notice::IoError(error.kind()));
                    // Keep accepting recovery commands without spinning on a
                    // failed interface. Rebinding enables receives again.
                    receive_enabled = transient_receive_error(error.kind());
                    vec![]
                }
            },
            _ = timer => core.tick(time(start)),
        };
    }
    drop(socket);
    let _ = events.send(Notice::Stopped);
    if let Some(reply) = stopped {
        let _ = reply.send(());
    }
}

fn transient_receive_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[tokio::test]
    async fn transient_receive_errors_and_same_port_refresh_preserve_service() {
        let a = Node::bind(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::from_seed(&[231; 32]),
            false,
        )
        .await
        .unwrap();
        let b = Node::bind(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::from_seed(&[232; 32]),
            true,
        )
        .await
        .unwrap();
        let contact = Contact::new(b.id(), b.local_addr());
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
        ] {
            let (tx, rx) = oneshot::channel();
            a.inner
                .commands
                .send(Command::ReceiveError(kind, tx))
                .await
                .unwrap();
            rx.await.unwrap();
            let mut events = a.subscribe();
            a.probe(contact).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if matches!(next_event(&mut events).await.unwrap(), Event::Ready(_)) {
                        break;
                    }
                }
            })
            .await
            .unwrap();
        }
        let before = *a.network().borrow();
        assert_eq!(
            a.rebind(before.address, &[contact]).await.unwrap(),
            before.address
        );
        assert_eq!(a.network().borrow().generation, before.generation + 1);
        let mut events = a.subscribe();
        a.probe(contact).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(next_event(&mut events).await.unwrap(), Event::Ready(_)) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn partial_store_reports_issued_replicas_after_capacity_failure() {
        let a = Node::bind(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::from_seed(&[233; 32]),
            false,
        )
        .await
        .unwrap();
        let b = Node::bind(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::from_seed(&[234; 32]),
            true,
        )
        .await
        .unwrap();
        let holder = Contact::new(b.id(), b.local_addr());
        let dead = Contact::new(
            NodeId::from_bytes([241; 32]),
            "127.0.0.1:9".parse().unwrap(),
        );
        a.apply(move |core, now| {
            let mut actions = vec![];
            for _ in 0..dht_next::MAX_PENDING - 1 {
                actions.extend(core.probe(dead, now)?);
            }
            Ok(((), actions))
        })
        .await
        .unwrap();
        let result = a
            .store_replicas(
                dht_next::Value::Immutable(b"partial".to_vec()),
                None,
                vec![holder, holder, holder],
            )
            .await
            .unwrap();
        assert_eq!(result.acknowledged, vec![holder]);
        assert_eq!(result.rejected, vec![holder, holder]);
        assert!(result.timed_out.is_empty());
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }
}
