//! Explicit UDP driver for the replacement DHT. This does not change `driver::Node`.
mod direct;
mod managed_value;
mod mapping;
mod nat64;
pub use managed_value::{ManagedValue, ValuePublicationConfig, ValuePublicationStatus};
pub use nat64::route_addresses;
pub use portmap::Gateway as MappingGateway;
mod overlay;
mod state;
use crate::diagnostics::{
    io_code, Observer, Operation as DiagnosticOperation, Value as DiagnosticValue,
};
use crypto::Keypair;
use dht_next::{Action, Contact, Dht, Event, NodeId, Record, RoutingPolicy, Time};
pub use direct::{DirectChannel, DirectSocket};
pub use overlay::OverlayId;
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

pub type AddressFilter = Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;

type Operation = Box<dyn FnOnce(&mut Dht, Time) -> Vec<Action> + Send>;
enum Command {
    Apply(Operation),
    Stop(oneshot::Sender<()>),
    #[cfg(test)]
    ReceiveError(io::ErrorKind, oneshot::Sender<()>),
    #[cfg(test)]
    DelayDiscovery(oneshot::Receiver<()>),
    Rebind(
        SocketAddr,
        Vec<Contact>,
        oneshot::Sender<io::Result<SocketAddr>>,
    ),
}
struct PendingRebind {
    observation: DiagnosticOperation,
    socket: Option<UdpSocket>,
    seeds: Vec<Contact>,
    reply: oneshot::Sender<io::Result<SocketAddr>>,
    discovery: std::pin::Pin<Box<dyn std::future::Future<Output = nat64::Translation> + Send>>,
}

/// Current bind address and monotonically increasing local network generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkState {
    pub address: SocketAddr,
    pub generation: u64,
}
struct Inner {
    diagnostics: Observer,
    commands: mpsc::Sender<Command>,
    events: broadcast::Sender<Notice>,
    network: watch::Sender<NetworkState>,
    translation: watch::Sender<nat64::Translation>,
    id: NodeId,
    overlay: OverlayId,
    address_filter: AddressFilter,
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
        Self::bind_in_overlay(addr, identity, server, policy, OverlayId::Global).await
    }
    pub async fn bind_in_overlay(
        addr: SocketAddr,
        identity: Keypair,
        server: bool,
        policy: RoutingPolicy,
        overlay: OverlayId,
    ) -> io::Result<Self> {
        Self::bind_filtered(addr, identity, server, policy, overlay, Arc::new(|_| true)).await
    }
    /// Restrict DHT transport peers before any routing state is established.
    pub async fn bind_filtered(
        addr: SocketAddr,
        identity: Keypair,
        server: bool,
        policy: RoutingPolicy,
        overlay: OverlayId,
        address_filter: AddressFilter,
    ) -> io::Result<Self> {
        let socket = bind_socket(addr)?;
        let addr = socket.local_addr()?;
        let (translation, _) = watch::channel(nat64::Translation::discover(addr).await);
        let core = Dht::with_routing_policy(identity, Keypair::generate().seed(), server, policy);
        let id = core.id();
        let (commands, receiver) = mpsc::channel(128);
        let (events, _) = broadcast::channel(256);
        let (network, _) = watch::channel(NetworkState {
            address: addr,
            generation: 0,
        });
        let inbound = Arc::new(AtomicU64::new(0));
        let diagnostics = Observer::new();
        let task = tokio::spawn(run(
            socket,
            translation.clone(),
            core,
            receiver,
            ActorSignals {
                events: events.clone(),
                network: network.clone(),
                inbound: inbound.clone(),
                diagnostics: diagnostics.clone(),
            },
            (overlay, address_filter.clone()),
        ));
        Ok(Self {
            inner: Arc::new(Inner {
                diagnostics,
                commands,
                events,
                network,
                translation,
                id,
                overlay,
                address_filter,
                inbound,
                managed_values: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new())),
                task,
            }),
        })
    }
    pub fn diagnostics(&self) -> Observer {
        self.inner.diagnostics.clone()
    }

    pub fn translation_mode(&self) -> &'static str {
        self.inner.translation.borrow().mode()
    }

    pub fn id(&self) -> NodeId {
        self.inner.id
    }
    pub fn overlay(&self) -> OverlayId {
        self.inner.overlay
    }
    pub fn allows_address(&self, address: SocketAddr) -> bool {
        (self.inner.address_filter)(address)
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
    /// Prepare a data socket using this node's current network translation.
    pub async fn direct_socket(
        &self,
        reflectors: &[Contact],
        gateway: Option<&portmap::Gateway>,
    ) -> io::Result<DirectSocket> {
        self.direct_socket_for(reflectors, gateway, None).await
    }

    pub async fn direct_socket_for(
        &self,
        reflectors: &[Contact],
        gateway: Option<&portmap::Gateway>,
        parent: Option<u64>,
    ) -> io::Result<DirectSocket> {
        let mut translation = self.inner.translation.borrow().clone();
        translation.bind.set_port(0);
        DirectSocket::bind_with_translation(
            translation.bind,
            reflectors,
            gateway,
            translation,
            self.diagnostics(),
            parent,
        )
        .await
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
        let diagnostics = self.diagnostics();
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
                        let code = match error {
                            dht_next::Error::Capacity => "capacity",
                            dht_next::Error::Invalid => "invalid",
                            dht_next::Error::UnknownSession => "unknown_session",
                        };
                        diagnostics.event("dht.command", code, vec![]);
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
        let overlay = self.overlay();
        self.apply(move |d, now| {
            Ok((
                BootstrapState::in_overlay(d.bootstrap_contacts(now), overlay),
                vec![],
            ))
        })
        .await
    }
    /// Revalidate stored hints through a normal authenticated bootstrap lookup.
    /// Subscribe first and await the returned query's `LookupDone` event.
    pub async fn restore_bootstrap(&self, state: &BootstrapState) -> Result<u64, Error> {
        if state.overlay() != self.overlay() {
            return Err(Error::Core(dht_next::Error::Invalid));
        }
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

struct ActorSignals {
    events: broadcast::Sender<Notice>,
    network: watch::Sender<NetworkState>,
    inbound: Arc<AtomicU64>,
    diagnostics: Observer,
}

async fn run(
    mut socket: UdpSocket,
    mappings: watch::Sender<nat64::Translation>,
    mut core: Dht,
    mut commands: mpsc::Receiver<Command>,
    signals: ActorSignals,
    transport: (OverlayId, AddressFilter),
) {
    let (overlay, address_filter) = transport;
    let ActorSignals {
        events,
        network,
        inbound,
        diagnostics,
    } = signals;
    let mut health = tokio::time::interval(Duration::from_secs(30));
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let (mut outbound, mut send_errors, mut receive_errors) = (0u64, 0u64, 0u64);
    let mut translation = mappings.borrow().clone();
    let mut pending: Option<PendingRebind> = None;
    #[cfg(test)]
    let mut discovery_gate: Option<oneshot::Receiver<()>> = None;
    let mut receive_enabled = true;
    let start = Instant::now();
    let mut buffer = [0; dht_next::protocol::MAX_PACKET + overlay::HEADER_LEN + 1];
    let mut actions = core.maintain_routing(time(start));
    let mut stopped = None;
    'actor: loop {
        for action in actions {
            match action {
                Action::Send { to, bytes } => {
                    if !address_filter(to) {
                        continue;
                    }
                    let destination = translation.destination(to);
                    let bytes = overlay.frame(bytes);
                    if let Err(error) = socket.send_to(&bytes, destination).await {
                        send_errors += 1;
                        diagnostics.event("dht.socket.send", io_code(&error), vec![]);
                        let _ = events.send(Notice::IoError(error.kind()));
                    } else {
                        outbound += 1;
                    }
                }
                Action::Event(event) => {
                    observe_dht_event(&diagnostics, &event);
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
                        let observation = diagnostics.operation("network.rebind");
                        let replacement = if socket.local_addr().ok() == Some(address) {
                            Ok(None)
                        } else { bind_socket(address).map(Some) };
                        match replacement {
                            Err(error) => { observation.finish(io_code(&error)); let _ = reply.send(Err(error)); }
                            Ok(replacement) => {
                                if let Some(previous) = pending.take() {
                                    previous.observation.finish("superseded");
                                    let _ = previous.reply.send(Err(io::Error::new(
                                        io::ErrorKind::Interrupted, "superseded network change")));
                                }
                                let bound = replacement.as_ref().unwrap_or(&socket).local_addr()
                                    .expect("bound UDP socket");
                                #[cfg(test)]
                                let gate = discovery_gate.take();
                                pending = Some(PendingRebind {
                                    observation,
                                    socket: replacement, seeds, reply,
                                    discovery: Box::pin(async move {
                                        #[cfg(test)]
                                        if let Some(gate) = gate { let _ = gate.await; }
                                        nat64::Translation::discover(bound).await
                                    }),
                                });
                            }
                        }
                        vec![]
                    }
                }
                #[cfg(test)]
                Some(Command::DelayDiscovery(gate)) => { discovery_gate = Some(gate); vec![] }
                #[cfg(test)]
                Some(Command::ReceiveError(kind, reply)) => {
                    receive_enabled = transient_receive_error(kind);
                    let _ = reply.send(());
                    vec![]
                }
                Some(Command::Stop(reply)) => { stopped = Some(reply); break 'actor; }
                None => break 'actor,
            },
            mapping = async {
                match pending.as_mut() {
                    Some(request) => request.discovery.as_mut().await,
                    None => std::future::pending().await,
                }
            } => {
                let request = pending.take().expect("completed discovery");
                if request.reply.is_closed() { vec![] } else {
                    match core.network_changed(Keypair::generate().seed(), &request.seeds, time(start)) {
                        Ok(actions) => {
                            if let Some(replacement) = request.socket { socket = replacement; }
                            let address = socket.local_addr().expect("bound UDP socket");
                            receive_enabled = true;
                            translation = mapping;
                            let mut observation = request.observation;
                            observation.field("translation", DiagnosticValue::Text(translation.mode()));
                            observation.field("discovery", DiagnosticValue::Text(translation.discovery_status));
                            diagnostics.generation(network.borrow().generation + 1);
                            observation.field("generation", DiagnosticValue::Count(network.borrow().generation + 1));
                            observation.finish("");
                            mappings.send_replace(translation.clone());
                            network.send_modify(|state| { state.address = address; state.generation += 1; });
                            let _ = request.reply.send(Ok(address));
                            actions
                        }
                        Err(error) => {
                            request.observation.finish("dht_rebind_rejected");
                            let _ = request.reply.send(Err(io::Error::other(format!("{error:?}"))));
                            vec![]
                        }
                    }
                }
            },
            packet = socket.recv_from(&mut buffer), if receive_enabled => match packet {
                Ok((len, from)) => {
                    inbound.fetch_add(1, Ordering::Relaxed);
                    let from = translation.source(from);
                    match overlay.payload(&buffer[..len]).filter(|_| address_filter(from)) {
                        Some(bytes) => core.receive(from, bytes, time(start)),
                        None => vec![],
                    }
                },
                Err(error) => {
                    receive_errors += 1;
                    diagnostics.event("dht.socket.receive", io_code(&error), vec![]);
                    let _ = events.send(Notice::IoError(error.kind()));
                    // Keep accepting recovery commands without spinning on a
                    // failed interface. Rebinding enables receives again.
                    receive_enabled = transient_receive_error(error.kind());
                    vec![]
                }
            },
            _ = timer => core.tick(time(start)),
            _ = health.tick() => {
                diagnostics.event("dht.health", "", vec![
                    ("routing_contacts", DiagnosticValue::Count(core.routing_len() as u64)),
                    ("inbound_datagrams", DiagnosticValue::Count(inbound.load(Ordering::Relaxed))),
                    ("outbound_datagrams", DiagnosticValue::Count(outbound)),
                    ("send_errors", DiagnosticValue::Count(send_errors)),
                    ("receive_errors", DiagnosticValue::Count(receive_errors)),
                    ("generation", DiagnosticValue::Count(network.borrow().generation)),
                    ("translation", DiagnosticValue::Text(translation.mode())),
                    ("discovery", DiagnosticValue::Text(translation.discovery_status)),
                ]);
                vec![]
            },
        };
    }
    drop(socket);
    let _ = events.send(Notice::Stopped);
    if let Some(reply) = stopped {
        let _ = reply.send(());
    }
}

fn observe_dht_event(observer: &Observer, event: &Event) {
    let (name, error, fields) = match event {
        Event::RpcTimedOut(_) => ("dht.rpc.timeout", "timeout", vec![]),
        Event::SignalTimedOut(_) => ("dht.signal", "timeout", vec![]),
        Event::Ready(_) => ("dht.handshake", "", vec![]),
        Event::Registered(_) => ("dht.registration", "", vec![]),
        Event::LookupDone {
            timed_out, closest, ..
        } => (
            "dht.lookup.result",
            if *timed_out { "timeout" } else { "" },
            vec![("closest", DiagnosticValue::Count(closest.len() as u64))],
        ),
        Event::Providers { records, .. } | Event::ProviderPage { records, .. } => (
            "dht.providers",
            "",
            vec![("providers", DiagnosticValue::Count(records.len() as u64))],
        ),
        Event::ValueStored { stored, .. } => (
            "dht.value.store",
            if *stored { "" } else { "rejected" },
            vec![],
        ),
        Event::Value { value, .. } => (
            "dht.value.fetch",
            "",
            vec![("found", DiagnosticValue::Flag(value.is_some()))],
        ),
        _ => return,
    };
    observer.event(name, error, fields);
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
    async fn delayed_discovery_keeps_actor_live_and_cannot_replace_newer_network() {
        let a = Node::bind("127.0.0.1:0".parse().unwrap(), Keypair::generate(), false)
            .await
            .unwrap();
        let b = Node::bind("127.0.0.1:0".parse().unwrap(), Keypair::generate(), true)
            .await
            .unwrap();
        let before = *a.network().borrow();
        let (release, gate) = oneshot::channel();
        a.inner
            .commands
            .send(Command::DelayDiscovery(gate))
            .await
            .unwrap();
        let (reply, result) = oneshot::channel();
        a.inner
            .commands
            .send(Command::Rebind(
                "127.0.0.1:0".parse().unwrap(),
                vec![],
                reply,
            ))
            .await
            .unwrap();
        // The command is accepted but discovery cannot complete yet.
        tokio::time::timeout(Duration::from_secs(1), a.routing_len())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*a.network().borrow(), before);
        let mut events = a.subscribe();
        a.probe(Contact::new(b.id(), b.local_addr())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if matches!(next_event(&mut events).await.unwrap(), Event::Ready(_)) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        a.rebind(before.address, &[]).await.unwrap();
        assert_eq!(
            result.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(release.send(()).is_err());
        assert_eq!(a.network().borrow().generation, before.generation + 1);
        assert_eq!(a.inner.translation.borrow().bind, before.address);
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn canceled_discovery_does_not_commit_and_shutdown_does_not_wait() {
        let node = Node::bind("127.0.0.1:0".parse().unwrap(), Keypair::generate(), false)
            .await
            .unwrap();
        let before = *node.network().borrow();
        let (release, gate) = oneshot::channel();
        node.inner
            .commands
            .send(Command::DelayDiscovery(gate))
            .await
            .unwrap();
        let (reply, result) = oneshot::channel();
        node.inner
            .commands
            .send(Command::Rebind(
                "127.0.0.1:0".parse().unwrap(),
                vec![],
                reply,
            ))
            .await
            .unwrap();
        node.routing_len().await.unwrap();
        drop(result);
        release.send(()).unwrap();
        node.routing_len().await.unwrap();
        assert_eq!(*node.network().borrow(), before);
        let (_release, gate) = oneshot::channel();
        node.inner
            .commands
            .send(Command::DelayDiscovery(gate))
            .await
            .unwrap();
        let (reply, _result) = oneshot::channel();
        node.inner
            .commands
            .send(Command::Rebind(before.address, vec![], reply))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), node.shutdown())
            .await
            .unwrap()
            .unwrap();
    }

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
