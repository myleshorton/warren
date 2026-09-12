//! Authenticated transfers discovered and signaled entirely through the new DHT.
//! Connections use direct nomination and bounded one-sided birthday punching.
//! Unreachable networks return `DirectUnavailable`; no central fallback is used.
use crate::{Link, NoiseLink};
use crypto::{Keypair, PublicKey};
use dht_next::{node_id, Contact, Event, ReceivedSignal, Record, RoutingPolicy};
use driver::next::{DirectSocket, Node, Notice};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, Semaphore};
use tokio::task::JoinHandle;

mod recovery;
pub use recovery::{NetworkMonitor, NetworkStatus, RecoveryConfig, RecoveryError};

const MAGIC: &[u8] = b"warren-connect\x02";
const CAPACITY: usize = 32;

#[derive(Clone)]
pub struct Config {
    /// Bound discovery, signaling, punching and authentication together.
    pub deadline: Duration,
    pub punch: driver::PunchConfig,
    /// Optional router mapping; failures fall back to reflected candidates.
    pub port_mapping: Option<driver::next::MappingGateway>,
    /// Called on authenticated offer authors before allocating a data socket.
    pub authorize: Arc<dyn Fn(PublicKey) -> bool + Send + Sync>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(60),
            punch: driver::PunchConfig::default(),
            port_mapping: None,
            authorize: Arc::new(|_| true),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DHT: {0}")]
    Dht(#[from] driver::next::Error),
    #[error("no signed registration for the requested public key")]
    PeerNotFound,
    #[error("DHT signaling timed out")]
    SignalingTimedOut,
    #[error("direct candidates were unreachable; no relay fallback is configured")]
    DirectUnavailable,
    #[error("invalid connection candidates")]
    InvalidCandidates,
    #[error("connection deadline exceeded")]
    Deadline,
    #[error("connection capacity exhausted")]
    Busy,
    #[error("incoming peer is not authorized")]
    Unauthorized,
    #[error("this endpoint already has a listener")]
    AlreadyListening,
    #[error("data socket: {0}")]
    Socket(#[source] io::Error),
    #[error("peer authentication: {0}")]
    Authentication(#[source] io::Error),
    #[error("invalid connection configuration")]
    InvalidConfig,
}
struct Inner {
    node: Node,
    identity: Keypair,
    config: Config,
    connections: Arc<Semaphore>,
    listening: AtomicBool,
    recovery: Mutex<()>,
}
#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<Inner>,
}
impl Endpoint {
    pub async fn bind(address: SocketAddr, identity: Keypair, server: bool) -> Result<Self, Error> {
        Self::bind_with_policy(
            address,
            identity,
            server,
            RoutingPolicy::Diverse,
            Config::default(),
        )
        .await
    }
    pub async fn bind_with_policy(
        address: SocketAddr,
        identity: Keypair,
        server: bool,
        policy: RoutingPolicy,
        config: Config,
    ) -> Result<Self, Error> {
        if config.deadline.is_zero()
            || config.deadline > Duration::from_secs(120)
            || config.punch.overall.is_zero()
            || config.punch.probe_interval.is_zero()
        {
            return Err(Error::InvalidConfig);
        }
        let node = Node::bind_with_policy(address, identity.clone(), server, policy)
            .await
            .map_err(Error::Socket)?;
        Ok(Self {
            inner: Arc::new(Inner {
                node,
                identity,
                config,
                connections: Arc::new(Semaphore::new(CAPACITY)),
                listening: AtomicBool::new(false),
                recovery: Mutex::new(()),
            }),
        })
    }
    pub fn dht(&self) -> &Node {
        &self.inner.node
    }
    pub fn public_key(&self) -> PublicKey {
        self.inner.identity.public()
    }

    /// Publish our public-key address and maintain it until the listener closes.
    /// Returns after the first acknowledged registration. Background renewal adds
    /// and repairs alternate coordinators; one acknowledgement is not redundancy.
    pub async fn listen(&self, seeds: &[Contact]) -> Result<Listener, Error> {
        if seeds.len() > 8 {
            return Err(Error::InvalidConfig);
        }
        if self.inner.listening.swap(true, Ordering::AcqRel) {
            return Err(Error::AlreadyListening);
        }
        let (offers, incoming) = mpsc::channel(CAPACITY);
        let reflectors = Arc::new(std::sync::Mutex::new(Vec::new()));
        let known_reflectors = reflectors.clone();
        let (stop, stopped) = oneshot::channel();
        let (ready, registered) = oneshot::channel();
        let endpoint = self.clone();
        let seeds = seeds.to_vec();
        let events = self.dht().subscribe();
        let initial_generation = self.dht().network().borrow().generation;
        let task = tokio::spawn(async move {
            let mut ready = Some(ready);
            let mut events = events;
            let mut generation = initial_generation;
            let work = async {
                endpoint.dht().publish(endpoint.dht().id(), &seeds).await?;
                loop {
                    let event = match next_event(&mut events).await {
                        Ok(event) => event,
                        Err(error) => break Err::<(), Error>(error),
                    };
                    match event {
                        Event::NetworkChanged(epoch) => {
                            generation = epoch;
                            known_reflectors.lock().expect("reflectors").clear();
                        }
                        Event::Registered(record)
                            if record.topic == endpoint.dht().id()
                                && record.provider == endpoint.public_key() =>
                        {
                            {
                                let mut known = known_reflectors.lock().expect("reflectors");
                                known.retain(|c: &Contact| c.id != record.coordinator.id);
                                known.insert(0, record.coordinator);
                                known.truncate(dht_next::MAX_COORDINATORS);
                            }
                            if let Some(ready) = ready.take() {
                                let _ = ready.send(Ok(()));
                            }
                        }
                        Event::Incoming {
                            coordinator,
                            signal,
                        } if signal.envelope.recipient == endpoint.dht().id()
                            && !signal.envelope.answer
                            && decode(&signal.payload, false).is_ok()
                            && (endpoint.inner.config.authorize)(signal.envelope.author) =>
                        {
                            let _ = offers.try_send(Ok((generation, coordinator, signal)));
                        }
                        _ => {}
                    }
                }
            };
            let result = tokio::select! {
                result = work => result,
                _ = stopped => Ok(()),
            };
            if let Err(error) = result {
                if let Some(ready) = ready.take() {
                    let _ = ready.send(Err(error));
                } else {
                    let _ = offers.try_send(Err(error));
                }
            }
            let _ = endpoint.dht().unpublish(endpoint.dht().id()).await;
            endpoint.inner.listening.store(false, Ordering::Release);
        });
        let listener = Listener {
            endpoint: self.clone(),
            incoming,
            reflectors,
            stop: Some(stop),
            task: Some(task),
        };
        match tokio::time::timeout(self.inner.config.deadline, registered).await {
            Ok(Ok(Ok(()))) => Ok(listener),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(Error::Dht(driver::next::Error::Closed)),
            Err(_) => Err(Error::Deadline),
        }
    }
    /// Dial a public key. Records published by other keys at that topic are ignored.
    pub async fn connect(&self, peer: PublicKey, seeds: &[Contact]) -> Result<Connection, Error> {
        let _permit = self
            .inner
            .connections
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        guarded(self.dht(), self.inner.config.deadline, async {
            let records = self.discover(peer, seeds).await?;
            self.connect_records(peer, &records).await
        })
        .await
    }
    async fn discover(&self, peer: PublicKey, seeds: &[Contact]) -> Result<Vec<Record>, Error> {
        let mut events = self.dht().subscribe();
        let target = node_id(peer);
        let query = self.dht().lookup(target, seeds).await?;
        let mut records = Vec::new();
        let mut incomplete;
        let closest = loop {
            match next_event(&mut events).await? {
                Event::Providers {
                    query: id,
                    records: found,
                } if id == query => {
                    records.extend(
                        found
                            .into_iter()
                            .filter(|r| r.provider == peer && r.topic == target),
                    );
                }
                Event::LookupDone {
                    query: id,
                    timed_out,
                    closest,
                } if id == query => {
                    incomplete = timed_out;
                    break closest;
                }
                _ => {}
            }
        };
        // Generic referral packets carry only two providers. Seek directly to
        // this provider's position so other publishers cannot crowd it off-page.
        let mut predecessor = *target.as_bytes();
        let after = if predecessor.iter().all(|byte| *byte == 0) {
            None
        } else {
            for byte in predecessor.iter_mut().rev() {
                if *byte != 0 {
                    *byte -= 1;
                    break;
                }
                *byte = 255;
            }
            Some(dht_next::NodeId::from_bytes(predecessor))
        };
        let mut pending = BTreeMap::new();
        if records.len() < dht_next::MAX_COORDINATORS {
            for coordinator in closest {
                if records.iter().any(|r| r.coordinator == coordinator) {
                    continue;
                }
                pending.insert(
                    self.dht()
                        .providers_page(coordinator, target, after)
                        .await?,
                    coordinator,
                );
            }
        }
        while !pending.is_empty() {
            match next_event(&mut events).await? {
                Event::ProviderPage {
                    request,
                    records: found,
                    ..
                } if pending.remove(&request).is_some() => {
                    records.extend(
                        found
                            .into_iter()
                            .filter(|r| r.provider == peer && r.topic == target),
                    );
                }
                Event::RpcTimedOut(request) if pending.remove(&request).is_some() => {
                    incomplete = true;
                }
                _ => {}
            }
        }
        if records.is_empty() && incomplete {
            return Err(driver::next::Error::TimedOut.into());
        }
        records.sort_by_key(|r| std::cmp::Reverse(r.expires));
        let key = records.first().ok_or(Error::PeerNotFound)?.signaling_key;
        let mut ids = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        records.retain(|r| {
            r.signaling_key == key
                && ids.insert(r.coordinator.id)
                && addresses.insert(r.coordinator.addr)
        });
        records.truncate(dht_next::MAX_COORDINATORS);
        Ok(records)
    }
    async fn connect_records(
        &self,
        peer: PublicKey,
        records: &[Record],
    ) -> Result<Connection, Error> {
        let reflectors: Vec<_> = records.iter().map(|r| r.coordinator).collect();
        let socket = self.prepare(&reflectors).await?;
        let mut events = self.dht().subscribe();
        let session = self
            .dht()
            .signal_via(records, encode(socket.candidates(), false)?)
            .await?;
        let candidates = loop {
            match next_event(&mut events).await? {
                Event::Answered(signal)
                    if signal.envelope.session == session && signal.envelope.author == peer =>
                {
                    break decode(&signal.payload, true)?;
                }
                Event::SignalTimedOut(id) if id == session => return Err(Error::SignalingTimedOut),
                _ => {}
            }
        };
        let channel = socket
            .punch(&candidates, &self.inner.config.punch, session, true)
            .await
            .map_err(Error::Socket)?
            .ok_or(Error::DirectUnavailable)?;
        let link =
            NoiseLink::connect_session(channel, &self.inner.identity, node_id(peer), session)
                .await
                .map_err(Error::Authentication)?;
        Ok(Connection::new(peer, session, link).on_network(self.dht().network()))
    }
    async fn prepare(&self, reflectors: &[Contact]) -> Result<DirectSocket, Error> {
        DirectSocket::bind_with_mapping(
            SocketAddr::new(self.dht().local_addr().ip(), 0),
            reflectors,
            self.inner.config.port_mapping.as_ref(),
        )
        .await
        .map_err(Error::Socket)
    }
}

/// A listener owns only its public-key registration and bounded offer queue.
/// Drop requests unpublication; `close().await` waits for it. Established data
/// connections own their sockets and outlive listener closure.
pub struct Listener {
    endpoint: Endpoint,
    reflectors: Arc<std::sync::Mutex<Vec<Contact>>>,
    incoming: mpsc::Receiver<Result<(u64, Contact, ReceivedSignal), Error>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
impl Listener {
    /// Wait for an authorized offer, then establish and authenticate its data path.
    /// The connection deadline begins when the offer is dequeued, not while idle.
    pub async fn accept(&mut self) -> Result<Connection, Error> {
        loop {
            match self.accept_once().await {
                Err(Error::Dht(
                    driver::next::Error::NetworkChanged
                    | driver::next::Error::Core(dht_next::Error::UnknownSession),
                )) => continue,
                result => return result,
            }
        }
    }
    async fn accept_once(&mut self) -> Result<Connection, Error> {
        let (coordinator, signal) = loop {
            let (generation, coordinator, signal) = self
                .incoming
                .recv()
                .await
                .ok_or(Error::Dht(driver::next::Error::Closed))??;
            if generation == self.endpoint.dht().network().borrow().generation {
                break (coordinator, signal);
            }
        };
        let endpoint = &self.endpoint;
        if !(endpoint.inner.config.authorize)(signal.envelope.author) {
            return Err(Error::Unauthorized);
        }
        let mut reflectors = self.reflectors.lock().expect("reflectors").clone();
        if !reflectors.contains(&coordinator) {
            reflectors.push(coordinator);
        }
        reflectors.truncate(dht_next::MAX_COORDINATORS);
        let _permit = endpoint
            .inner
            .connections
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        guarded(endpoint.dht(), endpoint.inner.config.deadline, async {
            let peer = signal.envelope.author;
            let session = signal.envelope.session;
            let candidates = decode(&signal.payload, false)?;
            let socket = endpoint.prepare(&reflectors).await?;
            endpoint
                .dht()
                .answer(session, encode(socket.candidates(), true)?)
                .await?;
            let channel = socket
                .punch(&candidates, &endpoint.inner.config.punch, session, false)
                .await
                .map_err(Error::Socket)?
                .ok_or(Error::DirectUnavailable)?;
            let (link, _) = NoiseLink::accept_session(
                channel,
                &endpoint.inner.identity,
                node_id(peer),
                session,
            )
            .await
            .map_err(Error::Authentication)?;
            Ok(Connection::new(peer, session, link).on_network(endpoint.dht().network()))
        })
        .await
    }
    pub async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// An authenticated datagram link usable by the existing reliable feed/blob
/// transfer APIs. This is not an ordered `AsyncRead`/`AsyncWrite` byte stream.
pub struct Connection {
    peer: PublicKey,
    session: [u8; 32],
    link: Arc<NoiseLink<driver::next::DirectChannel>>,
    incoming: Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>,
    receiver: JoinHandle<()>,
    network_task: Option<JoinHandle<()>>,
    network: Option<(
        tokio::sync::watch::Receiver<driver::next::NetworkState>,
        u64,
    )>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.receiver.abort();
        if let Some(task) = &self.network_task {
            task.abort();
        }
    }
}
impl Connection {
    fn new(
        peer: PublicKey,
        session: [u8; 32],
        link: NoiseLink<driver::next::DirectChannel>,
    ) -> Self {
        let link = Arc::new(link);
        let receiving = link.clone();
        let (send, incoming) = mpsc::channel(CAPACITY);
        let receiver = tokio::spawn(receive_connection(receiving, send));
        Self {
            peer,
            session,
            link,
            incoming: Mutex::new(incoming),
            receiver,
            network_task: None,
            network: None,
        }
    }
    fn on_network(
        mut self,
        network: tokio::sync::watch::Receiver<driver::next::NetworkState>,
    ) -> Self {
        let generation = network.borrow().generation;
        let mut changes = network.clone();
        let receiver = self.receiver.abort_handle();
        self.network_task = Some(tokio::spawn(async move {
            loop {
                if changes.borrow().generation != generation {
                    receiver.abort();
                    break;
                }
                if changes.changed().await.is_err() {
                    break;
                }
            }
        }));
        self.network = Some((network, generation));
        self
    }
    async fn network_changed(&self) {
        if let Some((network, generation)) = &self.network {
            let mut network = network.clone();
            loop {
                if network.borrow().generation != *generation {
                    return;
                }
                if network.changed().await.is_err() {
                    break;
                }
            }
        }
        std::future::pending::<()>().await;
    }
    pub fn remote_public_key(&self) -> PublicKey {
        self.peer
    }
    pub fn session(&self) -> [u8; 32] {
        self.session
    }
}
// These frames are inside Noise; punch controls cannot reset this deadline.
const KEEPALIVE: Duration = Duration::from_secs(15);
const DEAD_PEER: Duration = Duration::from_secs(90);
async fn receive_connection<L: Link + Send + Sync + 'static>(
    link: Arc<L>,
    send: mpsc::Sender<io::Result<Vec<u8>>>,
) {
    let mut heartbeat =
        tokio::time::interval_at(tokio::time::Instant::now() + KEEPALIVE, KEEPALIVE);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_received = tokio::time::Instant::now();
    let mut bytes = vec![0; link.max_payload()];
    let result: io::Result<()> = async {
        loop {
            tokio::select! {
                _ = send.closed() => return Ok(()),
                _ = tokio::time::sleep_until(last_received + DEAD_PEER) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "authenticated peer stopped responding"));
                }
                _ = heartbeat.tick() => { link.send(&[1]).await?; }
                received = link.recv(&mut bytes) => {
                    let len = received?;
                    match &bytes[..len] {
                        [0, payload @ ..] => {
                            last_received = tokio::time::Instant::now();
                            match send.try_send(Ok(payload.to_vec())) {
                                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                            }
                        }
                        [1] => {
                            last_received = tokio::time::Instant::now();
                            link.send(&[2]).await?;
                        }
                        [2] => { last_received = tokio::time::Instant::now(); }
                        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid connection frame")),
                    }
                }
            }
        }
    }.await;
    if let Err(error) = result {
        // Preserve the terminal error even if the application queue is full.
        let _ = send.send(Err(error)).await;
    }
}
impl Link for Connection {
    async fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max_payload() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram exceeds connection payload limit",
            ));
        }
        let mut frame = Vec::with_capacity(bytes.len() + 1);
        frame.push(0);
        frame.extend_from_slice(bytes);
        tokio::select! {
            biased;
            _ = self.network_changed() => return Err(network_error()),
            result = self.link.send(&frame) => { result?; }
        }
        Ok(bytes.len())
    }
    async fn recv(&self, bytes: &mut [u8]) -> io::Result<usize> {
        let packet = tokio::select! {
            biased;
            _ = self.network_changed() => return Err(network_error()),
            packet = async { self.incoming.lock().await.recv().await } => packet,
        }
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "connection receiver stopped")
        })??;
        if packet.len() > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffer too small for datagram",
            ));
        }
        bytes[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    fn max_payload(&self) -> usize {
        self.link.max_payload() - 1
    }
    fn authenticated(&self) -> bool {
        true
    }
}
async fn next_event(events: &mut broadcast::Receiver<Notice>) -> Result<Event, Error> {
    loop {
        match events.recv().await {
            Ok(Notice::Dht(event)) => return Ok(*event),
            Ok(Notice::Stopped) | Err(broadcast::error::RecvError::Closed) => {
                return Err(driver::next::Error::Closed.into())
            }
            Err(broadcast::error::RecvError::Lagged(count)) => {
                return Err(driver::next::Error::EventsLagged(count).into())
            }
            Ok(Notice::IoError(_)) => {}
        }
    }
}
fn network_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "local network changed; establish a fresh authenticated connection",
    )
}
async fn guarded<T>(
    node: &Node,
    deadline: Duration,
    work: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let mut events = node.subscribe();
    let mut network = node.network();
    let stopped = async {
        loop {
            match events.recv().await {
                Ok(Notice::Stopped) | Err(broadcast::error::RecvError::Closed) => return,
                _ => {}
            }
        }
    };
    tokio::select! {
        biased;
        _ = network.changed() => Err(driver::next::Error::NetworkChanged.into()),
        result = work => result,
        _ = stopped => Err(driver::next::Error::Closed.into()),
        _ = tokio::time::sleep(deadline) => Err(Error::Deadline),
    }
}
fn encode(addresses: &[SocketAddr], answer: bool) -> Result<Vec<u8>, Error> {
    if addresses.is_empty() || addresses.len() > 4 {
        return Err(Error::InvalidCandidates);
    }
    let mut bytes = MAGIC.to_vec();
    bytes.push(u8::from(answer));
    bytes.push(addresses.len() as u8);
    for address in addresses {
        match address.ip() {
            IpAddr::V4(ip) => {
                bytes.push(4);
                bytes.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                bytes.push(6);
                bytes.extend_from_slice(&ip.octets());
            }
        }
        bytes.extend_from_slice(&address.port().to_be_bytes());
    }
    decode(&bytes, answer)?;
    Ok(bytes)
}
fn decode(bytes: &[u8], answer: bool) -> Result<Vec<SocketAddr>, Error> {
    let mut bytes = bytes.strip_prefix(MAGIC).ok_or(Error::InvalidCandidates)?;
    if bytes.len() < 2 || bytes[0] != u8::from(answer) || !(1..=4).contains(&bytes[1]) {
        return Err(Error::InvalidCandidates);
    }
    let count = bytes[1];
    bytes = &bytes[2..];
    let mut addresses = Vec::new();
    for _ in 0..count {
        let family = *bytes.first().ok_or(Error::InvalidCandidates)?;
        bytes = &bytes[1..];
        let length = match family {
            4 => 4,
            6 => 16,
            _ => return Err(Error::InvalidCandidates),
        };
        if bytes.len() < length + 2 {
            return Err(Error::InvalidCandidates);
        }
        let ip = match family {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[..4]).unwrap())),
            _ => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[..16]).unwrap())),
        };
        let port = u16::from_be_bytes(bytes[length..length + 2].try_into().unwrap());
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            _ => ip,
        };
        let address = SocketAddr::new(ip, port);
        if port == 0
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
            || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
            || addresses.contains(&address)
        {
            return Err(Error::InvalidCandidates);
        }
        addresses.push(address);
        bytes = &bytes[length + 2..];
    }
    if !bytes.is_empty() {
        return Err(Error::InvalidCandidates);
    }
    Ok(addresses)
}

impl Link for driver::next::DirectChannel {
    async fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        self.send(bytes).await
    }
    async fn recv(&self, bytes: &mut [u8]) -> io::Result<usize> {
        self.recv(bytes).await
    }
    fn max_payload(&self) -> usize {
        crate::FRAGMENT
    }
    fn authenticated(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn router(seed: u8) -> Node {
        Node::bind_with_policy(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::from_seed(&[seed; 32]),
            true,
            RoutingPolicy::Unrestricted,
        )
        .await
        .unwrap()
    }
    async fn endpoint(seed: u8, host: &str) -> Endpoint {
        Endpoint::bind_with_policy(
            format!("{host}:0").parse().unwrap(),
            Keypair::from_seed(&[seed; 32]),
            false,
            RoutingPolicy::Unrestricted,
            Config::default(),
        )
        .await
        .unwrap()
    }
    fn contact(node: &Node) -> Contact {
        Contact::new(node.id(), node.local_addr())
    }

    #[tokio::test]
    async fn public_key_connect_streams_a_verified_blob_over_dht_signaling() {
        let router = router(91).await;
        let server = endpoint(92, "127.0.0.1").await;
        let client = endpoint(93, "127.0.0.1").await;
        let seeds = [contact(&router)];
        let mut listener = server.listen(&seeds).await.unwrap();
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.public_key(), &seeds),
            listener.accept()
        );
        let mut outgoing = outgoing.unwrap();
        let mut incoming = incoming.unwrap();
        assert!(outgoing.authenticated() && incoming.authenticated());
        assert_eq!(outgoing.remote_public_key(), server.public_key());
        assert_eq!(incoming.remote_public_key(), client.public_key());
        assert_eq!(incoming.session(), outgoing.session());
        listener.close().await;
        let bytes: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let mut store = blob::Store::new();
        let manifest = store.add(&bytes);
        let id = store.put(manifest.encode());
        let serving = tokio::spawn(async move {
            crate::serve_blob(&mut incoming, &store, &crate::Config::default()).await
        });
        let received = tokio::time::timeout(
            Duration::from_secs(15),
            crate::download_blob(&mut outgoing, id, &crate::Config::default()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, bytes);
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        assert_eq!(
            router.routing_len().await.unwrap(),
            0,
            "data sockets and clients must not enter routing"
        );
        for node in [&router, server.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn coordinator_failure_after_discovery_uses_an_alternate() {
        let a = router(94).await;
        let b = Node::bind(
            "[::1]:0".parse().unwrap(),
            Keypair::from_seed(&[95; 32]),
            true,
        )
        .await
        .unwrap();
        let server = endpoint(96, "[::]").await;
        let client = endpoint(97, "[::]").await;
        let seeds = [contact(&a), contact(&b)];
        let mut events = server.dht().subscribe();
        let mut listener = server.listen(&seeds).await.unwrap();
        let mut registered = BTreeSet::new();
        while registered.len() < 2 {
            if let Event::Registered(record) =
                tokio::time::timeout(Duration::from_secs(5), next_event(&mut events))
                    .await
                    .unwrap()
                    .unwrap()
            {
                registered.insert(record.coordinator.id);
            }
        }
        let records = client.discover(server.public_key(), &seeds).await.unwrap();
        assert_eq!(records.len(), 2);
        let (dead, live) = if records[0].coordinator.id == a.id() {
            (&a, &b)
        } else {
            (&b, &a)
        };
        dead.shutdown().await.unwrap();
        let (outgoing, incoming) = tokio::join!(
            guarded(
                client.dht(),
                Duration::from_secs(15),
                client.connect_records(server.public_key(), &records)
            ),
            listener.accept()
        );
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        outgoing
            .send(b"alternate coordinator worked")
            .await
            .unwrap();
        let mut bytes = [0; 128];
        let len = tokio::time::timeout(Duration::from_secs(2), incoming.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..len], b"alternate coordinator worked");
        listener.close().await;
        for node in [live, server.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn ipv6_wildcard_uses_the_observed_data_socket_mapping() {
        let router = Node::bind(
            "[::1]:0".parse().unwrap(),
            Keypair::from_seed(&[98; 32]),
            true,
        )
        .await
        .unwrap();
        let server = endpoint(99, "[::]").await;
        let client = endpoint(100, "[::]").await;
        let seeds = [contact(&router)];
        let mut listener = server.listen(&seeds).await.unwrap();
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.public_key(), &seeds),
            listener.accept()
        );
        assert_eq!(outgoing.unwrap().session(), incoming.unwrap().session());
        listener.close().await;
        for node in [&router, server.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn another_key_cannot_publish_itself_as_the_requested_peer() {
        let router = router(101).await;
        let imposter = endpoint(102, "127.0.0.1").await;
        let client = endpoint(103, "127.0.0.1").await;
        let target = Keypair::from_seed(&[104; 32]).public();
        let seeds = [contact(&router)];
        let mut events = imposter.dht().subscribe();
        imposter
            .dht()
            .publish(node_id(target), &seeds)
            .await
            .unwrap();
        loop {
            if matches!(next_event(&mut events).await.unwrap(), Event::Registered(_)) {
                break;
            }
        }
        assert!(matches!(
            client.connect(target, &seeds).await,
            Err(Error::PeerNotFound)
        ));
        for node in [&router, imposter.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn cancellation_stops_publication_and_releases_the_listener_slot() {
        let router = router(105).await;
        let server = endpoint(106, "127.0.0.1").await;
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = Contact::new(
            node_id(Keypair::from_seed(&[107; 32]).public()),
            blackhole.local_addr().unwrap(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), server.listen(&[dead]))
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.inner.listening.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!server.dht().unpublish(server.dht().id()).await.unwrap());
        let listener = server.listen(&[contact(&router)]).await.unwrap();
        assert!(matches!(
            server.listen(&[]).await,
            Err(Error::AlreadyListening)
        ));
        listener.close().await;
        assert!(!server.inner.listening.load(Ordering::Acquire));
        for node in [&router, server.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn unreachable_direct_candidates_return_an_explicit_failure() {
        let router = router(108).await;
        let server = endpoint(109, "127.0.0.1").await;
        let mut config = Config::default();
        config.punch.overall = Duration::from_millis(100);
        let client = Endpoint::bind_with_policy(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::from_seed(&[110; 32]),
            false,
            RoutingPolicy::Unrestricted,
            config,
        )
        .await
        .unwrap();
        let seeds = [contact(&router)];
        let mut events = server.dht().subscribe();
        server
            .dht()
            .publish(server.dht().id(), &seeds)
            .await
            .unwrap();
        loop {
            if matches!(next_event(&mut events).await.unwrap(), Event::Registered(_)) {
                break;
            }
        }
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (result, ()) = tokio::join!(client.connect(server.public_key(), &seeds), async {
            loop {
                if let Event::Incoming { signal, .. } = next_event(&mut events).await.unwrap() {
                    server
                        .dht()
                        .answer(
                            signal.envelope.session,
                            encode(&[blackhole.local_addr().unwrap()], true).unwrap(),
                        )
                        .await
                        .unwrap();
                    break;
                }
            }
        });
        assert!(matches!(result, Err(Error::DirectUnavailable)));
        for node in [&router, server.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn shutdown_interrupts_a_connection_waiting_for_acceptance() {
        let router = router(111).await;
        let server = endpoint(112, "127.0.0.1").await;
        let client = endpoint(113, "127.0.0.1").await;
        let seeds = [contact(&router)];
        let listener = server.listen(&seeds).await.unwrap();
        let mut events = server.dht().subscribe();
        let (result, ()) = tokio::join!(client.connect(server.public_key(), &seeds), async {
            loop {
                if matches!(
                    next_event(&mut events).await.unwrap(),
                    Event::Incoming { .. }
                ) {
                    client.dht().shutdown().await.unwrap();
                    break;
                }
            }
        });
        assert!(matches!(
            result,
            Err(Error::Dht(driver::next::Error::Closed))
        ));
        listener.close().await;
        for node in [&router, server.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn lost_nomination_and_noise_acks_recover_before_application_receive() {
        let left = DirectSocket::bind("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .unwrap();
        let right = DirectSocket::bind("127.0.0.1:0".parse().unwrap(), &[])
            .await
            .unwrap();
        let left_addr = left.candidates()[0];
        let right_addr = right.candidates()[0];
        let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let seen = dropped.clone();
        let nomination = Arc::new(AtomicBool::new(false));
        let nominated = nomination.clone();
        let forward = tokio::spawn(async move {
            let mut bytes = [0; 1500];
            loop {
                let (len, from) = proxy.recv_from(&mut bytes).await.unwrap();
                if from == right_addr
                    && len == 37
                    && bytes[..4] == *b"WPN1"
                    && bytes[36] == 3
                    && !nominated.swap(true, Ordering::AcqRel)
                {
                    continue;
                }
                if from == right_addr && bytes[0] == 4 && !seen.swap(true, Ordering::AcqRel) {
                    continue;
                }
                let to = if from == left_addr {
                    right_addr
                } else if from == right_addr {
                    left_addr
                } else {
                    continue;
                };
                proxy.send_to(&bytes[..len], to).await.unwrap();
            }
        });
        let config = driver::PunchConfig::default();
        let peers = [address];
        let client = Keypair::from_seed(&[114; 32]);
        let server = Keypair::from_seed(&[115; 32]);
        let session = [9; 32];
        let (left, right) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                async {
                    let left = left
                        .punch(&peers, &config, session, true)
                        .await
                        .unwrap()
                        .unwrap();
                    NoiseLink::connect_session(left, &client, node_id(server.public()), session)
                        .await
                },
                async {
                    let right = right
                        .punch(&peers, &config, session, false)
                        .await
                        .unwrap()
                        .unwrap();
                    let (link, _) = NoiseLink::accept_session(
                        right,
                        &server,
                        node_id(client.public()),
                        session,
                    )
                    .await
                    .unwrap();
                    Connection::new(client.public(), session, link)
                }
            )
        })
        .await
        .unwrap();
        let left = Connection::new(server.public(), session, left.unwrap());
        assert!(dropped.load(Ordering::Acquire));
        assert!(nomination.load(Ordering::Acquire));
        left.send(b"after handshake").await.unwrap();
        let mut bytes = [0; 64];
        let len = tokio::time::timeout(Duration::from_secs(1), right.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..len], b"after handshake");
        forward.abort();
        let _ = forward.await;
    }

    #[tokio::test]
    async fn coordinator_loss_after_offer_delivery_still_completes() {
        let a = router(116).await;
        let b = Node::bind(
            "[::1]:0".parse().unwrap(),
            Keypair::from_seed(&[117; 32]),
            true,
        )
        .await
        .unwrap();
        let server = endpoint(118, "[::]").await;
        let client = endpoint(119, "[::]").await;
        let seeds = [contact(&a), contact(&b)];
        let mut events = server.dht().subscribe();
        let mut listener = server.listen(&seeds).await.unwrap();
        let mut registered = BTreeSet::new();
        while registered.len() < 2 {
            if let Event::Registered(record) =
                tokio::time::timeout(Duration::from_secs(5), next_event(&mut events))
                    .await
                    .unwrap()
                    .unwrap()
            {
                registered.insert(record.coordinator.id);
            }
        }
        let (outgoing, incoming) =
            tokio::join!(client.connect(server.public_key(), &seeds), async {
                loop {
                    if let Event::Incoming { coordinator, .. } =
                        next_event(&mut events).await.unwrap()
                    {
                        if coordinator.id == a.id() {
                            a.shutdown().await.unwrap();
                        } else {
                            b.shutdown().await.unwrap();
                        }
                        break;
                    }
                }
                listener.accept().await
            });
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        assert_eq!(outgoing.session(), incoming.session());
        outgoing.send(b"after coordinator loss").await.unwrap();
        let mut bytes = [0; 64];
        let len = tokio::time::timeout(Duration::from_secs(2), incoming.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..len], b"after coordinator loss");
        listener.close().await;
        for node in [&a, &b, server.dht(), client.dht()] {
            let _ = node.shutdown().await;
        }
    }

    #[tokio::test]
    async fn authorization_rejects_offers_before_data_socket_allocation() {
        let router = router(120).await;
        let checked = Arc::new(AtomicBool::new(false));
        let seen = checked.clone();
        let config = Config {
            authorize: Arc::new(move |_| {
                seen.store(true, Ordering::Release);
                false
            }),
            ..Config::default()
        };
        let server = Endpoint::bind_with_policy(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::from_seed(&[121; 32]),
            false,
            RoutingPolicy::Unrestricted,
            config,
        )
        .await
        .unwrap();
        let client = endpoint(122, "127.0.0.1").await;
        let seeds = [contact(&router)];
        let mut listener = server.listen(&seeds).await.unwrap();
        let caller = client.clone();
        let peer = server.public_key();
        let connecting = tokio::spawn(async move { caller.connect(peer, &seeds).await });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !checked.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            listener.incoming.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        connecting.abort();
        assert!(connecting.await.is_err());
        listener.close().await;
        for node in [&router, server.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn simultaneous_sessions_nominate_consistent_dual_stack_paths() {
        let a = router(123).await;
        let b = Node::bind(
            "[::1]:0".parse().unwrap(),
            Keypair::from_seed(&[124; 32]),
            true,
        )
        .await
        .unwrap();
        let server = endpoint(125, "[::]").await;
        let client = endpoint(126, "[::]").await;
        let seeds = [contact(&a), contact(&b)];
        let mut events = server.dht().subscribe();
        let mut listener = server.listen(&seeds).await.unwrap();
        let mut registered = BTreeSet::new();
        while registered.len() < 2 {
            if let Event::Registered(record) =
                tokio::time::timeout(Duration::from_secs(5), next_event(&mut events))
                    .await
                    .unwrap()
                    .unwrap()
            {
                registered.insert(record.coordinator.id);
            }
        }
        let ((one, two), (first, second)) = tokio::try_join!(
            async {
                tokio::try_join!(
                    client.connect(server.public_key(), &seeds),
                    client.connect(server.public_key(), &seeds)
                )
            },
            async { Ok::<_, Error>((listener.accept().await?, listener.accept().await?)) }
        )
        .unwrap();
        assert_ne!(one.session(), two.session());
        one.send(b"one").await.unwrap();
        two.send(b"two").await.unwrap();
        for incoming in [&first, &second] {
            let expected = if incoming.session() == one.session() {
                b"one"
            } else {
                assert_eq!(incoming.session(), two.session());
                b"two"
            };
            let mut bytes = [0; 8];
            let len = tokio::time::timeout(Duration::from_secs(2), incoming.recv(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes[..len], expected);
        }
        listener.close().await;
        for node in [&a, &b, server.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn crowded_topics_do_not_hide_the_public_key_registration() {
        let router = router(130).await;
        let mut publishers = Vec::new();
        for seed in 131..134 {
            publishers.push(endpoint(seed, "127.0.0.1").await);
        }
        publishers.sort_by_key(|p| p.dht().id());
        let server = publishers.pop().unwrap();
        let seeds = [contact(&router)];
        for imposter in &publishers {
            let mut events = imposter.dht().subscribe();
            imposter
                .dht()
                .publish(server.dht().id(), &seeds)
                .await
                .unwrap();
            loop {
                if matches!(next_event(&mut events).await.unwrap(), Event::Registered(_)) {
                    break;
                }
            }
        }
        let mut listener = server.listen(&seeds).await.unwrap();
        let client = endpoint(134, "127.0.0.1").await;
        let mut events = client.dht().subscribe();
        let query = client
            .dht()
            .lookup(server.dht().id(), &seeds)
            .await
            .unwrap();
        let mut count = 0;
        loop {
            match next_event(&mut events).await.unwrap() {
                Event::Providers { query: id, records } if id == query => {
                    assert!(records.iter().all(|r| r.provider != server.public_key()));
                    count += records.len();
                }
                Event::LookupDone { query: id, .. } if id == query => break,
                _ => {}
            }
        }
        assert_eq!(count, 2);
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.public_key(), &seeds),
            listener.accept()
        );
        assert_eq!(outgoing.unwrap().session(), incoming.unwrap().session());
        listener.close().await;
        for imposter in publishers {
            imposter.dht().shutdown().await.unwrap();
        }
        for node in [&router, server.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[test]
    fn candidate_codec_rejects_wrong_role_trailing_bytes_and_unsafe_addresses() {
        let peers = ["127.0.0.1:7".parse().unwrap(), "[::1]:8".parse().unwrap()];
        let bytes = encode(&peers, false).unwrap();
        assert_eq!(decode(&bytes, false).unwrap(), peers);
        assert!(decode(&bytes, true).is_err());
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len], false).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing, false).is_err());
        for bad in [
            "0.0.0.0:1",
            "224.0.0.1:1",
            "255.255.255.255:1",
            "127.0.0.1:0",
            "[ff02::1]:1",
            "[fe80::1]:1",
        ] {
            assert!(encode(&[bad.parse().unwrap()], false).is_err(), "{bad}");
        }
        assert!(encode(&[peers[0], peers[0]], false).is_err());
    }
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    struct TestLink {
        incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
        outgoing: mpsc::Sender<Vec<u8>>,
    }
    impl Link for TestLink {
        async fn send(&self, bytes: &[u8]) -> io::Result<usize> {
            self.outgoing.send(bytes.to_vec()).await.unwrap();
            Ok(bytes.len())
        }
        async fn recv(&self, bytes: &mut [u8]) -> io::Result<usize> {
            let data = self.incoming.lock().await.recv().await.unwrap();
            bytes[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        }
        fn max_payload(&self) -> usize {
            1200
        }
        fn authenticated(&self) -> bool {
            true
        }
    }
    #[tokio::test(start_paused = true)]
    async fn heartbeat_survives_full_application_queue_and_reports_dead_peer() {
        let (network, incoming) = mpsc::channel(128);
        let (outgoing, mut sent) = mpsc::channel(128);
        let (send, mut application) = mpsc::channel(CAPACITY);
        let task = tokio::spawn(receive_connection(
            Arc::new(TestLink {
                incoming: Mutex::new(incoming),
                outgoing,
            }),
            send,
        ));
        // Saturate the application queue and keep the connection idle to its user.
        for _ in 0..CAPACITY + 1 {
            network.send(vec![0, 42]).await.unwrap();
        }
        tokio::task::yield_now().await;
        for _ in 0..12 {
            tokio::time::advance(KEEPALIVE).await;
            assert_eq!(sent.recv().await.unwrap(), vec![1]);
            network.send(vec![2]).await.unwrap();
            tokio::task::yield_now().await;
        }
        assert!(!task.is_finished());
        // Silence now exceeds the authenticated liveness deadline.
        tokio::time::advance(DEAD_PEER + Duration::from_secs(1)).await;
        for _ in 0..CAPACITY {
            assert_eq!(application.recv().await.unwrap().unwrap(), vec![42]);
        }
        assert_eq!(
            application.recv().await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        task.await.unwrap();
    }
    #[tokio::test]
    async fn heartbeat_frames_are_consumed_and_malformed_frames_close_receive() {
        let (network, incoming) = mpsc::channel(8);
        let (outgoing, mut sent) = mpsc::channel(8);
        let (send, mut application) = mpsc::channel(8);
        let task = tokio::spawn(receive_connection(
            Arc::new(TestLink {
                incoming: Mutex::new(incoming),
                outgoing,
            }),
            send,
        ));
        network.send(vec![1]).await.unwrap();
        assert_eq!(sent.recv().await.unwrap(), vec![2]);
        network.send(vec![0]).await.unwrap();
        assert_eq!(application.recv().await.unwrap().unwrap(), Vec::<u8>::new());
        network.send(vec![1, 42]).await.unwrap();
        assert_eq!(
            application.recv().await.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        task.await.unwrap();
    }
}
