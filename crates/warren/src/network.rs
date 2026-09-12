//! Discovery and authenticated links shared by legacy and v6 application sessions.
use crypto::PublicKey;
use dht_next::{Event, Record};
use driver::next::Notice;
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm::{Contact, NodeId};
use transfer::{Link, NoiseLink};

#[derive(Clone, Debug)]
pub struct Member {
    pub id: NodeId,
    /// Only a directly known DHT endpoint is suitable for a bootstrap cache.
    /// A v6 provider registration names a coordinator, not the provider's socket.
    pub contact: Option<Contact>,
}

pub trait Network: Clone + Send + Sync + 'static {
    fn id(&self) -> NodeId;
    fn lookup(&self, topic: NodeId) -> impl Future<Output = Result<Vec<Member>, String>> + Send;
    fn announce(&self, topic: NodeId) -> impl Future<Output = Result<(), String>> + Send;
    fn dial(&self, peer: NodeId) -> impl Future<Output = Result<Secure, String>> + Send;
    fn incoming(&self) -> impl Future<Output = Result<Incoming, String>> + Send;
}

pub enum Incoming {
    Legacy(driver::Channel, crypto::Keypair),
    Next(transfer::next::Connection),
}
impl Incoming {
    pub async fn authenticate(self) -> io::Result<Secure> {
        match self {
            Self::Legacy(channel, identity) => NoiseLink::accept(channel, &identity)
                .await
                .map(|(link, _)| Secure::Legacy(link)),
            Self::Next(link) => Ok(Secure::Next(link)),
        }
    }
}

pub enum Secure {
    Legacy(NoiseLink<driver::Channel>),
    Next(transfer::next::Connection),
}
impl Link for Secure {
    async fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Legacy(l) => l.send(bytes).await,
            Self::Next(l) => l.send(bytes).await,
        }
    }
    async fn recv(&self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Legacy(l) => l.recv(bytes).await,
            Self::Next(l) => l.recv(bytes).await,
        }
    }
    fn max_payload(&self) -> usize {
        match self {
            Self::Legacy(l) => l.max_payload(),
            Self::Next(l) => l.max_payload(),
        }
    }
    fn authenticated(&self) -> bool {
        true
    }
}

impl Network for driver::Node {
    async fn incoming(&self) -> Result<Incoming, String> {
        self.next_incoming()
            .await
            .map(|channel| Incoming::Legacy(channel, self.identity().clone()))
            .map_err(|e| e.to_string())
    }
    fn id(&self) -> NodeId {
        self.id()
    }
    async fn lookup(&self, topic: NodeId) -> Result<Vec<Member>, String> {
        self.lookup(topic)
            .await
            .map(|peers| {
                peers
                    .into_iter()
                    .map(|c| Member {
                        id: c.id,
                        contact: Some(c),
                    })
                    .collect()
            })
            .map_err(|e| e.to_string())
    }
    async fn announce(&self, topic: NodeId) -> Result<(), String> {
        self.announce(topic).await.map_err(|e| e.to_string())
    }
    async fn dial(&self, peer: NodeId) -> Result<Secure, String> {
        let conn = self
            .connect(peer)
            .await
            .map_err(|e| format!("connect: {e:?}"))?;
        let channel = conn
            .channel
            .ok_or_else(|| format!("no data channel (unreachable: {:?})", conn.outcome))?;
        let started = std::time::Instant::now();
        let result = NoiseLink::connect(channel, self.identity(), peer).await;
        self.emit_event(driver::NodeEvent::NoiseHandshake {
            peer,
            initiator: true,
            ok: result.is_ok(),
            dur_ms: started.elapsed().as_millis() as u64,
        });
        result
            .map(Secure::Legacy)
            .map_err(|e| format!("noise handshake: {e}"))
    }
}

struct NextInner {
    endpoint: transfer::next::Endpoint,
    seeds: Mutex<Vec<Contact>>,
    providers: Mutex<BTreeMap<NodeId, (PublicKey, u64)>>,
    listener: tokio::sync::Mutex<Option<transfer::next::Listener>>,
}

#[derive(Clone)]
pub struct NextNode {
    inner: Arc<NextInner>,
}

struct QueryGuard {
    node: driver::next::Node,
    query: u64,
}
impl Drop for QueryGuard {
    fn drop(&mut self) {
        let node = self.node.clone();
        let query = self.query;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = node.cancel_lookup(query).await;
            });
        }
    }
}

fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn io_error(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

impl NextNode {
    /// Bind a routing node for a helper/backbone. Applications normally use client role.
    pub async fn bind(address: SocketAddr, identity: crypto::Keypair) -> io::Result<Self> {
        Self::bind_with_role(address, identity, true).await
    }
    pub async fn bind_with_role(
        address: SocketAddr,
        identity: crypto::Keypair,
        server: bool,
    ) -> io::Result<Self> {
        let endpoint = transfer::next::Endpoint::bind(address, identity, server)
            .await
            .map_err(io_error)?;
        Ok(Self {
            inner: Arc::new(NextInner {
                endpoint,
                seeds: Mutex::new(vec![]),
                providers: Mutex::new(BTreeMap::new()),
                listener: tokio::sync::Mutex::new(None),
            }),
        })
    }
    pub fn id(&self) -> NodeId {
        self.inner.endpoint.dht().id()
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.endpoint.dht().local_addr()
    }
    pub fn contact(&self) -> Contact {
        Contact::new(self.id(), self.local_addr())
    }
    pub fn inbound_datagrams(&self) -> u64 {
        self.inner.endpoint.dht().inbound_datagrams()
    }
    pub fn endpoint(&self) -> &transfer::next::Endpoint {
        &self.inner.endpoint
    }
    fn seeds(&self) -> Vec<Contact> {
        self.inner.seeds.lock().expect("seeds").clone()
    }
    pub async fn add_contact(&self, peer: Contact) -> io::Result<()> {
        let mut seeds = self.inner.seeds.lock().expect("seeds");
        if peer.id != self.id() && !seeds.iter().any(|s| s.id == peer.id) && seeds.len() < 8 {
            seeds.push(peer);
        }
        Ok(())
    }
    pub async fn bootstrap(&self) -> io::Result<()> {
        self.query(self.id()).await.map(|_| ()).map_err(io_error)
    }
    pub async fn bootstrap_contacts(&self) -> io::Result<Vec<Contact>> {
        self.inner
            .endpoint
            .dht()
            .bootstrap_state()
            .await
            .map(|s| s.contacts().to_vec())
            .map_err(io_error)
    }
    async fn query(&self, topic: NodeId) -> Result<(Vec<Record>, Vec<Contact>), String> {
        let node = self.inner.endpoint.dht();
        let mut events = node.subscribe();
        let query = node
            .lookup(topic, &self.seeds())
            .await
            .map_err(|e| e.to_string())?;
        let _guard = QueryGuard {
            node: node.clone(),
            query,
        };
        tokio::time::timeout(Duration::from_secs(45), async {
            let mut records = Vec::new();
            loop {
                match events.recv().await.map_err(|e| e.to_string())? {
                    Notice::Dht(e) => match *e {
                        Event::Providers {
                            query: q,
                            records: found,
                        } if q == query => records.extend(found),
                        Event::LookupDone {
                            query: q,
                            closest,
                            timed_out,
                        } if q == query => {
                            if timed_out && records.is_empty() {
                                return Err("provider lookup timed out".to_string());
                            }
                            return Ok((records, closest));
                        }
                        Event::NetworkChanged(_) => return Err("network changed".to_string()),
                        _ => {}
                    },
                    Notice::Stopped => return Err("DHT stopped".to_string()),
                    Notice::IoError(_) => {}
                }
            }
        })
        .await
        .map_err(|_| "provider lookup deadline".to_string())?
    }
    pub async fn next_incoming(&self) -> io::Result<Secure> {
        self.listen().await?;
        let mut listener = self.inner.listener.lock().await;
        loop {
            match listener.as_mut().expect("listener").accept().await {
                Ok(link) => return Ok(Secure::Next(link)),
                Err(
                    error @ transfer::next::Error::Dht(
                        driver::next::Error::Closed | driver::next::Error::EventsLagged(_),
                    ),
                ) => {
                    *listener = None;
                    return Err(io_error(error));
                }
                Err(_) => continue,
            }
        }
    }
    pub async fn listen(&self) -> io::Result<()> {
        let mut listener = self.inner.listener.lock().await;
        if listener.is_none() {
            *listener = Some(
                self.inner
                    .endpoint
                    .listen(&self.seeds())
                    .await
                    .map_err(io_error)?,
            );
        }
        Ok(())
    }
    pub async fn shutdown(&self) -> io::Result<()> {
        self.inner.endpoint.dht().shutdown().await.map_err(io_error)
    }
    async fn pages(
        &self,
        topic: NodeId,
        closest: Vec<Contact>,
        records: &mut Vec<Record>,
    ) -> Result<(), String> {
        let node = self.inner.endpoint.dht();
        let mut events = node.subscribe();
        let mut pending = BTreeMap::new();
        for peer in closest.into_iter().take(20) {
            if let Ok(request) = node.providers_page(peer, topic, None).await {
                pending.insert(request, (peer, None, 0));
            }
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while !pending.is_empty() {
                match events.recv().await.map_err(|e| e.to_string())? {
                    Notice::Dht(e) => match *e {
                        Event::ProviderPage {
                            request,
                            records: found,
                            next,
                            ..
                        } => {
                            if let Some((peer, after, count)) = pending.remove(&request) {
                                records.extend(
                                    found
                                        .into_iter()
                                        .take(1024usize.saturating_sub(records.len())),
                                );
                                if let Some(next) =
                                    next.filter(|next| after.is_none_or(|a| *next > a))
                                {
                                    if count < 31 && records.len() < 1024 {
                                        if let Ok(request) =
                                            node.providers_page(peer, topic, Some(next)).await
                                        {
                                            pending.insert(request, (peer, Some(next), count + 1));
                                        }
                                    }
                                }
                            }
                        }
                        Event::RpcTimedOut(request) => {
                            pending.remove(&request);
                        }
                        Event::NetworkChanged(_) => return Err("network changed".into()),
                        _ => {}
                    },
                    Notice::Stopped => return Err("DHT stopped".into()),
                    _ => {}
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| "provider pagination deadline".to_string())?
    }
    /// Renew application topics in the background. Status exposes incomplete
    /// rounds, including remote registration quotas; startup never waits on them.
    pub async fn keep_announced<F>(&self, interval: Duration, topics: F) -> Announcer
    where
        F: Fn() -> Vec<NodeId> + Send + 'static,
    {
        let node = self.clone();
        let (status, receiver) = tokio::sync::watch::channel(AnnouncementStatus::default());
        let task = tokio::spawn(async move {
            loop {
                let mut round = AnnouncementStatus::default();
                for topic in topics() {
                    round.attempted += 1;
                    match node.announce(topic).await {
                        Ok(()) => round.acknowledged += 1,
                        Err(error) => round.last_error = Some(error),
                    }
                    status.send_replace(round.clone());
                }
                tokio::time::sleep(interval.max(Duration::from_millis(1))).await;
            }
        });
        Announcer {
            task,
            status: receiver,
        }
    }
    pub async fn announce(&self, topic: NodeId) -> Result<(), String> {
        Network::announce(self, topic).await
    }
    pub async fn lookup(&self, topic: NodeId) -> Result<Vec<Member>, String> {
        Network::lookup(self, topic).await
    }
}

impl Network for NextNode {
    async fn incoming(&self) -> Result<Incoming, String> {
        match self.next_incoming().await.map_err(|e| e.to_string())? {
            Secure::Next(link) => Ok(Incoming::Next(link)),
            Secure::Legacy(_) => unreachable!("v6 endpoint"),
        }
    }
    fn id(&self) -> NodeId {
        self.id()
    }
    async fn lookup(&self, topic: NodeId) -> Result<Vec<Member>, String> {
        let (mut records, closest) = self.query(topic).await?;
        self.pages(topic, closest, &mut records).await?;
        let now = unix();
        let mut keys = self.inner.providers.lock().expect("providers");
        keys.retain(|_, (_, expiry)| *expiry > now);
        let mut members = BTreeMap::new();
        for record in records {
            if record.topic != topic || !record.verify(now) {
                continue;
            }
            let id = dht_next::node_id(record.provider);
            if keys.len() >= 1024 && !keys.contains_key(&id) {
                continue;
            }
            keys.insert(id, (record.provider, record.expires));
            members.insert(id, Member { id, contact: None });
        }
        Ok(members.into_values().collect())
    }
    async fn announce(&self, topic: NodeId) -> Result<(), String> {
        let (_, closest) = self.query(topic).await?;
        let node = self.inner.endpoint.dht();
        let mut events = node.subscribe();
        let mut pending = Vec::new();
        for peer in closest.into_iter().take(3) {
            if node.register(peer, topic).await.is_ok() {
                pending.push(peer.id);
            }
        }
        if pending.is_empty() {
            return Err("no reachable registration coordinator".into());
        }
        tokio::time::timeout(Duration::from_secs(9), async {
            loop {
                match events.recv().await.map_err(|e| e.to_string())? {
                    Notice::Dht(e) => match *e {
                        Event::Registered(r)
                            if r.topic == topic
                                && r.provider == self.inner.endpoint.public_key()
                                && pending.contains(&r.coordinator.id) =>
                        {
                            return Ok(())
                        }
                        Event::NetworkChanged(_) => return Err("network changed".into()),
                        _ => {}
                    },
                    Notice::Stopped => return Err("DHT stopped".into()),
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "registration deadline".to_string())?
    }
    async fn dial(&self, peer: NodeId) -> Result<Secure, String> {
        let cached = self
            .inner
            .providers
            .lock()
            .expect("providers")
            .get(&peer)
            .copied()
            .filter(|(_, expiry)| *expiry > unix());
        let key = if let Some((key, _)) = cached {
            key
        } else {
            self.lookup(peer).await?;
            self.inner
                .providers
                .lock()
                .expect("providers")
                .get(&peer)
                .map(|(key, _)| *key)
                .ok_or_else(|| "no authenticated public key for provider".to_string())?
        };
        self.inner
            .endpoint
            .connect(key, &self.seeds())
            .await
            .map(Secure::Next)
            .map_err(|e| e.to_string())
    }
}

#[derive(Clone, Debug, Default)]
pub struct AnnouncementStatus {
    pub attempted: usize,
    pub acknowledged: usize,
    pub last_error: Option<String>,
}
pub struct Announcer {
    task: tokio::task::JoinHandle<()>,
    status: tokio::sync::watch::Receiver<AnnouncementStatus>,
}
impl Announcer {
    pub fn status(&self) -> tokio::sync::watch::Receiver<AnnouncementStatus> {
        self.status.clone()
    }
}
impl Drop for Announcer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
