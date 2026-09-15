//! Independent regional discovery with optional global discovery and signaling.
use crate::network::{Announcer, Incoming, Member, Network, NextNode, Secure};
use driver::next::{BootstrapState, OverlayId};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use swarm::{Contact, NodeId};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

struct IncomingQueues {
    receivers: Vec<mpsc::Receiver<Incoming>>,
    cursor: usize,
}

struct Inner {
    regional: NextNode,
    global: Option<NextNode>,
    community_node: Option<NextNode>,
    community: Option<crate::community::Community>,
    additional: Vec<NextNode>,
    publication: Vec<mpsc::Sender<NodeId>>,
    tasks: std::sync::Mutex<Vec<JoinHandle<()>>>,
    incoming: Mutex<Option<IncomingQueues>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().expect("tasks") {
            task.abort();
        }
    }
}

/// Endpoints use the same identity but independent sockets, routing tables,
/// coordinator leases, caches, and request budgets. Region membership is configured,
/// not inferred from IP geolocation and not an authorization boundary.
/// Initialize `listen()` before starting a single `Network::incoming` accept loop;
/// concurrent accepts and listen calls serialize behind a pending accept.
#[derive(Clone)]
pub struct RegionalNode {
    inner: Arc<Inner>,
}

impl RegionalNode {
    pub async fn bind(
        regional_address: SocketAddr,
        global_address: Option<SocketAddr>,
        identity: crypto::Keypair,
        server: bool,
        region: OverlayId,
    ) -> io::Result<Self> {
        Self::bind_overlays(
            regional_address,
            global_address,
            identity,
            server,
            region,
            None,
            None,
        )
        .await
    }

    /// Language selects the community. A separately supplied connectivity domain
    /// enables independent local discovery, with its own socket and bootstrap peers.
    pub async fn bind_community(
        local_address: SocketAddr,
        community_address: Option<SocketAddr>,
        global_address: Option<SocketAddr>,
        identity: crypto::Keypair,
        server: bool,
        community: &crate::community::Community,
        connectivity_domain: Option<&crate::community::ConnectivityDomain>,
    ) -> io::Result<Self> {
        let region = match connectivity_domain {
            Some(domain) => {
                if community_address.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "local domain requires a separate community socket",
                    ));
                }
                community.local_overlay(domain.label())?
            }
            None => {
                if community_address.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "community socket duplicates primary overlay",
                    ));
                }
                community.overlay()
            }
        };
        Self::bind_overlays(
            local_address,
            global_address,
            identity,
            server,
            region,
            Some((community.clone(), community_address)),
            connectivity_domain.map(|domain| domain.address_filter()),
        )
        .await
    }

    async fn bind_overlays(
        regional_address: SocketAddr,
        global_address: Option<SocketAddr>,
        identity: crypto::Keypair,
        server: bool,
        region: OverlayId,
        community: Option<(crate::community::Community, Option<SocketAddr>)>,
        address_filter: Option<driver::next::AddressFilter>,
    ) -> io::Result<Self> {
        if region == OverlayId::Global {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected regional overlay",
            ));
        }
        let regional = NextNode::bind_filtered(
            regional_address,
            identity.clone(),
            server,
            region,
            address_filter.unwrap_or_else(|| Arc::new(|_| true)),
        );
        let community_node = async {
            match &community {
                Some((selection, Some(address))) => NextNode::bind_in_overlay(
                    *address,
                    identity.clone(),
                    server,
                    selection.overlay(),
                )
                .await
                .map(Some),
                _ => Ok(None),
            }
        };
        let global = async {
            match global_address {
                Some(address) => NextNode::bind_with_role(address, identity.clone(), server)
                    .await
                    .map(Some),
                None => Ok(None),
            }
        };
        let (regional, community_node, global) =
            tokio::try_join!(regional, community_node, global)?;
        Self::assemble(
            regional,
            global,
            community_node,
            community.map(|(selection, _)| selection),
            vec![],
        )
    }

    /// Combine already-bound endpoints for one application session. Each overlay
    /// has one socket and routing table; all endpoints must use the same identity.
    /// The cap permits a home language, three invited languages, and global discovery.
    pub fn from_endpoints(primary: NextNode, additional: Vec<NextNode>) -> io::Result<Self> {
        if additional.len() > 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many discovery overlays",
            ));
        }
        let mut scopes = std::collections::BTreeSet::new();
        for node in std::iter::once(&primary).chain(additional.iter()) {
            if node.id() != primary.id() || !scopes.insert(node.endpoint().dht().overlay()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate overlay or mismatched identity",
                ));
            }
        }
        Self::assemble(primary, None, None, None, additional)
    }

    fn assemble(
        regional: NextNode,
        global: Option<NextNode>,
        community_node: Option<NextNode>,
        community: Option<crate::community::Community>,
        additional: Vec<NextNode>,
    ) -> io::Result<Self> {
        let mut tasks = vec![];
        let publication = community_node.iter().chain(global.iter()).chain(additional.iter()).map(|global| {
            let global = global.clone();
            let (sender, mut receiver) = mpsc::channel(32);
            tasks.push(tokio::spawn(async move {
                let mut pending = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        topic = receiver.recv(), if pending.len() < 4 => {
                            let Some(topic) = topic else { break };
                            let node = global.clone();
                            pending.spawn(async move {
                                let _ = tokio::time::timeout(Duration::from_secs(15), node.announce(topic)).await;
                            });
                        }
                        _ = pending.join_next(), if !pending.is_empty() => {}
                    }
                }
            }));
            sender
        }).collect();
        Ok(Self {
            inner: Arc::new(Inner {
                regional,
                global,
                community_node,
                community,
                additional,
                publication,
                tasks: std::sync::Mutex::new(tasks),
                incoming: Mutex::new(None),
            }),
        })
    }

    pub fn regional(&self) -> &NextNode {
        &self.inner.regional
    }
    pub fn global(&self) -> Option<&NextNode> {
        self.inner.global.as_ref()
    }
    pub fn community(&self) -> Option<&crate::community::Community> {
        self.inner.community.as_ref()
    }
    pub fn community_endpoint(&self) -> Option<&NextNode> {
        self.inner
            .community_node
            .as_ref()
            .or_else(|| self.community().map(|_| self.regional()))
    }
    fn extras(&self) -> impl Iterator<Item = &NextNode> {
        self.inner
            .community_node
            .iter()
            .chain(self.inner.global.iter())
            .chain(self.inner.additional.iter())
    }
    pub fn nodes(&self) -> impl Iterator<Item = &NextNode> {
        std::iter::once(self.regional()).chain(self.extras())
    }
    pub fn overlay(&self) -> OverlayId {
        self.regional().endpoint().dht().overlay()
    }
    pub fn id(&self) -> NodeId {
        self.regional().id()
    }

    pub async fn add_contact(&self, overlay: OverlayId, contact: Contact) -> io::Result<()> {
        self.node(overlay)?.add_contact(contact).await
    }
    pub fn supports_overlay(&self, overlay: OverlayId) -> bool {
        self.node(overlay).is_ok()
    }
    pub fn node(&self, overlay: OverlayId) -> io::Result<&NextNode> {
        if let Some(node) = self
            .nodes()
            .find(|node| node.endpoint().dht().overlay() == overlay)
        {
            return Ok(node);
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "overlay is not configured",
        ))
    }

    /// Restores hints into exactly one overlay and waits for its bootstrap lookup.
    /// Loading a regional snapshot never requires a working global endpoint.
    pub async fn restore_bootstrap(&self, state: &BootstrapState) -> io::Result<()> {
        self.node(state.overlay())?.restore_bootstrap(state).await
    }

    pub async fn bootstrap_state(&self, overlay: OverlayId) -> io::Result<BootstrapState> {
        self.node(overlay)?
            .endpoint()
            .dht()
            .bootstrap_state()
            .await
            .map_err(io::Error::other)
    }

    /// Start primary listening before returning. Secondary listening/recovery runs
    /// independently, with separate accept tasks so cancellation cannot drop the
    /// other overlay's in-progress handshake.
    /// Initialize before starting the single accept loop. A pending `incoming()`
    /// holds the queue lock, so concurrent `listen()` calls wait for that accept.
    pub async fn listen(&self) -> io::Result<()> {
        let mut incoming = self.inner.incoming.lock().await;
        if incoming.is_some() {
            return Ok(());
        }
        if self.inner.additional.is_empty() {
            self.regional().listen().await?;
        }
        let mut queues = IncomingQueues {
            receivers: vec![],
            cursor: 0,
        };
        for node in self.nodes() {
            let node = node.clone();
            let (sender, receiver) = mpsc::channel(32);
            queues.receivers.push(receiver);
            let task = tokio::spawn(async move {
                loop {
                    match node.incoming().await {
                        Ok(link) => {
                            if sender.send(link).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => {
                            if sender.is_closed() {
                                break;
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
            self.inner.tasks.lock().expect("tasks").push(task);
        }
        *incoming = Some(queues);
        Ok(())
    }

    /// Renew the primary and global overlays (legacy two-overlay API).
    /// Community deployments should use `keep_announced_all` to renew all three.
    /// Retain the returned handles for as long as publication is wanted.
    pub async fn keep_announced<F>(
        &self,
        interval: Duration,
        topics: F,
    ) -> (Announcer, Option<Announcer>)
    where
        F: Fn() -> Vec<NodeId> + Send + Sync + 'static,
    {
        let topics = Arc::new(topics);
        let local_topics = topics.clone();
        let regional = self
            .regional()
            .keep_announced(interval, move || local_topics())
            .await;
        let global = match self.global() {
            Some(global) => Some(global.keep_announced(interval, move || topics()).await),
            None => None,
        };
        (regional, global)
    }

    /// Independent renewal/status handles for every configured overlay, including
    /// the shared language community when a separate local domain is configured.
    pub async fn keep_announced_all<F>(
        &self,
        interval: Duration,
        topics: F,
    ) -> Vec<(OverlayId, Announcer)>
    where
        F: Fn() -> Vec<NodeId> + Send + Sync + 'static,
    {
        let topics = Arc::new(topics);
        let mut handles = vec![];
        for node in self.nodes() {
            let topics = topics.clone();
            handles.push((
                node.endpoint().dht().overlay(),
                node.keep_announced(interval, move || topics()).await,
            ));
        }
        handles
    }

    /// Explicit primary/global discovery (legacy two-overlay API).
    /// Use `lookup_all_overlays` to include a separate language community.
    pub async fn lookup_all(
        &self,
        topic: NodeId,
    ) -> (
        Result<Vec<Member>, String>,
        Option<Result<Vec<Member>, String>>,
    ) {
        tokio::join!(self.regional().lookup(topic), async {
            match self.global() {
                Some(global) => Some(global.lookup(topic).await),
                None => None,
            }
        })
    }

    /// Query every overlay concurrently, preserving its identity and result.
    pub async fn lookup_all_overlays(
        &self,
        topic: NodeId,
    ) -> Vec<(OverlayId, Result<Vec<Member>, String>)> {
        let mut pending = tokio::task::JoinSet::new();
        for node in self.nodes() {
            let node = node.clone();
            pending
                .spawn(async move { (node.endpoint().dht().overlay(), node.lookup(topic).await) });
        }
        let mut results = vec![];
        while let Some(result) = pending.join_next().await {
            if let Ok(result) = result {
                results.push(result);
            }
        }
        results.sort_by_key(|(overlay, _)| *overlay);
        results
    }

    pub async fn shutdown(&self) -> io::Result<()> {
        for task in self.inner.tasks.lock().expect("tasks").drain(..) {
            task.abort();
        }
        let mut pending = tokio::task::JoinSet::new();
        for node in self.nodes() {
            let node = node.clone();
            pending.spawn(async move { node.shutdown().await });
        }
        let mut error = None;
        while let Some(result) = pending.join_next().await {
            if let Err(failure) = result.map_err(io::Error::other).and_then(|r| r) {
                error = Some(failure);
            }
        }
        error.map_or(Ok(()), Err)
    }
}

/// First useful result wins; an empty lookup or error cannot mask the other
/// overlay's success. Dropping the losing future cancels its outstanding lookup.
async fn first_success<T>(
    regional: impl Future<Output = Result<T, String>>,
    global: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::pin!(regional, global);
    tokio::select! {
        biased;
        result = &mut regional => match result {
            Ok(value) => Ok(value),
            Err(local) => global.await.map_err(|remote| format!("regional: {local}; global: {remote}")),
        },
        result = &mut global => match result {
            Ok(value) => Ok(value),
            Err(remote) => regional.await.map_err(|local| format!("regional: {local}; global: {remote}")),
        },
    }
}

async fn first_providers(
    regional: impl Future<Output = Result<Vec<Member>, String>>,
    global: impl Future<Output = Result<Vec<Member>, String>>,
) -> Result<Vec<Member>, String> {
    tokio::pin!(regional, global);
    let (first, second) = tokio::select! {
        biased;
        result = &mut regional => {
            if result.as_ref().is_ok_and(|members| !members.is_empty()) { return result; }
            (result, global.await)
        },
        result = &mut global => {
            if result.as_ref().is_ok_and(|members| !members.is_empty()) { return result; }
            (result, regional.await)
        },
    };
    match (first, second) {
        (_, Ok(members)) => Ok(members),
        (Ok(members), Err(_)) => Ok(members),
        (Err(first), Err(second)) => Err(format!("both overlays failed: {first}; {second}")),
    }
}

async fn lookup_extras(nodes: Vec<NextNode>, topic: NodeId) -> Result<Vec<Member>, String> {
    let mut pending = tokio::task::JoinSet::new();
    for node in nodes {
        pending.spawn(async move { node.lookup(topic).await });
    }
    let mut empty = false;
    let mut errors = vec![];
    while let Some(result) = pending.join_next().await {
        match result.map_err(|e| e.to_string()).and_then(|r| r) {
            Ok(members) if !members.is_empty() => return Ok(members),
            Ok(_) => empty = true,
            Err(error) => errors.push(error),
        }
    }
    if empty {
        Ok(vec![])
    } else {
        Err(format!("no secondary providers: {}", errors.join("; ")))
    }
}
async fn dial_extras(nodes: Vec<NextNode>, peer: NodeId) -> Result<Secure, String> {
    let mut pending = tokio::task::JoinSet::new();
    for node in nodes {
        pending.spawn(async move { Box::pin(node.dial(peer)).await });
    }
    let mut errors = vec![];
    while let Some(result) = pending.join_next().await {
        match result.map_err(|e| e.to_string()).and_then(|r| r) {
            Ok(link) => return Ok(link),
            Err(error) => errors.push(error),
        }
    }
    Err(format!("no secondary connection: {}", errors.join("; ")))
}

impl Network for RegionalNode {
    fn id(&self) -> NodeId {
        self.id()
    }
    async fn lookup(&self, topic: NodeId) -> Result<Vec<Member>, String> {
        first_providers(
            Box::pin(self.regional().lookup(topic)),
            lookup_extras(self.extras().cloned().collect(), topic),
        )
        .await
    }
    /// Success means a regional registration was acknowledged. Global publication
    /// is best effort through a bounded background queue; use keep_announced for
    /// sustained publication and per-overlay acknowledgement status.
    async fn announce(&self, topic: NodeId) -> Result<(), String> {
        for sender in &self.inner.publication {
            let _ = sender.try_send(topic);
        }
        self.regional().announce(topic).await
    }
    async fn dial(&self, peer: NodeId) -> Result<Secure, String> {
        first_success(
            Box::pin(self.regional().dial(peer)),
            dial_extras(self.extras().cloned().collect(), peer),
        )
        .await
    }
    /// Use one accept loop per node. Concurrent accepts are serialized; cancellation
    /// releases the queue lock without consuming a connection.
    async fn incoming(&self) -> Result<Incoming, String> {
        self.listen().await.map_err(|e| e.to_string())?;
        let mut incoming = self.inner.incoming.lock().await;
        let queues = incoming.as_mut().expect("listener");
        std::future::poll_fn(|cx| {
            let count = queues.receivers.len();
            let mut closed = 0;
            for offset in 0..count {
                let index = (queues.cursor + offset) % count;
                match queues.receivers[index].poll_recv(cx) {
                    std::task::Poll::Ready(Some(link)) => {
                        queues.cursor = (index + 1) % count;
                        return std::task::Poll::Ready(Ok(link));
                    }
                    std::task::Poll::Ready(None) => closed += 1,
                    std::task::Poll::Pending => {}
                }
            }
            if closed == count {
                std::task::Poll::Ready(Err("regional listener stopped".into()))
            } else {
                std::task::Poll::Pending
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stalled_or_failed_overlay_does_not_delay_the_other() {
        let local = first_success(async { Ok(7) }, std::future::pending());
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), local)
                .await
                .unwrap(),
            Ok(7)
        );
        assert_eq!(
            first_success(async { Err("local".into()) }, async { Ok(8) }).await,
            Ok(8)
        );
        assert_eq!(
            first_success(async { Ok(9) }, async { Err("global".into()) }).await,
            Ok(9)
        );
        assert!(first_success::<()>(async { Err("local".into()) }, async {
            Err("global".into())
        })
        .await
        .unwrap_err()
        .contains("global"));
    }
}
