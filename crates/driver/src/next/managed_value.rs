//! Opt-in, bounded publication of application-owned values. Storage is still
//! best effort: acknowledgements are claims, not proofs of durable replication.
use super::*;
use dht_next::{MutableValue, Value, VALUE_TTL_SECS};
use std::collections::BTreeSet;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
pub struct ValuePublicationConfig {
    pub repair_interval: Duration,
    /// Nominal audit interval, randomized by ±20% and capped by the next refresh.
    pub audit_interval: Duration,
    pub cycle_timeout: Duration,
    pub renew_before: Duration,
}
impl Default for ValuePublicationConfig {
    fn default() -> Self {
        Self {
            repair_interval: Duration::from_secs(300),
            audit_interval: Duration::from_secs(60),
            cycle_timeout: Duration::from_secs(60),
            renew_before: Duration::from_secs(900),
        }
    }
}
#[derive(Clone, Debug)]
pub struct ValuePublicationStatus {
    /// Persist this signed value when publishing mutable data across restarts.
    pub value: Value,
    /// Write claims from the latest completed cycle; may include failed readbacks.
    pub acknowledged: Vec<Contact>,
    /// Exact validated readbacks during the latest completed cycle, not durability proofs.
    pub verified: Vec<Contact>,
    /// Distinct IPv4 /24 or IPv6 /64 networks among verified copies.
    pub verified_networks: usize,
    /// Peers temporarily excluded after failed RPCs or write/readback attempts.
    pub backed_off: Vec<Contact>,
    /// Completed audit cycles, included in `rounds`.
    pub audits: u64,
    pub rounds: u64,
    pub last_error: Option<String>,
    /// A newer value or an equal-sequence fork was observed. No more writes run.
    pub conflicted: bool,
}
pub struct ManagedValue {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    status: watch::Receiver<ValuePublicationStatus>,
}
impl Drop for ManagedValue {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
impl ManagedValue {
    pub fn status(&self) -> watch::Receiver<ValuePublicationStatus> {
        self.status.clone()
    }
    /// Stop repair/renewal. Remote copies expire under their original leases.
    pub async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
struct Slot {
    keys: Arc<Mutex<BTreeSet<NodeId>>>,
    key: NodeId,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.keys.lock().expect("managed values").remove(&self.key);
    }
}
impl Node {
    /// Maintain three readback-verified replicas, rediscovering holders each cycle.
    /// Mutable values require their publisher's signing key for lease renewal.
    /// At most sixteen distinct keys can be managed by one node. The handle owns
    /// the task; dropping it stops further work without revoking remote copies.
    pub fn publish_value(
        &self,
        value: Value,
        signer: Option<Keypair>,
        seeds: &[Contact],
        config: ValuePublicationConfig,
    ) -> Result<ManagedValue, Error> {
        let now = time(Instant::now());
        if seeds.len() > 8
            || seeds.iter().any(|c| {
                c.id == self.id()
                    || c.addr.port() == 0
                    || c.addr.ip().is_unspecified()
                    || c.addr.ip().is_multicast()
            })
            || !value.verify(now)
            || config.repair_interval < Duration::from_millis(50)
            || config.repair_interval > Duration::from_secs(600)
            || config.audit_interval < Duration::from_millis(50)
            || config.audit_interval > Duration::from_secs(600)
            || config.cycle_timeout < Duration::from_secs(1)
            || config.cycle_timeout > Duration::from_secs(120)
            || config.renew_before < Duration::from_secs(1)
            || config.renew_before > Duration::from_secs(VALUE_TTL_SECS / 2)
            || matches!(&value, Value::Mutable(v) if signer.as_ref().is_none_or(|key| key.public() != v.publisher))
        {
            return Err(Error::Core(dht_next::Error::Invalid));
        }
        let key = value.key();
        let keys = self.inner.managed_values.clone();
        {
            let mut occupied = keys.lock().expect("managed values");
            if occupied.len() >= 16 || !occupied.insert(key) {
                return Err(Error::Core(dht_next::Error::Capacity));
            }
        }
        let slot = Slot { keys, key };
        let node = self.clone();
        let seeds = seeds.to_vec();
        let (stop, stopped) = oneshot::channel();
        let (status, receiver) = watch::channel(ValuePublicationStatus {
            value: value.clone(),
            acknowledged: vec![],
            verified: vec![],
            verified_networks: 0,
            backed_off: vec![],
            audits: 0,
            rounds: 0,
            last_error: None,
            conflicted: false,
        });
        let task = tokio::spawn(async move {
            let _slot = slot;
            let mut value = value;
            let mut network = node.network();
            let mut backoff = FailureBackoff::default();
            let mut holders = Vec::new();
            let mut refresh_at = tokio::time::Instant::now();
            let mut capacity_delay = Duration::from_secs(1);
            let mut generation = network.borrow().generation;
            let work = async {
                loop {
                    let current_generation = network.borrow_and_update().generation;
                    if current_generation != generation {
                        backoff.entries.clear();
                        capacity_delay = Duration::from_secs(1);
                        refresh_at = tokio::time::Instant::now();
                        generation = current_generation;
                    }
                    let refresh = tokio::time::Instant::now() >= refresh_at;
                    let outcome = tokio::time::timeout(
                        config.cycle_timeout,
                        node.repair_value(
                            &mut value,
                            signer.as_ref(),
                            &seeds,
                            RepairPolicy {
                                renew_before: config.renew_before,
                                refresh,
                                holders: &holders,
                            },
                            &status,
                            &mut backoff,
                        ),
                    )
                    .await
                    .unwrap_or(Err(Error::TimedOut));
                    let capacity_limited =
                        matches!(outcome, Err(Error::Core(dht_next::Error::Capacity)));
                    let retry_delay = if capacity_limited {
                        let delay = audit_delay(capacity_delay).min(Duration::from_secs(30));
                        capacity_delay = (capacity_delay * 2).min(Duration::from_secs(30));
                        Some(delay)
                    } else {
                        capacity_delay = Duration::from_secs(1);
                        None
                    };
                    if refresh && !capacity_limited {
                        refresh_at = tokio::time::Instant::now() + config.repair_interval;
                    }
                    if let Ok(result) = &outcome {
                        let mut remembered = result.verified.clone();
                        for peer in &holders {
                            if remembered.len() == 3 {
                                break;
                            }
                            if !remembered.iter().any(|candidate| candidate.id == peer.id) {
                                remembered.push(*peer);
                            }
                        }
                        holders = remembered;
                    }
                    let conflict = matches!(outcome, Err(Error::ConflictingValues));
                    let closed = matches!(outcome, Err(Error::Closed));
                    status.send_modify(|state| {
                        state.value = value.clone();
                        state.rounds = state.rounds.saturating_add(1);
                        state.conflicted = conflict;
                        state.backed_off = backoff.active(tokio::time::Instant::now());
                        state.audits = state.audits.saturating_add(u64::from(!refresh));
                        match &outcome {
                            Ok(holders) => {
                                state.acknowledged = holders.acknowledged.clone();
                                state.verified = holders.verified.clone();
                                state.verified_networks =
                                    dht_next::distinct_networks(&state.verified);
                                state.last_error = (holders.verified.len() < 3).then(|| {
                                    "fewer than three replicas passed readback this cycle".into()
                                });
                            }
                            Err(error) => {
                                state.acknowledged.clear();
                                state.verified.clear();
                                state.verified_networks = 0;
                                state.last_error = Some(error.to_string());
                            }
                        }
                    });
                    if conflict || closed {
                        break;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay.unwrap_or_else(|| audit_delay(config.audit_interval).min(refresh_at.saturating_duration_since(tokio::time::Instant::now())))) => {},
                        _ = network.changed() => {},
                    }
                }
            };
            tokio::select! {
                _ = work => {},
                _ = stopped => {},
                _ = node.inner.commands.closed() => {},
            }
        });
        Ok(ManagedValue {
            stop: Some(stop),
            task: Some(task),
            status: receiver,
        })
    }

    async fn repair_value(
        &self,
        value: &mut Value,
        signer: Option<&Keypair>,
        seeds: &[Contact],
        policy: RepairPolicy<'_>,
        status: &watch::Sender<ValuePublicationStatus>,
        backoff: &mut FailureBackoff,
    ) -> Result<RoundResult, Error> {
        let mut events = self.subscribe();
        let closest = {
            let work = PendingValueWork::new(self).await?;
            let query = work.lookup(self, value.key(), seeds).await?;
            loop {
                if let Event::LookupDone {
                    query: id, closest, ..
                } = next_event(&mut events).await?
                {
                    if id == query {
                        break closest;
                    }
                }
            }
        };
        let candidates = publication_candidates(&closest, policy.holders);
        if candidates.is_empty() {
            return Err(Error::NoPeers);
        }
        let mut observed = self
            .preflight_values(value, &candidates, &mut events, backoff)
            .await?;
        if policy.refresh {
            observed.retain(|(peer, _)| closest.iter().take(20).any(|c| c.id == peer.id));
        }
        // Renew once, retain those exact signed bytes across failed writes and
        // retries, and expose them in status for the caller's restart storage.
        if let Value::Mutable(old) = value {
            let now = time(Instant::now());
            if old.expires <= now.unix_secs.saturating_add(policy.renew_before.as_secs()) {
                **old = MutableValue::sign(
                    signer.ok_or(Error::Core(dht_next::Error::Invalid))?,
                    old.salt.clone(),
                    old.sequence
                        .checked_add(1)
                        .ok_or(Error::Core(dht_next::Error::Invalid))?,
                    old.value.clone(),
                    now.unix_secs.saturating_add(VALUE_TTL_SECS),
                )
                .map_err(Error::Core)?;
            }
        }
        status.send_modify(|state| {
            if state.value != *value {
                state.acknowledged.clear();
                state.verified.clear();
                state.verified_networks = 0;
            }
            state.value = value.clone();
        });
        let mut result = RoundResult::default();
        if !policy.refresh {
            let mut existing: Vec<_> = observed
                .iter()
                .filter(|(_, remote)| remote.as_ref() == Some(value))
                .map(|(peer, _)| *peer)
                .collect();
            while let Some(peer) = dht_next::select_diverse_contact(&existing, &result.verified) {
                existing.retain(|candidate| *candidate != peer);
                backoff.succeeded(peer.id);
                result.verified.push(peer);
                if result.verified.len() == 3 {
                    return Ok(result);
                }
            }
            observed.retain(|(_, remote)| remote.as_ref() != Some(value));
        }
        while !observed.is_empty() {
            let candidates: Vec<_> = observed.iter().map(|(peer, _)| *peer).collect();
            let peer = dht_next::select_diverse_contact(&candidates, &result.verified)
                .expect("nonempty candidates");
            let index = observed
                .iter()
                .position(|(candidate, _)| *candidate == peer)
                .unwrap();
            let (peer, remote) = observed.remove(index);
            let cas = match remote {
                Some(Value::Mutable(remote)) => Some(remote.sequence),
                _ => None,
            };
            if self
                .write_publication_value(peer, value.clone(), cas, &mut events)
                .await?
            {
                result.acknowledged.push(peer);
            }
            if result.acknowledged.last() == Some(&peer) {
                match self
                    .read_publication_value(peer, value.key(), &mut events)
                    .await
                {
                    Ok(remote) => {
                        check_remote(value, remote.as_ref())?;
                        if remote.as_ref() == Some(value) {
                            result.verified.push(peer);
                        }
                    }
                    Err(Error::TimedOut) => {}
                    Err(error) => return Err(error),
                }
            }
            if result.verified.last() == Some(&peer) {
                backoff.succeeded(peer.id);
            } else {
                backoff.failed(peer, tokio::time::Instant::now());
            }
            if result.verified.len() == 3 {
                break;
            }
        }
        Ok(result)
    }
    async fn preflight_values(
        &self,
        value: &Value,
        candidates: &[Contact],
        events: &mut broadcast::Receiver<Notice>,
        backoff: &mut FailureBackoff,
    ) -> Result<Vec<(Contact, Option<Value>)>, Error> {
        let reads = PendingValueWork::new(self).await?;
        let mut remaining = candidates.iter().copied().take(23).enumerate();
        let mut pending = std::collections::BTreeMap::new();
        let mut observed = Vec::new();
        loop {
            while pending.len() < 3 {
                let Some((rank, peer)) = remaining.next() else {
                    break;
                };
                if backoff.blocked(peer.id, tokio::time::Instant::now()) {
                    continue;
                }
                let request = reads.get(self, peer, value.key()).await?;
                pending.insert(request, (rank, peer));
            }
            if pending.is_empty() {
                break;
            }
            match next_event(events).await? {
                Event::Value {
                    request,
                    value: remote,
                    ..
                } => {
                    if let Some((rank, peer)) = pending.remove(&request) {
                        check_remote(value, remote.as_ref())?;
                        observed.push((rank, peer, remote));
                    }
                }
                Event::RpcTimedOut(request) => {
                    if let Some((_, peer)) = pending.remove(&request) {
                        backoff.failed(peer, tokio::time::Instant::now());
                    }
                }
                _ => {}
            }
        }
        observed.sort_by_key(|(rank, _, _)| *rank);
        Ok(observed
            .into_iter()
            .map(|(_, peer, remote)| (peer, remote))
            .collect())
    }

    async fn write_publication_value(
        &self,
        peer: Contact,
        value: Value,
        cas: Option<u64>,
        events: &mut broadcast::Receiver<Notice>,
    ) -> Result<bool, Error> {
        let write = PendingValueWork::new(self).await?;
        let request = write.put(self, peer, value, cas).await?;
        loop {
            match next_event(events).await? {
                Event::ValueStored {
                    request: id,
                    stored,
                    ..
                } if id == request => return Ok(stored),
                Event::RpcTimedOut(id) if id == request => return Ok(false),
                _ => {}
            }
        }
    }

    async fn read_publication_value(
        &self,
        peer: Contact,
        key: NodeId,
        events: &mut broadcast::Receiver<Notice>,
    ) -> Result<Option<Value>, Error> {
        let reads = PendingValueWork::new(self).await?;
        let request = reads.get(self, peer, key).await?;
        loop {
            match next_event(events).await? {
                Event::Value {
                    request: id, value, ..
                } if id == request => return Ok(value),
                Event::RpcTimedOut(id) if id == request => return Err(Error::TimedOut),
                _ => {}
            }
        }
    }
}
struct PendingValueWork {
    cleanup: Option<mpsc::OwnedPermit<Command>>,
    requests: Arc<Mutex<Vec<[u8; 32]>>>,
    writes: Arc<Mutex<Vec<[u8; 32]>>>,
    queries: Arc<Mutex<Vec<u64>>>,
}
impl PendingValueWork {
    async fn new(node: &Node) -> Result<Self, Error> {
        let cleanup = node
            .inner
            .commands
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| Error::Closed)?;
        Ok(Self {
            cleanup: Some(cleanup),
            requests: Arc::new(Mutex::new(Vec::new())),
            writes: Arc::new(Mutex::new(Vec::new())),
            queries: Arc::new(Mutex::new(Vec::new())),
        })
    }
    async fn lookup(&self, node: &Node, key: NodeId, seeds: &[Contact]) -> Result<u64, Error> {
        let queries = self.queries.clone();
        let seeds: Vec<_> = seeds
            .iter()
            .copied()
            .take(dht_next::MAX_CANDIDATES)
            .collect();
        node.apply(move |core, now| {
            let (query, actions) = core.lookup(key, &seeds, now)?;
            queries.lock().expect("pending value lookups").push(query);
            Ok((query, actions))
        })
        .await
    }
    async fn put(
        &self,
        node: &Node,
        peer: Contact,
        value: Value,
        cas: Option<u64>,
    ) -> Result<[u8; 32], Error> {
        let writes = self.writes.clone();
        node.apply(move |core, now| {
            let (request, actions) = core.put_value(peer, value, cas, now)?;
            writes.lock().expect("pending value writes").push(request);
            Ok((request, actions))
        })
        .await
    }
    async fn get(&self, node: &Node, peer: Contact, key: NodeId) -> Result<[u8; 32], Error> {
        let requests = self.requests.clone();
        node.apply(move |core, now| {
            let (request, actions) = core.get_value(peer, key, now)?;
            requests.lock().expect("pending value reads").push(request);
            Ok((request, actions))
        })
        .await
    }
}
impl Drop for PendingValueWork {
    fn drop(&mut self) {
        let requests = self.requests.clone();
        let writes = self.writes.clone();
        let queries = self.queries.clone();
        if let Some(cleanup) = self.cleanup.take() {
            cleanup.send(Command::Apply(Box::new(move |core, _| {
                for query in queries.lock().expect("pending value lookups").drain(..) {
                    core.cancel_lookup(query);
                }
                for request in writes.lock().expect("pending value writes").drain(..) {
                    core.cancel_value_write(request);
                }
                for request in requests.lock().expect("pending value reads").drain(..) {
                    core.cancel_value_read(request);
                }
                vec![]
            })));
        }
    }
}
struct RepairPolicy<'a> {
    renew_before: Duration,
    refresh: bool,
    holders: &'a [Contact],
}
fn publication_candidates(closest: &[Contact], holders: &[Contact]) -> Vec<Contact> {
    let mut candidates: Vec<_> = closest.iter().copied().take(20).collect();
    for holder in holders.iter().take(3) {
        if !candidates.iter().any(|candidate| candidate.id == holder.id) {
            candidates.push(*holder);
        }
    }
    candidates
}
#[derive(Default)]
struct FailureBackoff {
    entries: std::collections::BTreeMap<NodeId, BackoffEntry>,
}
struct BackoffEntry {
    contact: Contact,
    failures: u8,
    until: tokio::time::Instant,
}
impl FailureBackoff {
    fn blocked(&self, id: NodeId, now: tokio::time::Instant) -> bool {
        self.entries.get(&id).is_some_and(|entry| entry.until > now)
    }
    fn failed(&mut self, contact: Contact, now: tokio::time::Instant) {
        if !self.entries.contains_key(&contact.id) && self.entries.len() == 64 {
            let oldest = *self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.until)
                .unwrap()
                .0;
            self.entries.remove(&oldest);
        }
        let failures = self
            .entries
            .get(&contact.id)
            .map_or(1, |entry| entry.failures.saturating_add(1));
        let delay = (30u64 << failures.saturating_sub(1).min(4)).min(300);
        self.entries.insert(
            contact.id,
            BackoffEntry {
                contact,
                failures,
                until: now + Duration::from_secs(delay),
            },
        );
    }
    fn succeeded(&mut self, id: NodeId) {
        self.entries.remove(&id);
    }
    fn active(&self, now: tokio::time::Instant) -> Vec<Contact> {
        self.entries
            .values()
            .filter(|entry| entry.until > now)
            .map(|entry| entry.contact)
            .collect()
    }
}
#[derive(Default)]
struct RoundResult {
    acknowledged: Vec<Contact>,
    verified: Vec<Contact>,
}
fn audit_delay(interval: Duration) -> Duration {
    let entropy = Keypair::generate().seed();
    let fraction = u64::from_le_bytes(entropy[..8].try_into().unwrap()) % 401;
    interval.mul_f64((800 + fraction) as f64 / 1000.0)
}
fn check_remote(local: &Value, remote: Option<&Value>) -> Result<(), Error> {
    if let (Value::Mutable(local), Some(Value::Mutable(remote))) = (local, remote) {
        if remote.sequence > local.sequence
            || (remote.sequence == local.sequence && remote != local)
        {
            return Err(Error::ConflictingValues);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn node() -> Node {
        Node::bind_with_policy(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::generate(),
            true,
            RoutingPolicy::Unrestricted,
        )
        .await
        .unwrap()
    }
    fn config() -> ValuePublicationConfig {
        ValuePublicationConfig {
            repair_interval: Duration::from_millis(100),
            renew_before: Duration::from_secs(10),
            ..Default::default()
        }
    }
    async fn settled(
        status: &mut watch::Receiver<ValuePublicationStatus>,
        round: u64,
    ) -> ValuePublicationStatus {
        tokio::time::timeout(Duration::from_secs(70), async {
            loop {
                let state = status.borrow_and_update().clone();
                if state.rounds >= round && (state.verified.len() == 3 || state.conflicted) {
                    return state;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn immutable_repairs_after_a_holder_disappears() {
        let publisher = node().await;
        let mut holders = Vec::new();
        for _ in 0..4 {
            holders.push(node().await);
        }
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact {
                id: n.id(),
                addr: n.local_addr(),
            })
            .collect();
        let value = Value::Immutable(b"maintain these replicas".to_vec());
        let publication = publisher
            .publish_value(value.clone(), None, &seeds, config())
            .unwrap();
        let mut status = publication.status();
        let first = settled(&mut status, 1).await;
        let dead = first.verified[0].id;
        holders
            .iter()
            .find(|n| n.id() == dead)
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        let repaired = tokio::time::timeout(Duration::from_secs(70), async {
            loop {
                let state = status.borrow_and_update().clone();
                if state.rounds > first.rounds
                    && state.verified.len() == 3
                    && state.verified.iter().all(|c| c.id != dead)
                {
                    break state;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(repaired.value, value);
        publication.close().await;
        assert!(publisher.inner.managed_values.lock().unwrap().is_empty());
        for holder in holders {
            let _ = holder.shutdown().await;
        }
        publisher.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn mutable_renews_then_stops_on_a_newer_signed_value() {
        let publisher = node().await;
        let mut holders = Vec::new();
        for _ in 0..3 {
            holders.push(node().await);
        }
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact {
                id: n.id(),
                addr: n.local_addr(),
            })
            .collect();
        let signer = Keypair::generate();
        let now = time(Instant::now()).unix_secs;
        let value = Value::from(
            MutableValue::sign(&signer, vec![], 5, b"owned".to_vec(), now + 9).unwrap(),
        );
        assert!(publisher
            .publish_value(value.clone(), None, &seeds, config())
            .is_err());
        assert!(publisher
            .publish_value(value.clone(), Some(Keypair::generate()), &seeds, config())
            .is_err());
        let publication = publisher
            .publish_value(value, Some(signer.clone()), &seeds, config())
            .unwrap();
        let mut status = publication.status();
        let first = settled(&mut status, 1).await;
        let Value::Mutable(renewed) = first.value else {
            panic!("mutable")
        };
        assert_eq!(renewed.sequence, 6);
        assert!(renewed.expires >= now + 3500);
        let newer = Value::from(
            MutableValue::sign(
                &signer,
                vec![],
                7,
                b"new application data".to_vec(),
                time(Instant::now()).unix_secs + 3600,
            )
            .unwrap(),
        );
        assert_eq!(
            publisher
                .store(newer.clone(), None, &seeds)
                .await
                .unwrap()
                .acknowledged
                .len(),
            3
        );
        let conflict = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let state = status.borrow_and_update().clone();
                if state.conflicted {
                    break state;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(conflict.last_error.is_some());
        assert_eq!(
            publisher.fetch(newer.key(), &seeds).await.unwrap().value,
            Some(newer)
        );
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn admission_is_bounded_and_close_releases_the_key() {
        let publisher = node().await;
        let mut publications = Vec::new();
        for i in 0..16 {
            publications.push(
                publisher
                    .publish_value(Value::Immutable(vec![i]), None, &[], config())
                    .unwrap(),
            );
        }
        assert!(matches!(
            publisher.publish_value(Value::Immutable(vec![0]), None, &[], config()),
            Err(Error::Core(dht_next::Error::Capacity))
        ));
        assert!(matches!(
            publisher.publish_value(Value::Immutable(vec![16]), None, &[], config()),
            Err(Error::Core(dht_next::Error::Capacity))
        ));
        publications.pop().unwrap().close().await;
        let replacement = publisher
            .publish_value(Value::Immutable(vec![15]), None, &[], config())
            .unwrap();
        replacement.close().await;
        for publication in publications {
            publication.close().await;
        }
        publisher.shutdown().await.unwrap();
    }
    async fn faults(node: &Node, faults: dht_next::testing::StorageFaults) {
        node.apply(move |core, _| {
            core.set_storage_faults_for_testing(faults);
            Ok(((), vec![]))
        })
        .await
        .unwrap();
    }
    async fn completed(
        status: &mut watch::Receiver<ValuePublicationStatus>,
        round: u64,
    ) -> ValuePublicationStatus {
        tokio::time::timeout(Duration::from_secs(70), async {
            loop {
                let state = status.borrow_and_update().clone();
                if state.rounds >= round {
                    return state;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn readback_replaces_discarding_missing_silent_and_stale_holders() {
        use dht_next::testing::{ReadFault, StorageFaults};
        let signer = Keypair::generate();
        let expires = time(Instant::now()).unix_secs + 3600;
        let value = Value::from(MutableValue::sign(&signer, vec![], 5, vec![5], expires).unwrap());
        let stale = Value::from(MutableValue::sign(&signer, vec![], 4, vec![4], expires).unwrap());
        for fault in [
            StorageFaults {
                discard_writes: true,
                read_after_write: None,
            },
            StorageFaults {
                discard_writes: false,
                read_after_write: Some(ReadFault::Missing),
            },
            StorageFaults {
                discard_writes: false,
                read_after_write: Some(ReadFault::Silent),
            },
            StorageFaults {
                discard_writes: false,
                read_after_write: Some(ReadFault::Value(stale.clone())),
            },
        ] {
            let publisher = node().await;
            let mut holders = Vec::new();
            for _ in 0..4 {
                holders.push(node().await);
            }
            holders.sort_by_key(|n| n.id().distance(&value.key()));
            faults(&holders[0], fault).await;
            let seeds: Vec<_> = holders
                .iter()
                .map(|n| Contact::new(n.id(), n.local_addr()))
                .collect();
            let publication = publisher
                .publish_value(
                    value.clone(),
                    Some(signer.clone()),
                    &seeds,
                    ValuePublicationConfig::default(),
                )
                .unwrap();
            let mut status = publication.status();
            let state = completed(&mut status, 1).await;
            assert_eq!(state.acknowledged.len(), 4);
            assert_eq!(state.verified.len(), 3);
            assert!(!state.verified.contains(&seeds[0]));
            assert!(state.verified.contains(&seeds[3]));
            assert!(state.last_error.is_none());
            publication.close().await;
            for holder in holders {
                holder.shutdown().await.unwrap();
            }
            publisher.shutdown().await.unwrap();
        }
    }
    #[tokio::test]
    async fn three_dishonest_acknowledgements_do_not_satisfy_replication() {
        let publisher = node().await;
        let mut holders = Vec::new();
        for _ in 0..3 {
            let holder = node().await;
            faults(
                &holder,
                dht_next::testing::StorageFaults {
                    discard_writes: true,
                    read_after_write: None,
                },
            )
            .await;
            holders.push(holder);
        }
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let publication = publisher
            .publish_value(
                Value::Immutable(vec![42]),
                None,
                &seeds,
                ValuePublicationConfig::default(),
            )
            .unwrap();
        let state = completed(&mut publication.status(), 1).await;
        assert_eq!(state.acknowledged.len(), 3);
        assert!(state.verified.is_empty());
        assert!(state.last_error.is_some());
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn audit_repairs_later_withholding_without_rewriting_healthy_copies() {
        use dht_next::testing::{ReadFault, StorageFaults};
        let publisher = node().await;
        let value = Value::Immutable(vec![17]);
        let mut holders = Vec::new();
        for _ in 0..4 {
            holders.push(node().await);
        }
        holders.sort_by_key(|n| n.id().distance(&value.key()));
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let publication = publisher
            .publish_value(
                value,
                None,
                &seeds,
                ValuePublicationConfig {
                    repair_interval: Duration::from_secs(600),
                    audit_interval: Duration::from_millis(100),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut status = publication.status();
        let first = completed(&mut status, 1).await;
        assert_eq!(first.verified, seeds[..3]);
        faults(
            &holders[0],
            StorageFaults {
                discard_writes: false,
                read_after_write: Some(ReadFault::Missing),
            },
        )
        .await;
        let repaired = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let state = completed(&mut status, first.rounds + 1).await;
                if state.verified == seeds[1..] {
                    break state;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(repaired.audits > 0);
        assert!(!repaired.acknowledged.contains(&seeds[1]));
        assert!(!repaired.acknowledged.contains(&seeds[2]));
        assert!(repaired.acknowledged.contains(&seeds[3]));
        publication.close().await;
        let rounds = status.borrow().rounds;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(status.borrow().rounds, rounds);
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn newer_value_during_readback_stops_further_writes() {
        let publisher = node().await;
        let signer = Keypair::generate();
        let expires = time(Instant::now()).unix_secs + 3600;
        let value = Value::from(MutableValue::sign(&signer, vec![], 1, vec![1], expires).unwrap());
        let newer = Value::from(MutableValue::sign(&signer, vec![], 2, vec![2], expires).unwrap());
        let mut holders = Vec::new();
        for _ in 0..3 {
            holders.push(node().await);
        }
        holders.sort_by_key(|n| n.id().distance(&value.key()));
        faults(
            &holders[0],
            dht_next::testing::StorageFaults {
                discard_writes: false,
                read_after_write: Some(dht_next::testing::ReadFault::Value(newer)),
            },
        )
        .await;
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let publication = publisher
            .publish_value(
                value.clone(),
                Some(signer),
                &seeds,
                ValuePublicationConfig::default(),
            )
            .unwrap();
        let state = completed(&mut publication.status(), 1).await;
        assert!(state.conflicted);
        assert!(state.verified.is_empty());
        let mut events = publisher.subscribe();
        for peer in &seeds[1..] {
            assert_eq!(
                publisher
                    .read_publication_value(*peer, value.key(), &mut events)
                    .await
                    .unwrap(),
                None
            );
        }
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn storage_prefers_other_networks_and_repair_retries_a_failed_network() {
        let publisher = Node::bind_with_policy(
            "[::]:0".parse().unwrap(),
            Keypair::generate(),
            true,
            RoutingPolicy::Unrestricted,
        )
        .await
        .unwrap();
        let value = Value::Immutable(b"network-diverse copies".to_vec());
        let mut identities: Vec<_> = (0..5).map(|_| Keypair::generate()).collect();
        identities.sort_by_key(|key| dht_next::node_id(key.public()).distance(&value.key()));
        let mut holders = Vec::new();
        for (index, identity) in identities.into_iter().enumerate() {
            let address = if index < 3 { "127.0.0.1:0" } else { "[::1]:0" };
            holders.push(
                Node::bind_with_policy(
                    address.parse().unwrap(),
                    identity,
                    true,
                    RoutingPolicy::Unrestricted,
                )
                .await
                .unwrap(),
            );
        }
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let stored = publisher.store(value.clone(), None, &seeds).await.unwrap();
        assert_eq!(stored.acknowledged.len(), 3);
        assert!(stored.acknowledged.contains(&seeds[3]));
        assert!(!stored.acknowledged.contains(&seeds[2]));
        faults(
            &holders[3],
            dht_next::testing::StorageFaults {
                discard_writes: true,
                read_after_write: None,
            },
        )
        .await;
        let publication = publisher
            .publish_value(value, None, &seeds, ValuePublicationConfig::default())
            .unwrap();
        let state = completed(&mut publication.status(), 1).await;
        assert_eq!(state.verified, vec![seeds[0], seeds[4], seeds[1]]);
        assert_eq!(state.verified_networks, 2);
        assert_eq!(state.acknowledged.len(), 4);
        assert!(state.last_error.is_none());
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn failed_readbacks_are_skipped_until_network_recovery() {
        let publisher = node().await;
        let value = Value::Immutable(b"bounded failure cooldown".to_vec());
        let mut holders = Vec::new();
        for _ in 0..4 {
            holders.push(node().await);
        }
        holders.sort_by_key(|n| n.id().distance(&value.key()));
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        faults(
            &holders[0],
            dht_next::testing::StorageFaults {
                discard_writes: true,
                read_after_write: None,
            },
        )
        .await;
        let publication = publisher
            .publish_value(
                value,
                None,
                &seeds,
                ValuePublicationConfig {
                    repair_interval: Duration::from_secs(600),
                    audit_interval: Duration::from_millis(100),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut status = publication.status();
        let first = completed(&mut status, 1).await;
        assert_eq!(first.backed_off, vec![seeds[0]]);
        assert_eq!(first.acknowledged.len(), 4);
        assert_eq!(first.verified, seeds[1..]);
        faults(&holders[0], dht_next::testing::StorageFaults::default()).await;
        let audited = completed(&mut status, first.rounds + 1).await;
        assert!(audited.acknowledged.is_empty());
        assert_eq!(audited.verified, seeds[1..]);
        assert_eq!(audited.backed_off, vec![seeds[0]]);
        publisher
            .rebind("127.0.0.1:0".parse().unwrap(), &seeds)
            .await
            .unwrap();
        let recovered = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let state = status.borrow_and_update().clone();
                if state.rounds > audited.rounds && state.verified.contains(&seeds[0]) {
                    break state;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(recovered.backed_off.is_empty());
        assert_eq!(recovered.verified.len(), 3);
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }
    #[test]
    fn failure_backoff_is_bounded_identity_scoped_and_recoverable() {
        let mut backoff = FailureBackoff::default();
        let start = tokio::time::Instant::now();
        let peer = Contact::new(
            NodeId::from_bytes([1; 32]),
            "127.0.0.1:4000".parse().unwrap(),
        );
        let moved = Contact::new(peer.id, "127.0.0.1:5000".parse().unwrap());
        backoff.failed(peer, start);
        assert!(backoff.blocked(moved.id, start + Duration::from_secs(29)));
        assert!(!backoff.blocked(peer.id, start + Duration::from_secs(30)));
        let retry = start + Duration::from_secs(31);
        backoff.failed(moved, retry);
        assert!(backoff.blocked(peer.id, retry + Duration::from_secs(59)));
        assert!(!backoff.blocked(peer.id, retry + Duration::from_secs(60)));
        for _ in 0..20 {
            backoff.failed(peer, retry);
        }
        assert!(!backoff.blocked(peer.id, retry + Duration::from_secs(300)));
        backoff.succeeded(peer.id);
        assert!(backoff.entries.is_empty());
        backoff.failed(peer, start);
        assert!(!backoff.blocked(peer.id, start + Duration::from_secs(30)));
        for n in 2..=100 {
            backoff.failed(Contact::new(NodeId::from_bytes([n; 32]), peer.addr), start);
            assert!(backoff.entries.len() <= 64);
        }
        let other_publication = FailureBackoff::default();
        assert!(!other_publication.blocked(peer.id, start));
    }

    #[tokio::test]
    async fn publication_retries_local_capacity_without_consuming_its_refresh() {
        let publisher = node().await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let seed = Contact::new(NodeId::from_bytes([7; 32]), silent.local_addr().unwrap());
        let occupied = publisher
            .apply(move |core, now| {
                let mut queries = Vec::new();
                let mut actions = Vec::new();
                for n in 0..dht_next::MAX_QUERIES {
                    let (query, outgoing) =
                        core.lookup(NodeId::from_bytes([n as u8; 32]), &[seed], now)?;
                    queries.push(query);
                    actions.extend(outgoing);
                }
                Ok((queries, actions))
            })
            .await
            .unwrap();
        let mut holders = Vec::new();
        for _ in 0..3 {
            holders.push(node().await);
        }
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let started = tokio::time::Instant::now();
        let publication = publisher
            .publish_value(
                Value::Immutable(b"capacity retry".to_vec()),
                None,
                &seeds,
                ValuePublicationConfig {
                    repair_interval: Duration::from_secs(600),
                    audit_interval: Duration::from_secs(60),
                    ..ValuePublicationConfig::default()
                },
            )
            .unwrap();
        let mut status = publication.status();
        let failed = completed(&mut status, 1).await;
        assert_eq!(
            failed.last_error,
            Some(Error::Core(dht_next::Error::Capacity).to_string())
        );
        assert_eq!(failed.audits, 0);
        assert!(failed.backed_off.is_empty());
        publisher
            .apply(move |core, _| {
                for query in occupied {
                    assert!(core.cancel_lookup(query));
                }
                Ok(((), vec![]))
            })
            .await
            .unwrap();
        let recovered = tokio::time::timeout(Duration::from_secs(5), settled(&mut status, 2))
            .await
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(800));
        assert_eq!(recovered.rounds, 2);
        assert_eq!(recovered.audits, 0);
        assert_eq!(recovered.acknowledged.len(), 3);
        assert!(recovered.backed_off.is_empty());
        assert!(recovered.last_error.is_none());
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cleanup_survives_full_queue_and_operation_reply_races() {
        for kind in 0..3 {
            for stage in 0..3 {
                let mut core = Dht::with_routing_policy(
                    Keypair::generate(),
                    Keypair::generate().seed(),
                    true,
                    RoutingPolicy::Unrestricted,
                );
                let (commands, mut receiver) = mpsc::channel(2);
                let (events, _) = broadcast::channel(16);
                let (network, _) = watch::channel(NetworkState {
                    address: "127.0.0.1:4000".parse().unwrap(),
                    generation: 0,
                });
                let node = Node {
                    inner: Arc::new(Inner {
                        commands,
                        events,
                        network,
                        id: core.id(),
                        inbound: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        managed_values: Arc::new(Mutex::new(BTreeSet::new())),
                        task: tokio::spawn(std::future::pending()),
                    }),
                };
                let peer = Contact::new(
                    NodeId::from_bytes([7; 32]),
                    "127.0.0.1:5000".parse().unwrap(),
                );
                let value = Value::Immutable(b"cancellation race".to_vec());
                let now = time(Instant::now());
                let (unrelated, _) = core.get_value(peer, value.key(), now).unwrap();
                let work = PendingValueWork::new(&node).await.unwrap();
                let mut operation = Box::pin(async {
                    match kind {
                        0 => work.get(&node, peer, value.key()).await.map(|_| ()),
                        1 => work.put(&node, peer, value.clone(), None).await.map(|_| ()),
                        _ => work.lookup(&node, value.key(), &[peer]).await.map(|_| ()),
                    }
                });
                let mut context = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(std::future::Future::poll(operation.as_mut(), &mut context).is_pending());
                let Command::Apply(start) = receiver.try_recv().unwrap() else {
                    panic!("apply")
                };
                let deferred = if stage == 0 {
                    Some(start)
                } else {
                    assert!(!start(&mut core, now).is_empty());
                    assert_eq!(core.pending_len(), 2);
                    None
                };
                if stage == 2 {
                    assert!(matches!(
                        std::future::Future::poll(operation.as_mut(), &mut context),
                        std::task::Poll::Ready(Ok(()))
                    ));
                }
                node.inner
                    .commands
                    .try_send(Command::Apply(Box::new(|_, _| vec![])))
                    .unwrap();
                assert_eq!(node.inner.commands.capacity(), 0);
                let queries = work.queries.lock().unwrap().clone();
                drop(operation);
                drop(work);
                assert_eq!(receiver.len(), 2);
                if let Some(start) = deferred {
                    assert!(start(&mut core, now).is_empty());
                }
                for _ in 0..2 {
                    let Command::Apply(cleanup) = receiver.try_recv().unwrap() else {
                        panic!("apply")
                    };
                    assert!(cleanup(&mut core, now).is_empty());
                }
                assert_eq!(
                    core.pending_len(),
                    1,
                    "operation {kind}, cancellation stage {stage}"
                );
                for query in queries {
                    assert!(!core.cancel_lookup(query));
                }
                assert!(core.cancel_value_read(unrelated));
                assert_eq!(node.inner.commands.capacity(), 2);
            }
        }
    }

    #[tokio::test]
    async fn closing_publication_cancels_discovery_but_preserves_other_lookups() {
        let publisher = node().await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peers: Vec<_> = (1..=4)
            .map(|n| Contact::new(NodeId::from_bytes([n; 32]), silent.local_addr().unwrap()))
            .collect();
        let value = Value::Immutable(b"cancel discovery".to_vec());
        let unrelated = publisher.lookup(value.key(), &peers[3..]).await.unwrap();
        let publication = publisher
            .publish_value(value, None, &peers[..3], config())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let pending = publisher
                    .apply(|core, _| Ok((core.pending_len(), vec![])))
                    .await
                    .unwrap();
                if pending == 4 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        publication.close().await;
        let pending = publisher
            .apply(|core, _| Ok((core.pending_len(), vec![])))
            .await
            .unwrap();
        assert_eq!(pending, 1);
        assert!(publisher
            .apply(move |core, _| Ok((core.cancel_lookup(unrelated), vec![])))
            .await
            .unwrap());
        publisher.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn canceled_publication_write_preserves_unrelated_reads_and_writes() {
        let publisher = node().await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = Contact::new(NodeId::from_bytes([1; 32]), silent.local_addr().unwrap());
        let value = Value::Immutable(b"cancel write".to_vec());
        publisher.get_value(peer, value.key()).await.unwrap();
        let unrelated = publisher
            .put_value(peer, value.clone(), None)
            .await
            .unwrap();
        let worker_node = publisher.clone();
        let worker = tokio::spawn(async move {
            let mut events = worker_node.subscribe();
            worker_node
                .write_publication_value(peer, value, None, &mut events)
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let pending = publisher
                    .apply(|core, _| Ok((core.pending_len(), vec![])))
                    .await
                    .unwrap();
                if pending == 3 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        let pending = publisher
            .apply(|core, _| Ok((core.pending_len(), vec![])))
            .await
            .unwrap();
        assert_eq!(pending, 2);
        assert!(publisher
            .apply(move |core, _| Ok((core.cancel_value_write(unrelated), vec![])))
            .await
            .unwrap());
        publisher.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn canceled_preflight_releases_only_its_own_pending_reads() {
        let publisher = node().await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peers: Vec<_> = (1..=4)
            .map(|n| Contact::new(NodeId::from_bytes([n; 32]), silent.local_addr().unwrap()))
            .collect();
        let value = Value::Immutable(b"cancel preflight".to_vec());
        publisher.get_value(peers[3], value.key()).await.unwrap();
        let worker_node = publisher.clone();
        let worker = tokio::spawn(async move {
            let mut events = worker_node.subscribe();
            worker_node
                .preflight_values(
                    &value,
                    &peers[..3],
                    &mut events,
                    &mut FailureBackoff::default(),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let pending = publisher
                    .apply(|core, _| Ok((core.pending_len(), vec![])))
                    .await
                    .unwrap();
                if pending == 4 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        let pending = publisher
            .apply(|core, _| Ok((core.pending_len(), vec![])))
            .await
            .unwrap();
        assert_eq!(pending, 1);
        publisher.shutdown().await.unwrap();
    }

    #[test]
    fn audit_candidates_preserve_holders_without_displacing_lookup_results() {
        let peers: Vec<_> = (1..=25)
            .map(|n| {
                Contact::new(
                    NodeId::from_bytes([n; 32]),
                    "127.0.0.1:4000".parse().unwrap(),
                )
            })
            .collect();
        let holders = &peers[20..];
        assert_eq!(publication_candidates(&peers[..20], holders), peers[..23]);
        assert_eq!(publication_candidates(&[], holders), peers[20..23]);
        let moved = Contact::new(peers[20].id, "127.0.0.1:5000".parse().unwrap());
        assert_eq!(
            publication_candidates(&[moved], holders),
            vec![moved, peers[21], peers[22]]
        );
        assert_eq!(publication_candidates(&peers, holders), peers[..23]);
    }

    #[tokio::test]
    async fn refresh_checks_displaced_holders_before_writing_new_replicas() {
        for remote_kind in [0, 1, 2] {
            let publisher = node().await;
            let writer = node().await;
            let displaced = node().await;
            let holder = Contact::new(displaced.id(), displaced.local_addr());
            let mut destinations = Vec::new();
            for _ in 0..3 {
                destinations.push(node().await);
            }
            let seeds: Vec<_> = destinations
                .iter()
                .map(|n| Contact::new(n.id(), n.local_addr()))
                .collect();
            let signer = Keypair::generate();
            let expires = time(Instant::now()).unix_secs + VALUE_TTL_SECS;
            let mut value = Value::from(
                MutableValue::sign(&signer, vec![], 1, b"original".to_vec(), expires).unwrap(),
            );
            let remote = match remote_kind {
                0 => value.clone(),
                1 => Value::from(
                    MutableValue::sign(&signer, vec![], 2, b"newer".to_vec(), expires).unwrap(),
                ),
                _ => Value::from(
                    MutableValue::sign(&signer, vec![], 1, b"fork".to_vec(), expires).unwrap(),
                ),
            };
            let mut writes = writer.subscribe();
            let request = writer.put_value(holder, remote, None).await.unwrap();
            loop {
                if matches!(next_event(&mut writes).await.unwrap(), Event::ValueStored { request: id, stored: true, .. } if id == request)
                {
                    break;
                }
            }
            let (status, _) = watch::channel(ValuePublicationStatus {
                value: value.clone(),
                acknowledged: vec![],
                verified: vec![holder],
                verified_networks: 1,
                backed_off: vec![],
                audits: 0,
                rounds: 1,
                last_error: None,
                conflicted: false,
            });
            let outcome = tokio::time::timeout(
                Duration::from_secs(10),
                publisher.repair_value(
                    &mut value,
                    Some(&signer),
                    &seeds,
                    RepairPolicy {
                        renew_before: Duration::from_secs(10),
                        refresh: true,
                        holders: &[holder],
                    },
                    &status,
                    &mut FailureBackoff::default(),
                ),
            )
            .await
            .unwrap();
            if remote_kind == 0 {
                let result = outcome.unwrap();
                assert_eq!(result.verified.len(), 3);
                assert!(result.verified.iter().all(|peer| seeds.contains(peer)));
            } else {
                assert!(matches!(outcome, Err(Error::ConflictingValues)));
            }
            let mut reads = writer.subscribe();
            for peer in seeds {
                let stored = writer
                    .read_publication_value(peer, value.key(), &mut reads)
                    .await
                    .unwrap();
                assert_eq!(stored, (remote_kind == 0).then(|| value.clone()));
            }
            for destination in destinations {
                destination.shutdown().await.unwrap();
            }
            displaced.shutdown().await.unwrap();
            writer.shutdown().await.unwrap();
            publisher.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn preflight_reads_holders_beyond_twenty_lookup_candidates() {
        let publisher = node().await;
        let mut nodes = Vec::new();
        for _ in 0..23 {
            nodes.push(node().await);
        }
        let peers: Vec<_> = nodes
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let value = Value::Immutable(b"retained replicas".to_vec());
        let mut events = publisher.subscribe();
        for peer in &peers[20..] {
            let request = publisher
                .put_value(*peer, value.clone(), None)
                .await
                .unwrap();
            loop {
                if matches!(next_event(&mut events).await.unwrap(), Event::ValueStored { request: id, stored: true, .. } if id == request)
                {
                    break;
                }
            }
        }
        let candidates = publication_candidates(&peers[..20], &peers[20..]);
        let observed = tokio::time::timeout(
            Duration::from_secs(10),
            publisher.preflight_values(
                &value,
                &candidates,
                &mut events,
                &mut FailureBackoff::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(observed.len(), 23);
        assert!(observed[..20].iter().all(|(_, remote)| remote.is_none()));
        assert_eq!(
            observed[20..],
            peers[20..]
                .iter()
                .map(|peer| (*peer, Some(value.clone())))
                .collect::<Vec<_>>()
        );
        for holder in nodes {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn preflight_overlaps_silent_peers_with_bounded_concurrency() {
        for silent in [2, 5] {
            let publisher = node().await;
            let value = Value::Immutable(vec![99]);
            let mut holders = Vec::new();
            for _ in 0..5 {
                holders.push(node().await);
            }
            let candidates: Vec<_> = holders
                .iter()
                .map(|n| Contact::new(n.id(), n.local_addr()))
                .collect();
            let mut events = publisher.subscribe();
            for (index, peer) in candidates.iter().enumerate() {
                let request = publisher
                    .put_value(*peer, value.clone(), None)
                    .await
                    .unwrap();
                loop {
                    if matches!(next_event(&mut events).await.unwrap(), Event::ValueStored { request: id, stored: true, .. } if id == request)
                    {
                        break;
                    }
                }
                if index < silent {
                    faults(
                        &holders[index],
                        dht_next::testing::StorageFaults {
                            discard_writes: false,
                            read_after_write: Some(dht_next::testing::ReadFault::Silent),
                        },
                    )
                    .await;
                }
            }
            let reader = publisher.clone();
            let peers = candidates.clone();
            let worker = tokio::spawn(async move {
                let mut backoff = FailureBackoff::default();
                let observed = reader
                    .preflight_values(&value, &peers, &mut events, &mut backoff)
                    .await
                    .unwrap();
                (observed, backoff)
            });
            let mut peak = 0;
            tokio::time::timeout(Duration::from_secs(10), async {
                while !worker.is_finished() {
                    let pending = publisher
                        .apply(|core, _| Ok((core.pending_len(), vec![])))
                        .await
                        .unwrap();
                    assert!(pending <= 3);
                    peak = peak.max(pending);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let (observed, backoff) = worker.await.unwrap();
            if silent == 5 {
                assert_eq!(peak, 3);
            } else {
                assert!(peak >= 2);
            }
            assert_eq!(
                observed.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(),
                candidates[silent..]
            );
            assert!(observed
                .iter()
                .all(|(_, value)| value == &Some(Value::Immutable(vec![99]))));
            assert_eq!(backoff.entries.len(), silent);
            for holder in holders {
                holder.shutdown().await.unwrap();
            }
            publisher.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn concurrent_preflight_checks_later_candidates_before_writing() {
        let publisher = node().await;
        let signer = Keypair::generate();
        let expires = time(Instant::now()).unix_secs + 3600;
        let value = Value::from(MutableValue::sign(&signer, vec![], 1, vec![1], expires).unwrap());
        let newer = Value::from(MutableValue::sign(&signer, vec![], 2, vec![2], expires).unwrap());
        let mut holders = Vec::new();
        for _ in 0..4 {
            holders.push(node().await);
        }
        holders.sort_by_key(|n| n.id().distance(&value.key()));
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let mut events = publisher.subscribe();
        let request = publisher.put_value(seeds[3], newer, None).await.unwrap();
        loop {
            if matches!(next_event(&mut events).await.unwrap(), Event::ValueStored { request: id, stored: true, .. } if id == request)
            {
                break;
            }
        }
        let publication = publisher
            .publish_value(
                value.clone(),
                Some(signer),
                &seeds,
                ValuePublicationConfig::default(),
            )
            .unwrap();
        let state = completed(&mut publication.status(), 1).await;
        assert!(state.conflicted);
        for peer in &seeds[..3] {
            assert_eq!(
                publisher
                    .read_publication_value(*peer, value.key(), &mut events)
                    .await
                    .unwrap(),
                None
            );
        }
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn audit_reuses_healthy_copies_when_closer_empty_peers_appear() {
        let publisher = node().await;
        let value = Value::Immutable(b"avoid churn-driven replica writes".to_vec());
        let mut holders = Vec::new();
        for _ in 0..5 {
            holders.push(node().await);
        }
        holders.sort_by_key(|n| n.id().distance(&value.key()));
        let peers: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let publication = publisher
            .publish_value(
                value.clone(),
                None,
                &peers[2..],
                ValuePublicationConfig {
                    audit_interval: Duration::from_millis(300),
                    repair_interval: Duration::from_secs(3),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut status = publication.status();
        let first = completed(&mut status, 1).await;
        assert_eq!(first.verified, peers[2..]);
        let mut events = publisher.subscribe();
        for peer in &peers[..2] {
            publisher.probe(*peer).await.unwrap();
            loop {
                if matches!(next_event(&mut events).await.unwrap(), Event::Ready(contact) if contact == *peer)
                {
                    break;
                }
            }
        }
        let after_discovery = status.borrow().rounds;
        let audited = completed(&mut status, after_discovery + 2).await;
        assert!(audited.audits >= 2);
        assert_eq!(audited.verified, peers[2..]);
        assert!(audited.acknowledged.is_empty());
        for peer in &peers[..2] {
            assert_eq!(
                publisher
                    .read_publication_value(*peer, value.key(), &mut events)
                    .await
                    .unwrap(),
                None
            );
        }
        let refreshed = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let state = status.borrow_and_update().clone();
                if state.verified == peers[..3] && state.acknowledged.len() == 3 {
                    break state;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(refreshed.rounds > audited.rounds);
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn audit_renews_mutable_expiry_before_the_scheduled_refresh() {
        let publisher = node().await;
        let signer = Keypair::generate();
        let mut holders = Vec::new();
        for _ in 0..3 {
            holders.push(node().await);
        }
        let seeds: Vec<_> = holders
            .iter()
            .map(|n| Contact::new(n.id(), n.local_addr()))
            .collect();
        let expires = time(Instant::now()).unix_secs + 5;
        let value = Value::from(MutableValue::sign(&signer, vec![], 5, vec![7], expires).unwrap());
        let publication = publisher
            .publish_value(
                value.clone(),
                Some(signer),
                &seeds,
                ValuePublicationConfig {
                    repair_interval: Duration::from_secs(600),
                    audit_interval: Duration::from_millis(300),
                    renew_before: Duration::from_secs(2),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut status = publication.status();
        let first = completed(&mut status, 1).await;
        assert_eq!(first.value, value);
        let renewed = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let state = status.borrow_and_update().clone();
                if matches!(&state.value, Value::Mutable(v) if v.sequence == 6)
                    && state.verified.len() == 3
                {
                    break state;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(renewed.audits > 0);
        assert_eq!(renewed.acknowledged.len(), 3);
        assert!(renewed.value.verify(time(Instant::now())));
        publication.close().await;
        for holder in holders {
            holder.shutdown().await.unwrap();
        }
        publisher.shutdown().await.unwrap();
    }

    #[test]
    fn audit_jitter_stays_within_twenty_percent() {
        for _ in 0..32 {
            let delay = audit_delay(Duration::from_secs(60));
            assert!((Duration::from_secs(48)..=Duration::from_secs(72)).contains(&delay));
        }
    }

    #[test]
    fn equal_sequence_forks_are_not_repaired_over() {
        let signer = Keypair::generate();
        let now = time(Instant::now()).unix_secs;
        let local =
            Value::from(MutableValue::sign(&signer, vec![], 1, vec![1], now + 100).unwrap());
        let fork = Value::from(MutableValue::sign(&signer, vec![], 1, vec![2], now + 100).unwrap());
        assert_eq!(
            check_remote(&local, Some(&fork)),
            Err(Error::ConflictingValues)
        );
        assert_eq!(check_remote(&local, Some(&local)), Ok(()));
    }
}
