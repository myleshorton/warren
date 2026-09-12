use super::*;

/// Bounded reconnection policy. Cancellation drops the active connection and
/// leaves caller-owned verified download/replica state intact.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryConfig {
    pub attempts: usize,
    pub backoff: Duration,
    pub deadline: Duration,
}
impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            attempts: 8,
            backoff: Duration::from_millis(250),
            deadline: Duration::from_secs(300),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error(transparent)]
    Connection(#[from] Error),
    #[error(transparent)]
    Transfer(#[from] crate::TransferError),
    #[error("recovery deadline exceeded")]
    Deadline,
    #[error("invalid recovery policy")]
    InvalidConfig,
}
impl RecoveryConfig {
    fn validate(self) -> Result<Self, RecoveryError> {
        if self.attempts == 0
            || self.attempts > 32
            || self.backoff.is_zero()
            || self.backoff > Duration::from_secs(30)
            || self.deadline.is_zero()
            || self.deadline > Duration::from_secs(3600)
        {
            return Err(RecoveryError::InvalidConfig);
        }
        Ok(self)
    }
    async fn pause(self, attempt: usize) {
        tokio::time::sleep(
            self.backoff
                .saturating_mul(1 << attempt.min(5))
                .min(Duration::from_secs(5)),
        )
        .await;
    }
}
fn retry_transfer(error: &crate::TransferError) -> bool {
    match error {
        crate::TransferError::Timeout => true,
        crate::TransferError::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::TimedOut
                | io::ErrorKind::NotConnected
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
        ),
        _ => false,
    }
}
fn retry_connect(error: &Error) -> bool {
    match error {
        Error::Authentication(error) => matches!(
            error.kind(),
            io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::UnexpectedEof
        ),
        _ => matches!(
            error,
            Error::PeerNotFound
                | Error::SignalingTimedOut
                | Error::DirectUnavailable
                | Error::Deadline
                | Error::Busy
                | Error::Socket(_)
                | Error::Dht(
                    driver::next::Error::NetworkChanged
                        | driver::next::Error::TimedOut
                        | driver::next::Error::NoPeers
                )
        ),
    }
}

/// Progress from the platform network-notification adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkStatus {
    Idle,
    Recovering,
    Ready(SocketAddr),
    Failed(String),
}
/// Drop to stop watching network notifications and cancel pending recovery.
pub struct NetworkMonitor {
    task: JoinHandle<()>,
    status: tokio::sync::watch::Receiver<NetworkStatus>,
}
impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl NetworkMonitor {
    pub fn status(&self) -> tokio::sync::watch::Receiver<NetworkStatus> {
        self.status.clone()
    }
}
impl Endpoint {
    /// Automatically recover when the platform publishes a new bind address.
    /// The initial watch value is not applied. Publishing the same address again
    /// handles resume/NAT expiry. New notifications supersede pending retries.
    pub fn watch_network(
        &self,
        mut changes: tokio::sync::watch::Receiver<SocketAddr>,
        seeds: &[Contact],
    ) -> Result<NetworkMonitor, Error> {
        if seeds.len() > 8 {
            return Err(Error::InvalidConfig);
        }
        let endpoint = self.clone();
        let seeds = seeds.to_vec();
        let (status, receiver) = tokio::sync::watch::channel(NetworkStatus::Idle);
        let task = tokio::spawn(async move {
            while changes.changed().await.is_ok() {
                let mut address = *changes.borrow_and_update();
                let mut failures = 0u32;
                loop {
                    status.send_replace(NetworkStatus::Recovering);
                    let result = tokio::select! {
                        biased;
                        changed = changes.changed() => {
                            if changed.is_err() { return; }
                            address = *changes.borrow_and_update();
                            failures = 0;
                            continue;
                        }
                        result = endpoint.network_changed(address, &seeds) => result,
                    };
                    match result {
                        Ok(bound) => {
                            status.send_replace(NetworkStatus::Ready(bound));
                            break;
                        }
                        Err(error) => {
                            status.send_replace(NetworkStatus::Failed(error.to_string()));
                        }
                    }
                    let wait = Duration::from_secs(1 << failures.min(5));
                    failures = failures.saturating_add(1);
                    tokio::select! {
                        changed = changes.changed() => {
                            if changed.is_err() { return; }
                            address = *changes.borrow_and_update();
                            failures = 0;
                        }
                        _ = tokio::time::sleep(wait) => {}
                    }
                }
            }
        });
        Ok(NetworkMonitor {
            task,
            status: receiver,
        })
    }
    /// Report a platform network change (including resume after sleep). Rebinds
    /// the same actor, revalidates contacts, and renews existing publications.
    /// Existing connections fail with ConnectionAborted and must authenticate anew.
    /// Port zero is recommended; a bind failure leaves the old socket untouched.
    /// With a listener, waits for the first new registration acknowledgement.
    pub async fn network_changed(
        &self,
        bind: SocketAddr,
        seeds: &[Contact],
    ) -> Result<SocketAddr, Error> {
        let _recovery = self.inner.recovery.lock().await;
        let mut events = self.dht().subscribe();
        let address = self
            .dht()
            .rebind(bind, seeds)
            .await
            .map_err(Error::Socket)?;
        if self.inner.listening.load(Ordering::Acquire) {
            tokio::time::timeout(self.inner.config.deadline, async {
                let mut changed = false;
                loop {
                    match next_event(&mut events).await? {
                        Event::NetworkChanged(_) => changed = true,
                        Event::Registered(record)
                            if changed
                                && record.topic == self.dht().id()
                                && record.provider == self.public_key() =>
                        {
                            return Ok::<_, Error>(())
                        }
                        _ => {}
                    }
                }
            })
            .await
            .map_err(|_| Error::Deadline)??;
        }
        Ok(address)
    }

    /// Reconnect through DHT signaling and resume only missing blob chunks.
    pub async fn recover_blob(
        &self,
        peer: PublicKey,
        seeds: &[Contact],
        download: &mut sync::BlobDownload,
        transfer: &crate::Config,
        policy: RecoveryConfig,
    ) -> Result<Vec<u8>, RecoveryError> {
        let policy = policy.validate()?;
        tokio::time::timeout(policy.deadline, async {
            for attempt in 0..policy.attempts {
                if attempt > 0 {
                    policy.pause(attempt - 1).await;
                }
                let result = match self.connect(peer, seeds).await {
                    Ok(mut connection) => crate::resume_blob(&mut connection, download, transfer)
                        .await
                        .map_err(RecoveryError::Transfer),
                    Err(error) => Err(RecoveryError::Connection(error)),
                };
                let retry = match &result {
                    Err(RecoveryError::Connection(error)) => retry_connect(error),
                    Err(RecoveryError::Transfer(error)) => retry_transfer(error),
                    _ => false,
                };
                if !retry || attempt + 1 == policy.attempts {
                    return result;
                }
            }
            unreachable!("validated attempts")
        })
        .await
        .map_err(|_| RecoveryError::Deadline)?
    }

    /// Reconnect a live feed mirror from the replica's last verified length.
    /// Runs until cancellation, a non-retryable error, or the recovery budget.
    pub async fn recover_feed(
        &self,
        peer: PublicKey,
        seeds: &[Contact],
        replica: &std::sync::Mutex<feed::Replica>,
        appended: &tokio::sync::Notify,
        transfer: &crate::Config,
        policy: RecoveryConfig,
    ) -> Result<(), RecoveryError> {
        let policy = policy.validate()?;
        let public_key = replica.lock().expect("replica").public_key();
        tokio::time::timeout(policy.deadline, async {
            for attempt in 0..policy.attempts {
                if attempt > 0 {
                    policy.pause(attempt - 1).await;
                }
                let result = match self.connect(peer, seeds).await {
                    Ok(mut connection) => crate::replicate_feed(
                        &mut connection,
                        public_key,
                        replica,
                        appended,
                        transfer,
                    )
                    .await
                    .map_err(RecoveryError::Transfer),
                    Err(error) => Err(RecoveryError::Connection(error)),
                };
                let retry = match &result {
                    Err(RecoveryError::Connection(error)) => retry_connect(error),
                    Err(RecoveryError::Transfer(error)) => retry_transfer(error),
                    _ => false,
                };
                if !retry || attempt + 1 == policy.attempts {
                    return result;
                }
            }
            unreachable!("validated attempts")
        })
        .await
        .map_err(|_| RecoveryError::Deadline)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    async fn endpoint(seed: u8) -> Endpoint {
        Endpoint::bind_with_policy(
            "[::]:0".parse().unwrap(),
            Keypair::from_seed(&[seed; 32]),
            false,
            RoutingPolicy::Unrestricted,
            Config::default(),
        )
        .await
        .unwrap()
    }
    async fn router(address: &str, seed: u8) -> Node {
        Node::bind_with_policy(
            address.parse().unwrap(),
            Keypair::from_seed(&[seed; 32]),
            true,
            RoutingPolicy::Unrestricted,
        )
        .await
        .unwrap()
    }
    fn contact(node: &Node) -> Contact {
        Contact::new(node.id(), node.local_addr())
    }
    fn transfer_config() -> crate::Config {
        crate::Config {
            request_timeout: Duration::from_millis(200),
            retries: 2,
            initial_rtt: Duration::from_millis(1),
            idle: Duration::from_secs(3),
        }
    }

    #[tokio::test]
    async fn blob_recovers_after_address_changes_and_coordinator_loss_without_refetching_verified_chunks(
    ) {
        tokio::time::timeout(Duration::from_secs(40), async {
            let a = router("127.0.0.1:0", 151).await;
            let b = router("[::1]:0", 152).await;
            let server = endpoint(153).await;
            let client = endpoint(154).await;
            let seeds = [contact(&a), contact(&b)];
            let mut events = server.dht().subscribe();
            let mut listener = server.listen(&seeds).await.unwrap();
            let mut coordinators = BTreeSet::new();
            while coordinators.len() < 2 {
                if let Event::Registered(record) = next_event(&mut events).await.unwrap() {
                    coordinators.insert(record.coordinator.id);
                }
            }
            let bytes: Vec<_> = (0..blob::CHUNK_SIZE*4).map(|i| (i / blob::CHUNK_SIZE) as u8).collect();
            let mut store = blob::Store::new();
            let manifest = store.add(&bytes);
            let id = store.put(manifest.encode());
            let first_chunk = manifest.chunks[0];
            let mut download = sync::BlobDownload::new(id);
            let config = transfer_config();
            let policy = RecoveryConfig { attempts: 5, deadline: Duration::from_secs(35), ..RecoveryConfig::default() };
            let serving = async {
                let first = listener.accept().await.unwrap();
                let old_session = first.session();
                let stop = tokio::sync::Notify::new();
                let requested = AtomicUsize::new(0);
                tokio::select! {
                    biased;
                    _ = stop.notified() => {},
                    result = crate::serve(&first, &config, None, |request| {
                        if matches!(request, sync::Message::GetChunk { .. })
                            && requested.fetch_add(1, Ordering::SeqCst) == 1 { stop.notify_one(); }
                        sync::serve_blob(request, &store)
                    }) => panic!("first server ended before forced network change: {result:?}"),
                }
                // Requesting the second chunk proves that the first was verified.
                client.network_changed("[::1]:0".parse().unwrap(), &[contact(&b)]).await.unwrap();
                assert_eq!(first.remote_public_key(), client.public_key());
                a.shutdown().await.unwrap();
                server.network_changed("[::1]:0".parse().unwrap(), &[contact(&b)]).await.unwrap();
                assert_eq!(first.send(b"stale session").await.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
                drop(first);
                let second = listener.accept().await.unwrap();
                assert_ne!(second.session(), old_session);
                assert_eq!(second.remote_public_key(), client.public_key());
                let result = crate::serve(&second, &config, None, |request| {
                    assert!(!matches!(request, sync::Message::GetManifest { .. }), "verified manifest must survive recovery");
                    assert!(!matches!(request, sync::Message::GetChunk { hash } if *hash == first_chunk), "verified chunk must not be fetched again");
                    sync::serve_blob(request, &store)
                }).await;
                assert!(result.is_ok(), "{result:?}");
            };
            let (result, ()) = tokio::join!(client.recover_blob(server.public_key(), &seeds, &mut download, &config, policy), serving);
            assert_eq!(result.unwrap(), bytes);
            listener.close().await;
            for node in [&b, server.dht(), client.dht()] { node.shutdown().await.unwrap(); }
        }).await.expect("bounded network recovery");
    }

    #[tokio::test]
    async fn failed_bind_preserves_generation_and_live_listener() {
        let router = router("[::1]:0", 155).await;
        let server = endpoint(156).await;
        let client = endpoint(157).await;
        let seeds = [contact(&router)];
        let mut listener = server.listen(&seeds).await.unwrap();
        let before = *server.dht().network().borrow();
        assert!(server
            .network_changed(router.local_addr(), &seeds)
            .await
            .is_err());
        assert_eq!(*server.dht().network().borrow(), before);
        let (client_link, server_link) = tokio::join!(
            client.connect(server.public_key(), &seeds),
            listener.accept()
        );
        assert_eq!(
            client_link.unwrap().session(),
            server_link.unwrap().session()
        );
        listener.close().await;
        for node in [&router, server.dht(), client.dht()] {
            node.shutdown().await.unwrap();
        }
    }

    #[test]
    fn recovery_does_not_retry_verification_or_authentication_failures() {
        assert!(!retry_transfer(&crate::TransferError::Sync(
            sync::SyncError::BadChunk
        )));
        assert!(!retry_connect(&Error::Authentication(io::Error::other(
            "wrong key"
        ))));
        assert!(retry_transfer(&crate::TransferError::Io(network_error())));
        assert!(retry_connect(&Error::Dht(
            driver::next::Error::NetworkChanged
        )));
        assert!(RecoveryConfig {
            attempts: 0,
            ..RecoveryConfig::default()
        }
        .validate()
        .is_err());
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[tokio::test]
    async fn monitor_recovers_from_bind_failure_and_same_address_resume() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let router = Node::bind(
                "127.0.0.1:0".parse().unwrap(),
                Keypair::from_seed(&[161; 32]),
                true,
            )
            .await
            .unwrap();
            let endpoint = Endpoint::bind(
                "127.0.0.1:0".parse().unwrap(),
                Keypair::from_seed(&[162; 32]),
                false,
            )
            .await
            .unwrap();
            let (send, changes) = tokio::sync::watch::channel("127.0.0.1:0".parse().unwrap());
            let monitor = endpoint
                .watch_network(changes, &[Contact::new(router.id(), router.local_addr())])
                .unwrap();
            let mut status = monitor.status();
            send.send_replace(router.local_addr());
            loop {
                status.changed().await.unwrap();
                if matches!(*status.borrow_and_update(), NetworkStatus::Failed(_)) {
                    break;
                }
            }
            assert_eq!(endpoint.dht().network().borrow().generation, 0);
            for generation in 1..=2 {
                send.send_replace("127.0.0.1:0".parse().unwrap());
                loop {
                    status.changed().await.unwrap();
                    if matches!(*status.borrow_and_update(), NetworkStatus::Ready(_)) {
                        break;
                    }
                }
                assert_eq!(endpoint.dht().network().borrow().generation, generation);
            }
            drop(monitor);
            status.changed().await.unwrap_err();
            endpoint.dht().shutdown().await.unwrap();
            router.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn live_feed_resumes_verified_length_with_a_distinct_feed_key() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let router = Node::bind("127.0.0.1:0".parse().unwrap(), Keypair::from_seed(&[163;32]), true).await.unwrap();
            let server = Endpoint::bind("127.0.0.1:0".parse().unwrap(), Keypair::from_seed(&[164;32]), false).await.unwrap();
            let client = Endpoint::bind("127.0.0.1:0".parse().unwrap(), Keypair::from_seed(&[165;32]), false).await.unwrap();
            let seeds = [Contact::new(router.id(), router.local_addr())];
            let mut listener = server.listen(&seeds).await.unwrap();
            let mut source = feed::Log::new(Keypair::from_seed(&[166;32]));
            source.append(b"one".to_vec());
            let replica = std::sync::Mutex::new(feed::Replica::new(source.public_key(), source.head(), vec![b"one".to_vec()]).unwrap());
            source.append(b"two".to_vec());
            let source = std::sync::Mutex::new(source);
            let appended = tokio::sync::Notify::new();
            let config = crate::Config { initial_rtt: Duration::from_millis(1), request_timeout: Duration::from_millis(100), retries: 2, idle: Duration::from_secs(1) };
            let recovering = async {
                tokio::select! {
                    result = client.recover_feed(server.public_key(), &seeds, &replica, &appended, &config, RecoveryConfig::default()) => panic!("premature end: {result:?}"),
                    _ = async {
                        loop {
                            let changed = appended.notified();
                            if replica.lock().unwrap().len() == 3 { break; }
                            changed.await;
                        }
                    } => {},
                }
            };
            let serving = async {
                let first = listener.accept().await.unwrap();
                let session = first.session();
                let stop = tokio::sync::Notify::new();
                tokio::select! {
                    biased;
                    _ = stop.notified() => {},
                    result = crate::serve(&first, &config, None, |request| {
                        if matches!(request, sync::Message::Tail { have: 2 }) { stop.notify_one(); }
                        sync::serve_feed(request, &*source.lock().unwrap())
                    }) => panic!("first feed server stopped: {result:?}"),
                }
                assert_eq!(replica.lock().unwrap().len(), 2);
                client.network_changed("127.0.0.1:0".parse().unwrap(), &seeds).await.unwrap();
                drop(first);
                source.lock().unwrap().append(b"three".to_vec());
                let second = listener.accept().await.unwrap();
                assert_ne!(second.session(), session);
                let checked = AtomicBool::new(false);
                let served = crate::serve(&second, &config, None, |request| {
                    if !checked.swap(true, Ordering::SeqCst) {
                        assert!(matches!(request, sync::Message::Tail { have: 2 }));
                    }
                    sync::serve_feed(request, &*source.lock().unwrap())
                }).await;
                assert!(served.is_ok() || matches!(served, Err(crate::TransferError::Io(ref error)) if error.kind() == io::ErrorKind::ConnectionRefused));
            };
            tokio::join!(recovering, serving);
            assert_eq!(replica.lock().unwrap().block(2).unwrap(), b"three");
            listener.close().await;
            for node in [&router, server.dht(), client.dht()] { node.shutdown().await.unwrap(); }
        }).await.unwrap();
    }
}
