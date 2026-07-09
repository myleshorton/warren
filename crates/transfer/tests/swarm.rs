//! Swarm download over real punched channels: a client fetches a blob's chunks
//! from several providers at once, verified by hash, and still completes when a
//! provider drops out.

use std::net::SocketAddr;
use std::time::Duration;

use driver::{open_channel, Channel, DataListener, PunchConfig};
use tokio::time::timeout;
use transfer::{download_blob_swarm, serve_blob, Config};

const LO: &str = "127.0.0.1:0";
const T: Duration = Duration::from_secs(15);

/// Punch a connected pair of channels on loopback: (client, server).
async fn connected_pair() -> (Channel, Channel) {
    let listener = DataListener::bind(LO.parse().unwrap()).await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let client_bind: SocketAddr = LO.parse().unwrap();
    let peer_host = client_bind.ip();
    let punch = PunchConfig::default();
    let accept = tokio::spawn(async move { listener.accept(peer_host, &punch).await });
    let client = open_channel(client_bind, server_addr, &PunchConfig::default())
        .await
        .unwrap()
        .expect("client channel");
    let server = accept.await.unwrap().unwrap().expect("server channel");
    (client, server)
}

/// A store holding the whole blob (its chunks plus the manifest under its own
/// content address, so the provider can serve both).
fn full_store(data: &[u8]) -> blob::Store {
    let mut store = blob::Store::new();
    let manifest = store.add(data);
    store.put(manifest.encode());
    store
}

#[tokio::test]
async fn swarm_downloads_from_several_full_providers() {
    // A blob of several chunks, held in full by three providers. The client
    // fetches it from all three at once and reassembles the exact bytes.
    let data: Vec<u8> = (0..400_000u32).map(|i| i as u8).collect();
    let id = blob::split(&data).0.id();

    let mut clients = Vec::new();
    let mut servers = Vec::new();
    for _ in 0..3 {
        let (client, mut server) = connected_pair().await;
        clients.push(client);
        let store = full_store(&data);
        servers.push(tokio::spawn(async move {
            let _ = serve_blob(&mut server, &store, &Config::default()).await;
        }));
    }

    let got = timeout(T, download_blob_swarm(clients, id, &Config::default()))
        .await
        .expect("swarm should finish")
        .expect("swarm should verify");
    assert_eq!(got, data);
}

#[tokio::test]
async fn swarm_completes_despite_a_dead_provider() {
    // Two providers: one serves the whole blob, the other's channel is dead (its
    // server side is dropped). The dead provider's assigned chunks are
    // re-partitioned to the live one, so the download still completes.
    let data: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    let id = blob::split(&data).0.id();

    let (client_live, mut server_live) = connected_pair().await;
    let (client_dead, _server_dead) = connected_pair().await; // server side dropped → never answers

    let store = full_store(&data);
    let _live = tokio::spawn(async move {
        let _ = serve_blob(&mut server_live, &store, &Config::default()).await;
    });

    // A short request timeout so the dead provider is retired quickly.
    let cfg = Config {
        request_timeout: Duration::from_millis(200),
        retries: 2,
        idle: Duration::from_secs(2),
        initial_rtt: Duration::from_millis(20),
    };

    // Put the live provider first so the manifest comes from it.
    let got = timeout(
        T,
        download_blob_swarm(vec![client_live, client_dead], id, &cfg),
    )
    .await
    .expect("swarm should finish")
    .expect("swarm should verify");
    assert_eq!(got, data);
}
