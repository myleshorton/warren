//! End-to-end transfer over real punched UDP channels on loopback: a server
//! serves a feed / blob, a client downloads and verifies it across the channel.

use std::net::SocketAddr;
use std::time::Duration;

use crypto::Keypair;
use driver::{open_channel, Channel, DataListener, PunchConfig};
use feed::Log;
use tokio::time::timeout;
use transfer::{download_blob, download_feed, serve_blob, serve_feed, Config};

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

#[tokio::test]
async fn downloads_a_feed_over_a_channel() {
    let (client_ch, server_ch) = connected_pair().await;

    let mut log = Log::new(Keypair::from_seed(&[1u8; 32]));
    for i in 0..15u8 {
        log.append(vec![i; (i as usize % 5) + 1]);
    }
    let public_key = log.public_key();
    let expected: Vec<Vec<u8>> = (0..15u8).map(|i| vec![i; (i as usize % 5) + 1]).collect();

    // Server answers in the background; client pulls the whole feed.
    tokio::spawn(async move { serve_feed(&server_ch, &log, &Config::default()).await });
    let blocks = timeout(T, download_feed(&client_ch, public_key, &Config::default()))
        .await
        .expect("download should finish")
        .expect("download should verify");
    assert_eq!(blocks, expected);
}

#[tokio::test]
async fn downloads_a_blob_over_a_channel() {
    let (client_ch, server_ch) = connected_pair().await;

    let data: Vec<u8> = (0..40_000).map(|i| i as u8).collect();
    // Chunk well under MAX_DATAGRAM so each Chunk message fits one datagram
    // (the default 64 KiB chunk would not). Store the chunks and the manifest
    // (under its own content address) so the server can serve both.
    let (manifest, chunks) = blob::split_with(&data, 8 * 1024);
    let mut store = blob::Store::new();
    for chunk in chunks {
        store.put(chunk);
    }
    let id = store.put(manifest.encode());

    tokio::spawn(async move { serve_blob(&server_ch, &store, &Config::default()).await });
    let got = timeout(T, download_blob(&client_ch, id, &Config::default()))
        .await
        .expect("download should finish")
        .expect("download should verify");
    assert_eq!(got, data);
}
