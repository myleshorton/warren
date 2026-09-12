//! Run an isolated public-key connection through DHT signaling on loopback.
use crypto::Keypair;
use driver::next::Node;
use swarm::Contact;
use transfer::{next::Endpoint, Link};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let router = Node::bind("127.0.0.1:0".parse()?, Keypair::generate(), true).await?;
    let seeds = [Contact::new(router.id(), router.local_addr())];
    let server = Endpoint::bind("127.0.0.1:0".parse()?, Keypair::generate(), false).await?;
    let client = Endpoint::bind("127.0.0.1:0".parse()?, Keypair::generate(), false).await?;
    let mut listener = server.listen(&seeds).await?;
    let (outgoing, incoming) = tokio::try_join!(
        client.connect(server.public_key(), &seeds),
        listener.accept()
    )?;
    assert_eq!(outgoing.remote_public_key(), server.public_key());
    assert_eq!(incoming.remote_public_key(), client.public_key());
    assert_eq!(outgoing.session(), incoming.session());
    outgoing
        .send(b"hello through decentralized signaling")
        .await?;
    let mut bytes = [0; 256];
    let len = incoming.recv(&mut bytes).await?;
    assert_eq!(&bytes[..len], b"hello through decentralized signaling");
    incoming.send(b"authenticated reply").await?;
    let len = outgoing.recv(&mut bytes).await?;
    assert_eq!(&bytes[..len], b"authenticated reply");
    let previous_session = outgoing.session();
    server
        .network_changed("127.0.0.1:0".parse()?, &seeds)
        .await?;
    client
        .network_changed("127.0.0.1:0".parse()?, &seeds)
        .await?;
    assert_eq!(
        outgoing.send(b"obsolete path").await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    drop(outgoing);
    drop(incoming);
    let (outgoing, incoming) = tokio::try_join!(
        client.connect(server.public_key(), &seeds),
        listener.accept()
    )?;
    assert_ne!(outgoing.session(), previous_session);
    outgoing.send(b"recovered through DHT signaling").await?;
    let len = incoming.recv(&mut bytes).await?;
    assert_eq!(&bytes[..len], b"recovered through DHT signaling");
    println!("Public-key discovery, DHT signaling, direct punching and authenticated transfer and network-change reconnection succeeded.");
    listener.close().await;
    for node in [&router, server.dht(), client.dht()] {
        node.shutdown().await?;
    }
    Ok(())
}
