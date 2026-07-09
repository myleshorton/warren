//! Property tests for feed sync: an honest server always yields the exact feed,
//! a tampered block is always rejected, and the message codec is panic-free and
//! round-trips.

use crypto::Keypair;
use feed::Log;
use proptest::prelude::*;
use sync::{serve_feed, FeedDownload, Message, SyncError};

fn arb_blocks() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 0..40)
}

fn build(blocks: &[Vec<u8>]) -> Log {
    let mut log = Log::new(Keypair::from_seed(&[5u8; 32]));
    for b in blocks {
        log.append(b.clone());
    }
    log
}

/// Drive a download against `server` to completion (honest responses).
fn run(dl: &mut FeedDownload, server: &Log) {
    let mut steps = 0;
    while let Some(request) = dl.poll_request() {
        let response = serve_feed(&request, server);
        dl.handle_response(&response)
            .expect("honest response verifies");
        steps += 1;
        assert!(steps < 1_000_000, "sync must terminate");
    }
}

proptest! {
    /// Syncing from an honest server yields exactly the server's blocks.
    #[test]
    fn honest_sync_reproduces_the_feed(blocks in arb_blocks()) {
        let server = build(&blocks);
        let mut dl = FeedDownload::new(server.public_key());
        run(&mut dl, &server);
        prop_assert!(dl.is_complete());
        prop_assert_eq!(dl.into_blocks(), blocks);
    }

    /// A block response tampered in any byte is rejected — the client never
    /// accepts data that doesn't verify against the signed head.
    #[test]
    fn a_tampered_block_is_always_rejected(blocks in arb_blocks(), seed in any::<u64>()) {
        prop_assume!(!blocks.is_empty());
        let server = build(&blocks);
        let mut dl = FeedDownload::new(server.public_key());
        dl.handle_response(&serve_feed(&Message::GetHead, &server)).unwrap();

        let index = (seed % blocks.len() as u64) as usize;
        let mut resp = serve_feed(&Message::GetBlock { index: index as u64 }, &server);
        if let Message::Block { data, .. } = &mut resp {
            // Perturb the block bytes (flip a byte, or add one if empty).
            match data.first_mut() {
                Some(b) => *b ^= 1,
                None => data.push(0),
            }
            prop_assert_eq!(dl.handle_response(&resp), Err(SyncError::BadBlock));
        }
    }

    /// Decoding arbitrary bytes never panics.
    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Message::decode(&bytes);
    }

    /// Every protocol message round-trips through its codec.
    #[test]
    fn messages_roundtrip(blocks in arb_blocks(), idx in any::<u64>()) {
        let server = build(&blocks);
        let mut msgs = vec![
            Message::GetHead,
            Message::Head(server.head()),
            Message::GetBlock { index: idx },
            Message::Absent,
        ];
        if !blocks.is_empty() {
            let i = idx % blocks.len() as u64;
            msgs.push(serve_feed(&Message::GetBlock { index: i }, &server));
        }
        for m in msgs {
            prop_assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }
}
