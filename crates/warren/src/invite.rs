//! Shareable channel invites.
//!
//! An invite bundles the channel key(s) with one or more bootstrap peers to join
//! the DHT through, so a new member can paste a single string and land in the same
//! channel with a reachable entry point. The wire form is `<prefix><hex>` where
//! `<hex>` is a small JSON payload — hex keeps it URL-safe and copy/paste-proof
//! without a base64 dependency, and the whole thing is opaque to anyone who
//! doesn't already have it. The application chooses `prefix` (its URL scheme).

use serde::{Deserialize, Serialize};

use crate::util::{from_hex, to_hex};
use crate::Peer;

/// A decoded invite: which channel (discovery key), the content key needed to
/// decrypt (empty for a blind-mirror invite), and where to bootstrap in.
#[derive(Debug, Clone)]
pub struct Invite {
    pub channel_key: String,
    pub content_key: String,
    pub bootstrap: Vec<Peer>,
}

/// Compact JSON form with short keys (`k`ey, `c`ontent-key, `b`ootstrap).
#[derive(Serialize, Deserialize)]
struct Wire {
    k: String,
    /// Absent ⇒ a legacy single-key invite (content defaults to the channel key);
    /// present ⇒ the content key (may be empty for a blind-mirror invite).
    #[serde(default)]
    c: Option<String>,
    #[serde(default)]
    b: Vec<WirePeer>,
}

#[derive(Serialize, Deserialize)]
struct WirePeer {
    n: String,
    a: String,
}

/// Encode a discovery key + content key + bootstrap peers into a shareable
/// `<prefix><hex>` invite. Pass an empty `content_key` for a blind-mirror invite.
pub fn encode_invite(
    prefix: &str,
    channel_key: String,
    content_key: String,
    bootstrap: Vec<Peer>,
) -> String {
    let wire = Wire {
        k: channel_key,
        c: Some(content_key),
        b: bootstrap
            .into_iter()
            .map(|p| WirePeer {
                n: p.node_id,
                a: p.addr,
            })
            .collect(),
    };
    // A `Wire` is plain data and can't fail to serialize; `expect` rather than
    // silently emitting an empty/invalid invite on the impossible error.
    let json = serde_json::to_vec(&wire).expect("invite serializes");
    format!("{prefix}{}", to_hex(&json))
}

/// Parse a `<prefix><hex>` invite. Returns `None` if it isn't a well-formed invite
/// or carries no channel key. Whitespace is trimmed so a pasted string with stray
/// newlines still works.
pub fn decode_invite(prefix: &str, text: &str) -> Option<Invite> {
    let body = text.trim().strip_prefix(prefix)?;
    let json = from_hex(body)?;
    let wire: Wire = serde_json::from_slice(&json).ok()?;
    if wire.k.is_empty() {
        return None;
    }
    // Legacy invite (no `c`) ⇒ single-key channel: content = discovery key.
    let content_key = wire.c.unwrap_or_else(|| wire.k.clone());
    Some(Invite {
        channel_key: wire.k,
        content_key,
        bootstrap: wire
            .b
            .into_iter()
            .map(|p| Peer {
                node_id: p.n,
                addr: p.a,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PFX: &str = "warren://";

    #[test]
    fn invite_round_trips() {
        let peers = vec![
            Peer {
                node_id: "ab12".repeat(16),
                addr: "1.2.3.4:9000".into(),
            },
            Peer {
                node_id: "cd34".repeat(16),
                addr: "[::1]:7000".into(),
            },
        ];
        let s = encode_invite(
            PFX,
            "my-secret-channel".into(),
            "the-content-key".into(),
            peers.clone(),
        );
        assert!(s.starts_with(PFX));

        let back = decode_invite(PFX, &s).expect("decodes");
        assert_eq!(back.channel_key, "my-secret-channel");
        assert_eq!(back.content_key, "the-content-key");
        assert_eq!(back.bootstrap, peers);
    }

    #[test]
    fn blind_mirror_invite_carries_no_content_key() {
        let s = encode_invite(PFX, "chan".into(), String::new(), vec![]);
        let back = decode_invite(PFX, &s).unwrap();
        assert_eq!(back.channel_key, "chan");
        assert!(
            back.content_key.is_empty(),
            "blind: discovery only, no content key"
        );
    }

    #[test]
    fn tolerates_surrounding_whitespace() {
        let s = encode_invite(PFX, "chan".into(), "chan".into(), vec![]);
        let padded = format!("  \n{s}\n ");
        assert_eq!(decode_invite(PFX, &padded).unwrap().channel_key, "chan");
    }

    #[test]
    fn rejects_junk_and_empty_channel() {
        assert!(decode_invite(PFX, "hello").is_none());
        assert!(decode_invite(PFX, "warren://zzzz").is_none()); // not hex
        assert!(decode_invite(PFX, "warren://").is_none()); // empty payload
        let empty_key = encode_invite(PFX, "".into(), "".into(), vec![]);
        assert!(decode_invite(PFX, &empty_key).is_none());
    }
}
