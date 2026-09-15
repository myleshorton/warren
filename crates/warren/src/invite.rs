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

/// A regional invitation is a separate versioned format. It is not encrypted or
/// a membership credential; possession reveals the channel keys and peer hints.
#[derive(Clone, Debug)]
pub struct RegionalInvite {
    pub community_language: Option<String>,
    pub community_bootstrap: Option<driver::next::BootstrapState>,
    pub channel_key: String,
    pub content_key: String,
    pub bootstrap: driver::next::BootstrapState,
    pub expires: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegionalWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    community_language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    community_bootstrap: Option<String>,
    version: u8,
    channel: String,
    content: String,
    bootstrap: String,
    expires: u64,
}

impl RegionalInvite {
    /// Export at most eight verified regional contacts. Explicit exclusions are
    /// never bypassed; no global or configured-but-unverified seeds are included.
    pub async fn create(
        node: &crate::regional::RegionalNode,
        channel_key: String,
        content_key: String,
        excluded: &[swarm::NodeId],
        lifetime: std::time::Duration,
    ) -> std::io::Result<Self> {
        if channel_key.is_empty()
            || channel_key.len().saturating_add(content_key.len()) > 1024
            || lifetime.as_secs() == 0
            || lifetime.as_secs() > 86_400
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid invite lifetime or channel",
            ));
        }
        let state = node.bootstrap_state(node.overlay()).await?;
        let contacts = state
            .contacts()
            .iter()
            .copied()
            .filter(|peer| !excluded.contains(&peer.id))
            .take(8)
            .collect::<Vec<_>>();
        if contacts.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "no eligible regional introduction peers",
            ));
        }
        let community_bootstrap = match node.community_endpoint() {
            Some(endpoint) if endpoint.endpoint().dht().overlay() != node.overlay() => {
                let state = endpoint
                    .endpoint()
                    .dht()
                    .bootstrap_state()
                    .await
                    .map_err(std::io::Error::other)?;
                let contacts = state
                    .contacts()
                    .iter()
                    .copied()
                    .filter(|peer| !excluded.contains(&peer.id))
                    .take(8)
                    .collect::<Vec<_>>();
                (!contacts.is_empty())
                    .then(|| driver::next::BootstrapState::in_overlay(contacts, state.overlay()))
            }
            _ => None,
        };
        Ok(Self {
            community_bootstrap,
            community_language: node
                .community()
                .and_then(|c| c.language().map(str::to_owned)),
            channel_key,
            content_key,
            bootstrap: driver::next::BootstrapState::in_overlay(contacts, node.overlay()),
            expires: crate::util::now_secs().saturating_add(lifetime.as_secs()),
        })
    }
    pub fn encode(&self, prefix: &str) -> String {
        let wire = RegionalWire {
            community_bootstrap: self
                .community_bootstrap
                .as_ref()
                .map(|state| to_hex(&state.encode())),
            community_language: self.community_language.clone(),
            version: if self.community_language.is_some() {
                2
            } else {
                1
            },
            channel: self.channel_key.clone(),
            content: self.content_key.clone(),
            bootstrap: to_hex(&self.bootstrap.encode()),
            expires: self.expires,
        };
        format!(
            "{prefix}{}",
            to_hex(&serde_json::to_vec(&wire).expect("regional invite"))
        )
    }
    pub fn decode(prefix: &str, text: &str, now: u64) -> Option<Self> {
        let body = text.trim().strip_prefix(prefix)?;
        if body.len() > 24_576 {
            return None;
        }
        let wire: RegionalWire = serde_json::from_slice(&from_hex(body)?).ok()?;
        if !matches!(
            (wire.version, wire.community_language.is_some()),
            (1, false) | (2, true)
        ) || wire
            .community_language
            .as_ref()
            .is_some_and(|language| crate::community::Community::from_locale(language).is_none())
            || wire.channel.is_empty()
            || wire.channel.len().saturating_add(wire.content.len()) > 1024
            || wire.expires <= now
            || wire.expires > now.saturating_add(86_400)
        {
            return None;
        }
        let bootstrap = driver::next::BootstrapState::decode(&from_hex(&wire.bootstrap)?).ok()?;
        if bootstrap.overlay() == driver::next::OverlayId::Global
            || bootstrap.contacts().is_empty()
            || bootstrap.contacts().len() > 8
        {
            return None;
        }
        let community_bootstrap = match wire.community_bootstrap {
            Some(encoded) => {
                let community =
                    crate::community::Community::from_locale(wire.community_language.as_ref()?)?;
                let state = driver::next::BootstrapState::decode(&from_hex(&encoded)?).ok()?;
                if state.overlay() != community.overlay()
                    || state.contacts().is_empty()
                    || state.contacts().len() > 8
                {
                    return None;
                }
                Some(state)
            }
            None => None,
        };
        Some(Self {
            community_bootstrap,
            community_language: wire.community_language,
            channel_key: wire.channel,
            content_key: wire.content,
            bootstrap,
            expires: wire.expires,
        })
    }
    pub async fn join(&self, node: &crate::regional::RegionalNode) -> std::io::Result<()> {
        if self.expires <= crate::util::now_secs() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "expired invite",
            ));
        }
        if let Some(language) = &self.community_language {
            let expected = crate::community::Community::from_locale(language);
            if expected.as_ref() != node.community() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invitation selects a different community",
                ));
            }
        }
        let mut pending = tokio::task::JoinSet::new();
        for state in std::iter::once(&self.bootstrap).chain(self.community_bootstrap.iter()) {
            if !node.supports_overlay(state.overlay()) {
                continue;
            }
            for peer in state.contacts() {
                let _ = node.add_contact(state.overlay(), *peer).await;
            }
            let state = state.clone();
            let node = node.clone();
            pending.spawn(async move { node.restore_bootstrap(&state).await });
        }
        let mut error = std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "no reachable invitation peers for the configured overlays",
        );
        while let Some(result) = pending.join_next().await {
            match result.map_err(std::io::Error::other).and_then(|r| r) {
                Ok(()) => return Ok(()),
                Err(failure) => error = failure,
            }
        }
        Err(error)
    }
}
