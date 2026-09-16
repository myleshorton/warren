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

/// Maximum language communities advertised by one invitation or session.
pub const MAX_COMMUNITIES: usize = 4;
/// Preserve the existing Murmur-compatible envelope limit.
pub const MAX_INVITE_HEX: usize = 16 * 1024;
/// Combined discovery and effective content key size, shared by both formats.
pub const MAX_INVITE_KEY_BYTES: usize = 1024;
/// The older snapshot-based regional format retains its original wire limit.
const MAX_REGIONAL_INVITE_HEX: usize = 24 * 1024;

/// Bootstrap hints belong exclusively to the DHT derived from `language`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityPeers {
    pub language: String,
    pub peers: Vec<Peer>,
}

/// Validate canonical language names, unique scopes, and bounded peer hints.
pub fn validate_communities(groups: &[CommunityPeers]) -> std::io::Result<()> {
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid discovery communities",
        )
    };
    if groups.len() > MAX_COMMUNITIES {
        return Err(invalid());
    }
    let mut seen = std::collections::HashSet::new();
    for group in groups {
        let community =
            crate::community::Community::from_locale(&group.language).ok_or_else(invalid)?;
        if community.language() != Some(group.language.as_str())
            || !seen.insert(&group.language)
            || group.peers.len() > 8
        {
            return Err(invalid());
        }
        for peer in &group.peers {
            let addr: std::net::SocketAddr = peer.addr.parse().map_err(|_| invalid())?;
            if crate::util::hash_from_hex(&peer.node_id).is_none()
                || addr.port() == 0
                || addr.ip().is_unspecified()
                || addr.ip().is_multicast()
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

/// Shared invitation payload, compatible with legacy single-key invitations.
/// Applications may flatten this into an envelope containing their own metadata.
/// Hex encoding does not encrypt the keys or peer addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitePayload {
    #[serde(rename = "k")]
    pub channel_key: String,
    #[serde(rename = "c", default)]
    pub content_key: Option<String>,
    #[serde(rename = "b", default, with = "compact_peers")]
    pub bootstrap: Vec<Peer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub communities: Vec<CommunityPeers>,
}

impl InvitePayload {
    pub fn validate(&self) -> std::io::Result<()> {
        if self.channel_key.is_empty()
            || self
                .channel_key
                .len()
                .saturating_add(self.content_key().len())
                > MAX_INVITE_KEY_BYTES
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty or oversized channel keys",
            ));
        }
        validate_communities(&self.communities)
    }

    pub fn content_key(&self) -> &str {
        self.content_key.as_deref().unwrap_or(&self.channel_key)
    }

    /// Encode a validated payload. Application envelopes should use `encode_payload`.
    pub fn encode(&self, prefix: &str) -> std::io::Result<String> {
        self.validate()?;
        encode_payload(prefix, self)
    }

    pub fn decode(prefix: &str, text: &str) -> Option<Self> {
        let payload: Self = decode_payload(prefix, text)?;
        payload.validate().ok()?;
        Some(payload)
    }
}

/// Serialize a bounded payload or application envelope. The application validates
/// its metadata and shared payload first. Serialization and size failures are
/// returned as errors, including when application metadata exceeds the wire cap.
pub fn encode_payload<T: Serialize>(prefix: &str, payload: &T) -> std::io::Result<String> {
    let json = serde_json::to_vec(payload).map_err(std::io::Error::other)?;
    if json.len() > MAX_INVITE_HEX / 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invite too large",
        ));
    }
    Ok(format!("{prefix}{}", to_hex(&json)))
}

/// Decode a bounded payload or application envelope. Callers must validate the
/// shared payload and their own metadata before using it.
pub fn decode_payload<T: serde::de::DeserializeOwned>(prefix: &str, text: &str) -> Option<T> {
    let body = text.trim().strip_prefix(prefix)?;
    if body.len() > MAX_INVITE_HEX {
        return None;
    }
    serde_json::from_slice(&from_hex(body)?).ok()
}

mod compact_peers {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        peers: &[Peer],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        peers
            .iter()
            .map(|p| WirePeer {
                n: p.node_id.clone(),
                a: p.addr.clone(),
            })
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Peer>, D::Error> {
        Ok(Vec::<WirePeer>::deserialize(deserializer)?
            .into_iter()
            .map(|p| Peer {
                node_id: p.n,
                addr: p.a,
            })
            .collect())
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
            || channel_key.len().saturating_add(content_key.len()) > MAX_INVITE_KEY_BYTES
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
            version: if self.community_language.is_some() || self.community_bootstrap.is_some() {
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
        if body.len() > MAX_REGIONAL_INVITE_HEX {
            return None;
        }
        let wire: RegionalWire = serde_json::from_slice(&from_hex(body)?).ok()?;
        let valid_version = match wire.version {
            1 => wire.community_language.is_none() && wire.community_bootstrap.is_none(),
            2 => wire.community_language.is_some() || wire.community_bootstrap.is_some(),
            _ => false,
        };
        if !valid_version
            || wire.community_language.as_ref().is_some_and(|language| {
                crate::community::Community::from_locale(language).is_none()
            })
            || wire.channel.is_empty()
            || wire.channel.len().saturating_add(wire.content.len()) > MAX_INVITE_KEY_BYTES
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
                let community = wire
                    .community_language
                    .as_deref()
                    .and_then(crate::community::Community::from_locale);
                let state = driver::next::BootstrapState::decode(&from_hex(&encoded)?).ok()?;
                if state.overlay() == driver::next::OverlayId::Global
                    || community.is_some_and(|community| state.overlay() != community.overlay())
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
    /// Join through the first reachable compatible overlay. All accepted hints are
    /// installed first; success cancels sibling revalidation lookups so an offline
    /// external overlay cannot delay local joining. Sibling bootstrap is best effort.
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
        let mut rejected = 0;
        let mut considered = 0;
        for state in std::iter::once(&self.bootstrap).chain(self.community_bootstrap.iter()) {
            if !node.supports_overlay(state.overlay()) {
                continue;
            }
            let mut accepted = Vec::new();
            for peer in state.contacts() {
                considered += 1;
                match node.add_contact(state.overlay(), *peer).await {
                    Ok(()) => accepted.push(*peer),
                    Err(error)
                        if error.get_ref().is_some_and(|cause| {
                            cause.is::<crate::network::AddressPolicyRejected>()
                        }) =>
                    {
                        rejected += 1
                    }
                    Err(error) => return Err(error),
                }
            }
            if accepted.is_empty() {
                continue;
            }
            let state = driver::next::BootstrapState::in_overlay(accepted, state.overlay());
            let node = node.clone();
            pending.spawn(async move { node.restore_bootstrap(&state).await });
        }
        if pending.is_empty() && rejected > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{rejected} of {considered} invite peers outside the configured domain"),
            ));
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

#[cfg(test)]
mod community_payload_tests {
    use super::*;

    #[test]
    fn rejects_invalid_scopes_and_peer_hints() {
        let valid = CommunityPeers {
            language: "fa".into(),
            peers: vec![Peer {
                node_id: "ab".repeat(32),
                addr: "127.0.0.1:1234".into(),
            }],
        };
        validate_communities(std::slice::from_ref(&valid)).unwrap();
        assert!(validate_communities(&[valid.clone(), valid.clone()]).is_err());
        for language in ["fa-IR", "FA", "../fa", "und", ""] {
            let mut group = valid.clone();
            group.language = language.into();
            assert!(validate_communities(&[group]).is_err());
        }
        for address in ["0.0.0.0:1", "[::]:1", "127.0.0.1:0", "224.0.0.1:1", "bad"] {
            let mut group = valid.clone();
            group.peers[0].addr = address.into();
            assert!(validate_communities(&[group]).is_err());
        }
        let mut group = valid.clone();
        group.peers[0].node_id = "abcd".into();
        assert!(validate_communities(&[group]).is_err());
        let mut group = valid.clone();
        group.peers = vec![valid.peers[0].clone(); 9];
        assert!(validate_communities(&[group]).is_err());
        let groups = ["en", "fa", "ru", "de", "fr"]
            .into_iter()
            .map(|language| CommunityPeers {
                language: language.into(),
                peers: vec![],
            })
            .collect::<Vec<_>>();
        assert!(validate_communities(&groups).is_err());
    }

    #[test]
    fn legacy_payloads_and_application_metadata_remain_compatible() {
        #[derive(Serialize, Deserialize)]
        struct ApplicationInvite {
            #[serde(flatten)]
            payload: InvitePayload,
            f: String,
        }
        let old = format!("app://{}", to_hex(br#"{"k":"legacy","f":"founder"}"#));
        let envelope: ApplicationInvite = decode_payload("app://", &old).unwrap();
        envelope.payload.validate().unwrap();
        assert_eq!(envelope.payload.content_key(), "legacy");
        assert!(envelope.payload.communities.is_empty());
        let encoded = encode_payload("app://", &envelope).unwrap();
        let decoded: ApplicationInvite = decode_payload("app://", &encoded).unwrap();
        assert_eq!(decoded.f, "founder");
        let oversized = format!("app://{}", "0".repeat(MAX_INVITE_HEX + 1));
        assert!(decode_payload::<InvitePayload>("app://", &oversized).is_none());
    }
    #[test]
    fn envelope_encoding_bounds_application_metadata_and_returns_serialization_errors() {
        #[derive(Serialize, Deserialize)]
        struct Envelope {
            #[serde(flatten)]
            payload: InvitePayload,
            metadata: String,
        }
        let mut envelope = Envelope {
            payload: InvitePayload {
                channel_key: "channel".into(),
                content_key: None,
                bootstrap: vec![],
                communities: vec![],
            },
            metadata: String::new(),
        };
        envelope.payload.validate().unwrap();
        let overhead = serde_json::to_vec(&envelope).unwrap().len();
        envelope.metadata = "x".repeat(MAX_INVITE_HEX / 2 - overhead);
        let encoded = encode_payload("app://", &envelope).unwrap();
        assert_eq!(encoded.len() - "app://".len(), MAX_INVITE_HEX);
        assert!(decode_payload::<Envelope>("app://", &encoded).is_some());
        envelope.metadata.push('x');
        assert_eq!(
            encode_payload("app://", &envelope).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        struct Unserializable;
        impl Serialize for Unserializable {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(
                    "intentional serialization failure",
                ))
            }
        }
        assert!(encode_payload("app://", &Unserializable).is_err());
    }

    #[test]
    fn key_limits_apply_to_validation_and_untrusted_decoding() {
        let mut payload = InvitePayload {
            channel_key: "k".repeat(MAX_INVITE_KEY_BYTES),
            content_key: Some(String::new()),
            bootstrap: vec![],
            communities: vec![],
        };
        payload.validate().unwrap();
        assert!(InvitePayload::decode("app://", &payload.encode("app://").unwrap()).is_some());
        payload.content_key = Some("c".into());
        assert!(payload.validate().is_err());
        assert!(payload.encode("app://").is_err());
        let untrusted = encode_payload("app://", &payload).unwrap();
        assert!(InvitePayload::decode("app://", &untrusted).is_none());
        payload.channel_key = "k".into();
        payload.content_key = Some("c".repeat(MAX_INVITE_KEY_BYTES));
        assert!(payload.validate().is_err());
        payload.content_key = None;
        payload.channel_key = "k".repeat(MAX_INVITE_KEY_BYTES / 2);
        payload.validate().unwrap();
        payload.channel_key.push('k');
        assert!(payload.validate().is_err());
    }

    #[test]
    fn existing_murmur_peer_field_names_are_preserved() {
        let fixture = serde_json::json!({
            "k": "channel", "c": null,
            "b": [{ "n": "ab".repeat(32), "a": "127.0.0.1:1234" }],
            "communities": [{ "language": "fa", "peers": [{
                "node_id": "cd".repeat(32), "addr": "127.0.0.1:5678"
            }] }]
        });
        let encoded = encode_payload("app://", &fixture).unwrap();
        let payload = InvitePayload::decode("app://", &encoded).unwrap();
        let reencoded = payload.encode("app://").unwrap();
        assert_eq!(
            decode_payload::<serde_json::Value>("app://", &reencoded).unwrap(),
            fixture
        );
    }
}
