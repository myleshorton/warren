//! Shareable channel invitations with bounded JSON encoded as hex.
//! The application chooses the URL prefix. Hex is not encryption: holders can
//! read the channel keys and peer hints.

use crate::util::{from_hex, to_hex};
use crate::Peer;
use serde::{Deserialize, Serialize};

/// Maximum language communities advertised by one invitation or session.
pub const MAX_COMMUNITIES: usize = 4;
/// Maximum hex body of one invitation envelope, application metadata included.
pub const MAX_INVITE_HEX: usize = 16 * 1024;
/// Combined discovery and effective content key size, shared by both formats.
pub const MAX_INVITE_KEY_BYTES: usize = 1024;
/// The snapshot-based regional format carries bulkier bootstrap state.
const MAX_REGIONAL_INVITE_HEX: usize = 24 * 1024;

/// Bootstrap hints belong exclusively to the DHT derived from `language`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityPeers {
    pub language: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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

/// Shared invitation payload with optional separate content keys.
/// Applications may flatten this into an envelope containing their own metadata.
/// Hex encoding does not encrypt the keys or peer addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitePayload {
    pub channel_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    /// Validate the complete invitation at a given time, including snapshots
    /// supplied directly by callers rather than through `create`.
    pub fn validate(&self, now: u64) -> std::io::Result<()> {
        let invalid = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid regional invitation",
            )
        };
        if self.channel_key.is_empty()
            || self
                .channel_key
                .len()
                .saturating_add(self.content_key.len())
                > MAX_INVITE_KEY_BYTES
            || self.expires <= now
            || self.expires > now.saturating_add(86_400)
            || self.community_language.as_ref().is_some_and(|language| {
                crate::community::Community::from_locale(language).is_none()
            })
        {
            return Err(invalid());
        }
        for state in std::iter::once(&self.bootstrap).chain(self.community_bootstrap.iter()) {
            if state.overlay() == driver::next::OverlayId::Global
                || state.contacts().is_empty()
                || state.contacts().len() > 8
            {
                return Err(invalid());
            }
            driver::next::BootstrapState::decode(&state.encode()).map_err(|_| invalid())?;
        }
        if let (Some(language), Some(state)) = (&self.community_language, &self.community_bootstrap)
        {
            let community =
                crate::community::Community::from_locale(language).ok_or_else(invalid)?;
            if state.overlay() != community.overlay() {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Encode only invitations valid at the current time.
    pub fn encode(&self, prefix: &str) -> std::io::Result<String> {
        self.encode_at(prefix, crate::util::now_secs())
    }

    fn encode_at(&self, prefix: &str, now: u64) -> std::io::Result<String> {
        self.validate(now)?;
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
        let json = serde_json::to_vec(&wire).map_err(std::io::Error::other)?;
        if json.len() > MAX_REGIONAL_INVITE_HEX / 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "regional invite too large",
            ));
        }
        Ok(format!("{prefix}{}", to_hex(&json)))
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
        if !valid_version {
            return None;
        }
        let bootstrap = driver::next::BootstrapState::decode(&from_hex(&wire.bootstrap)?).ok()?;
        let community_bootstrap = match wire.community_bootstrap {
            Some(encoded) => Some(driver::next::BootstrapState::decode(&from_hex(&encoded)?).ok()?),
            None => None,
        };
        let invite = Self {
            community_bootstrap,
            community_language: wire.community_language,
            channel_key: wire.channel,
            content_key: wire.content,
            bootstrap,
            expires: wire.expires,
        };
        invite.validate(now).ok()?;
        Some(invite)
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
    fn application_metadata_flattens_around_the_shared_payload() {
        #[derive(Serialize, Deserialize)]
        struct ApplicationInvite {
            #[serde(flatten)]
            payload: InvitePayload,
            founder: String,
        }
        // Only `channel_key` is required; everything else defaults, so an envelope
        // carrying just its own metadata still parses.
        let minimal = format!(
            "app://{}",
            to_hex(br#"{"channel_key":"chan","founder":"founder-key"}"#)
        );
        let envelope: ApplicationInvite = decode_payload("app://", &minimal).unwrap();
        envelope.payload.validate().unwrap();
        assert_eq!(envelope.payload.content_key(), "chan");
        assert!(envelope.payload.communities.is_empty());
        let encoded = encode_payload("app://", &envelope).unwrap();
        let decoded: ApplicationInvite = decode_payload("app://", &encoded).unwrap();
        assert_eq!(decoded.founder, "founder-key");
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

    /// Whatever an encoder accepts, the matching decoder must accept back.
    ///
    /// Three separate defects in this module had that exact shape: a version-1
    /// regional invite that carried `community_bootstrap` (the version field and
    /// the optional field disagreed), an invitation built on a global overlay
    /// (which `decode` rejects unconditionally), and an envelope encoder with no
    /// size bound against a decoder that had one. Each produced a string that
    /// encoded cleanly and that no recipient could ever open, and each was caught
    /// by reading rather than by a test. This sweeps those three dimensions --
    /// optional-field presence, overlay kind, and size boundaries -- across both
    /// formats so the next one fails here instead.
    #[test]
    fn whatever_encodes_must_decode() {
        const NOW: u64 = 1_700_000_000;
        let contact = || {
            swarm::Contact::new(
                swarm::NodeId::from_bytes([7; 32]),
                "192.0.2.1:9000".parse().unwrap(),
            )
        };
        let peer = || Peer {
            node_id: "ab".repeat(32),
            addr: "127.0.0.1:1234".into(),
        };

        // --- InvitePayload: encode() validates, so Ok(..) must always decode.
        let languages = ["fa", "en", "ru", "de"];
        for content_key in [None, Some(String::new()), Some("content".to_owned())] {
            for bootstrap in [0usize, 1, 8] {
                for groups in [0usize, 1, MAX_COMMUNITIES] {
                    for peers in [0usize, 1, 8] {
                        for channel_len in [1usize, MAX_INVITE_KEY_BYTES / 2] {
                            let payload = InvitePayload {
                                channel_key: "k".repeat(channel_len),
                                content_key: content_key.clone(),
                                bootstrap: vec![peer(); bootstrap],
                                communities: languages[..groups]
                                    .iter()
                                    .map(|language| CommunityPeers {
                                        language: (*language).to_owned(),
                                        peers: vec![peer(); peers],
                                    })
                                    .collect(),
                            };
                            let label = format!(
                                "content={content_key:?} bootstrap={bootstrap} groups={groups} peers={peers} channel={channel_len}"
                            );
                            let Ok(encoded) = payload.encode("app://") else {
                                continue; // Refused up front is fine; silently unopenable is not.
                            };
                            let decoded = InvitePayload::decode("app://", &encoded)
                                .unwrap_or_else(|| panic!("encoded but did not decode: {label}"));
                            assert_eq!(decoded.channel_key, payload.channel_key, "{label}");
                            assert_eq!(decoded.content_key(), payload.content_key(), "{label}");
                            assert_eq!(decoded.bootstrap, payload.bootstrap, "{label}");
                            assert_eq!(decoded.communities, payload.communities, "{label}");
                        }
                    }
                }
            }
        }

        // Regional encoding validates the same constraints as decoding.
        let local = driver::next::OverlayId::regional("local-domain");
        let farsi = crate::community::Community::from_locale("fa").unwrap();
        for language in [None, Some("fa".to_owned())] {
            for carries_community in [false, true] {
                for keys in [(1usize, 0usize), (MAX_INVITE_KEY_BYTES - 1, 1)] {
                    let community_overlay = match &language {
                        Some(_) => farsi.overlay(),
                        None => driver::next::OverlayId::regional("opaque-community"),
                    };
                    let invite = RegionalInvite {
                        community_language: language.clone(),
                        community_bootstrap: carries_community.then(|| {
                            driver::next::BootstrapState::in_overlay(
                                vec![contact()],
                                community_overlay,
                            )
                        }),
                        channel_key: "k".repeat(keys.0),
                        content_key: "c".repeat(keys.1),
                        bootstrap: driver::next::BootstrapState::in_overlay(vec![contact()], local),
                        expires: NOW + 600,
                    };
                    let label = format!(
                        "language={language:?} community={carries_community} keys={keys:?}"
                    );
                    let encoded = invite.encode_at("warren://", NOW).unwrap();
                    let decoded = RegionalInvite::decode("warren://", &encoded, NOW)
                        .unwrap_or_else(|| panic!("encoded but did not decode: {label}"));
                    assert_eq!(
                        decoded.community_language, invite.community_language,
                        "{label}"
                    );
                    assert_eq!(decoded.channel_key, invite.channel_key, "{label}");
                    assert_eq!(decoded.content_key, invite.content_key, "{label}");
                    assert_eq!(
                        decoded.community_bootstrap.is_some(),
                        carries_community,
                        "{label}"
                    );
                    assert_eq!(decoded.bootstrap.overlay(), local, "{label}");
                }
            }
        }

        let global_backed = RegionalInvite {
            community_language: None,
            community_bootstrap: None,
            channel_key: "channel".into(),
            content_key: String::new(),
            bootstrap: driver::next::BootstrapState::in_overlay(
                vec![contact()],
                driver::next::OverlayId::Global,
            ),
            expires: NOW + 600,
        };
        assert!(global_backed.encode_at("warren://", NOW).is_err());
    }

    #[test]
    fn regional_encode_and_decode_reject_the_same_invalid_values() {
        use driver::next::{BootstrapState, OverlayId};
        const NOW: u64 = 1_700_000_000;
        let scope = crate::community::Community::from_locale("fa")
            .unwrap()
            .overlay();
        let state = |scope, count: u8| {
            BootstrapState::in_overlay(
                (1..=count)
                    .map(|n| {
                        swarm::Contact::new(
                            swarm::NodeId::from_bytes([n; 32]),
                            format!("192.0.2.{n}:9000").parse().unwrap(),
                        )
                    })
                    .collect(),
                scope,
            )
        };
        let valid = RegionalInvite {
            community_language: Some("fa".into()),
            community_bootstrap: Some(state(scope, 8)),
            channel_key: "k".repeat(MAX_INVITE_KEY_BYTES),
            content_key: String::new(),
            bootstrap: state(OverlayId::regional("local"), 8),
            expires: NOW + 86_400,
        };
        let encoded = valid.encode_at("region://", NOW).unwrap();
        assert!(RegionalInvite::decode("region://", &encoded, NOW).is_some());
        let mut cases = vec![];
        for expires in [NOW - 1, NOW, NOW + 86_401] {
            cases.push((
                "expiry",
                RegionalInvite {
                    expires,
                    ..valid.clone()
                },
            ));
        }
        for channel_key in [String::new(), "k".repeat(MAX_INVITE_KEY_BYTES + 1)] {
            cases.push((
                "channel key",
                RegionalInvite {
                    channel_key,
                    ..valid.clone()
                },
            ));
        }
        cases.push((
            "combined keys",
            RegionalInvite {
                content_key: "c".into(),
                ..valid.clone()
            },
        ));
        cases.push((
            "language",
            RegionalInvite {
                community_language: Some("und".into()),
                ..valid.clone()
            },
        ));
        cases.push((
            "mismatched community",
            RegionalInvite {
                community_language: Some("ru".into()),
                ..valid.clone()
            },
        ));
        for (scope, count) in [(OverlayId::Global, 1), (scope, 0), (scope, 9)] {
            cases.push((
                "primary snapshot",
                RegionalInvite {
                    bootstrap: state(scope, count),
                    ..valid.clone()
                },
            ));
            cases.push((
                "community snapshot",
                RegionalInvite {
                    community_bootstrap: Some(state(scope, count)),
                    ..valid.clone()
                },
            ));
        }
        for (label, invite) in cases {
            assert!(invite.encode_at("region://", NOW).is_err(), "{label}");
            // Forge the corresponding wire input independently of the encoder.
            let wire = serde_json::json!({
                "version": 2, "community_language": invite.community_language,
                "community_bootstrap": invite.community_bootstrap.map(|s| to_hex(&s.encode())),
                "channel": invite.channel_key, "content": invite.content_key,
                "bootstrap": to_hex(&invite.bootstrap.encode()), "expires": invite.expires,
            });
            let encoded = format!("region://{}", to_hex(&serde_json::to_vec(&wire).unwrap()));
            assert!(
                RegionalInvite::decode("region://", &encoded, NOW).is_none(),
                "{label}"
            );
        }
        let mut wrong_version: serde_json::Value =
            serde_json::from_slice(&from_hex(encoded.strip_prefix("region://").unwrap()).unwrap())
                .unwrap();
        wrong_version["version"] = 1.into();
        let encoded = format!(
            "region://{}",
            to_hex(&serde_json::to_vec(&wrong_version).unwrap())
        );
        assert!(RegionalInvite::decode("region://", &encoded, NOW).is_none());
        assert!(RegionalInvite::decode(
            "region://",
            &format!("region://{}", "0".repeat(MAX_REGIONAL_INVITE_HEX + 1)),
            NOW
        )
        .is_none());
    }

    #[test]
    fn wire_shape_is_readable_and_omits_defaulted_fields() {
        // One `Peer` representation everywhere, and nothing is written just to say
        // "absent": a missing content key already means "content = channel key",
        // and a named community with no reachable peers is still membership metadata.
        let fixture = serde_json::json!({
            "channel_key": "channel",
            "bootstrap": [{ "node_id": "ab".repeat(32), "addr": "127.0.0.1:1234" }],
            "communities": [
                { "language": "fa", "peers": [{ "node_id": "cd".repeat(32), "addr": "127.0.0.1:5678" }] },
                { "language": "en" },
            ]
        });
        let payload =
            InvitePayload::decode("app://", &encode_payload("app://", &fixture).unwrap()).unwrap();
        assert!(payload.content_key.is_none());
        assert!(payload.communities[1].peers.is_empty());
        let reencoded = payload.encode("app://").unwrap();
        assert_eq!(
            decode_payload::<serde_json::Value>("app://", &reencoded).unwrap(),
            fixture,
            "re-encoding must reproduce the fixture exactly: one peer shape, no defaulted fields"
        );
    }
}
