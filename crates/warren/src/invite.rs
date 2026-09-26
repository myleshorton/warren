//! Shareable channel invitations in a compact, checksummed binary format.
//! The application chooses the text prefix. Base64url is not encryption:
//! holders can read the channel keys and peer hints.
//!
//! Wire layout (version 1), carried as unpadded base64url after the prefix:
//!
//! ```text
//! version (1) | record* | checksum (4)
//! record   = tag (1) | length (minimal LEB128) | value
//! checksum = BLAKE3("warren-invite-v1\0" || version || records)[..4]
//! ```
//!
//! Records appear in ascending tag order. Only bootstrap peers and communities
//! repeat. Tags `APP_TAG_MIN..=APP_TAG_MAX` carry application extensions, and
//! every other unassigned tag is rejected, so each invitation has exactly one
//! encoding.

use crate::util::{from_base64url, from_hex, hash_from_hex, to_base64url, to_hex};
use crate::Peer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Maximum language communities advertised by one invitation or session.
pub const MAX_COMMUNITIES: usize = 4;
/// Maximum peers hinted for one language community.
pub const MAX_COMMUNITY_PEERS: usize = 8;
/// Maximum bootstrap peers carried by one invitation.
pub const MAX_BOOTSTRAP_PEERS: usize = 16;
/// Maximum binary size of one invitation, application extensions included.
pub const MAX_INVITE_BYTES: usize = 8 * 1024;
/// Maximum base64url text after the prefix, matching `MAX_INVITE_BYTES`.
pub const MAX_INVITE_TEXT: usize = (MAX_INVITE_BYTES * 4).div_ceil(3);
/// Combined discovery and effective content key size, shared by both formats.
pub const MAX_INVITE_KEY_BYTES: usize = 1024;
/// The snapshot-based regional format carries bulkier bootstrap state.
const MAX_REGIONAL_INVITE_HEX: usize = 24 * 1024;

/// First tag reserved for application extensions.
pub const APP_TAG_MIN: u8 = 0x40;
/// Last tag reserved for application extensions.
pub const APP_TAG_MAX: u8 = 0x7f;

/// Application-defined invitation fields keyed by a tag in
/// `APP_TAG_MIN..=APP_TAG_MAX`. Warren carries the bytes without interpreting them.
pub type Extensions = BTreeMap<u8, Vec<u8>>;

const FORMAT_VERSION: u8 = 1;
const CHECKSUM_LEN: usize = 4;
const CHECKSUM_DOMAIN: &[u8] = b"warren-invite-v1\0";
const TAG_CHANNEL_PACKED: u8 = 0x01;
const TAG_CHANNEL_RAW: u8 = 0x02;
const TAG_CONTENT_PACKED: u8 = 0x03;
const TAG_CONTENT_RAW: u8 = 0x04;
const TAG_BOOTSTRAP: u8 = 0x05;
const TAG_COMMUNITY: u8 = 0x06;
const FAMILY_V4: u8 = 4;
const FAMILY_V6: u8 = 6;

/// Bootstrap hints belong exclusively to the DHT derived from `language`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityPeers {
    pub language: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<Peer>,
}

fn invalid_input(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

/// A peer hint must name a 32-byte node id and a dialable socket address.
fn peer_address(peer: &Peer) -> Option<([u8; 32], SocketAddr)> {
    let addr: SocketAddr = peer.addr.parse().ok()?;
    let node = hash_from_hex(&peer.node_id)?;
    (addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast())
        .then_some((node, addr))
}

/// Validate canonical language names, unique scopes, and bounded peer hints.
pub fn validate_communities(groups: &[CommunityPeers]) -> std::io::Result<()> {
    let invalid = || invalid_input("invalid discovery communities");
    if groups.len() > MAX_COMMUNITIES {
        return Err(invalid());
    }
    let mut seen = std::collections::HashSet::new();
    for group in groups {
        let community =
            crate::community::Community::from_locale(&group.language).ok_or_else(invalid)?;
        if community.language() != Some(group.language.as_str())
            || !seen.insert(&group.language)
            || group.peers.len() > MAX_COMMUNITY_PEERS
            || group.peers.iter().any(|peer| peer_address(peer).is_none())
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Shared invitation payload with optional separate content keys. Applications
/// attach their own metadata as `Extensions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePayload {
    pub channel_key: String,
    pub content_key: Option<String>,
    pub bootstrap: Vec<Peer>,
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
            return Err(invalid_input("empty or oversized channel keys"));
        }
        if self.bootstrap.len() > MAX_BOOTSTRAP_PEERS
            || self
                .bootstrap
                .iter()
                .any(|peer| peer_address(peer).is_none())
        {
            return Err(invalid_input("invalid bootstrap peers"));
        }
        validate_communities(&self.communities)
    }

    pub fn content_key(&self) -> &str {
        self.content_key.as_deref().unwrap_or(&self.channel_key)
    }

    /// Encode a validated payload with no application extensions.
    pub fn encode(&self, prefix: &str) -> std::io::Result<String> {
        self.encode_with(prefix, &Extensions::new())
    }

    /// Encode a validated payload and application extensions. Peer node ids and
    /// addresses are written in canonical form, so they decode as lowercase hex
    /// and `SocketAddr` display strings. IPv6 flow and scope ids are not carried.
    pub fn encode_with(&self, prefix: &str, extensions: &Extensions) -> std::io::Result<String> {
        self.validate()?;
        if extensions
            .keys()
            .any(|tag| !(APP_TAG_MIN..=APP_TAG_MAX).contains(tag))
        {
            return Err(invalid_input("extension tag outside the application range"));
        }
        let bytes = self.encode_bytes(extensions);
        if bytes.len() > MAX_INVITE_BYTES {
            return Err(invalid_input("invite too large"));
        }
        Ok(format!("{prefix}{}", to_base64url(&bytes)))
    }

    pub fn decode(prefix: &str, text: &str) -> Option<Self> {
        Self::decode_with(prefix, text).map(|(payload, _)| payload)
    }

    /// Decode a payload and its application extensions. Whitespace around the
    /// text is ignored. Callers validate their own extension values.
    pub fn decode_with(prefix: &str, text: &str) -> Option<(Self, Extensions)> {
        let body = text.trim().strip_prefix(prefix)?;
        if body.len() > MAX_INVITE_TEXT {
            return None;
        }
        decode_bytes(&from_base64url(body)?)
    }

    /// Serialize without validation, so tests can forge inputs the encoder refuses.
    fn encode_bytes(&self, extensions: &Extensions) -> Vec<u8> {
        let mut out = vec![FORMAT_VERSION];
        push_key(
            &mut out,
            TAG_CHANNEL_PACKED,
            TAG_CHANNEL_RAW,
            &self.channel_key,
        );
        if let Some(content) = &self.content_key {
            push_key(&mut out, TAG_CONTENT_PACKED, TAG_CONTENT_RAW, content);
        }
        for peer in &self.bootstrap {
            let mut value = Vec::new();
            push_peer(&mut value, peer);
            push_record(&mut out, TAG_BOOTSTRAP, &value);
        }
        for group in &self.communities {
            let mut value = vec![group.language.len() as u8];
            value.extend_from_slice(group.language.as_bytes());
            for peer in &group.peers {
                push_peer(&mut value, peer);
            }
            push_record(&mut out, TAG_COMMUNITY, &value);
        }
        for (tag, value) in extensions {
            push_record(&mut out, *tag, value);
        }
        let checksum = checksum(&out);
        out.extend_from_slice(&checksum);
        out
    }
}

fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut input = Vec::with_capacity(CHECKSUM_DOMAIN.len() + body.len());
    input.extend_from_slice(CHECKSUM_DOMAIN);
    input.extend_from_slice(body);
    let hash = crypto::hash(&input);
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Keys are strings whose exact bytes are the key material. Only canonical
/// lowercase 64-character hex packs into 32 bytes; anything else is carried
/// verbatim so it decodes to the identical string.
fn packed_key(key: &str) -> Option<[u8; 32]> {
    let canonical = key.len() == 64 && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    canonical.then(|| hash_from_hex(key)).flatten()
}

fn push_key(out: &mut Vec<u8>, packed_tag: u8, raw_tag: u8, key: &str) {
    match packed_key(key) {
        Some(bytes) => push_record(out, packed_tag, &bytes),
        None => push_record(out, raw_tag, key.as_bytes()),
    }
}

fn push_record(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    let mut len = value.len();
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out.extend_from_slice(value);
}

/// Callers validate first; an invalid peer here is a bug in this module.
fn push_peer(out: &mut Vec<u8>, peer: &Peer) {
    let (node, addr) = peer_address(peer).expect("peer validated before encoding");
    out.extend_from_slice(&node);
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(FAMILY_V4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(FAMILY_V6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if input.len() < len {
        return None;
    }
    let (head, rest) = input.split_at(len);
    *input = rest;
    Some(head)
}

/// Minimal LEB128 bounded by the invitation size, so each length has one encoding.
fn read_len(input: &mut &[u8]) -> Option<usize> {
    let mut len = 0usize;
    for shift in [0, 7] {
        let byte = *take(input, 1)?.first()?;
        len |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if shift > 0 && byte == 0 {
                return None;
            }
            return (len <= MAX_INVITE_BYTES).then_some(len);
        }
    }
    None
}

fn read_peer(input: &mut &[u8]) -> Option<Peer> {
    let node = take(input, 32)?;
    let ip = match *take(input, 1)?.first()? {
        FAMILY_V4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(take(input, 4)?).ok()?)),
        FAMILY_V6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(take(input, 16)?).ok()?)),
        _ => return None,
    };
    let port = u16::from_be_bytes(take(input, 2)?.try_into().ok()?);
    Some(Peer {
        node_id: to_hex(node),
        addr: SocketAddr::new(ip, port).to_string(),
    })
}

fn read_key(value: &[u8], packed: bool) -> Option<String> {
    if packed {
        return (value.len() == 32).then(|| to_hex(value));
    }
    let key = std::str::from_utf8(value).ok()?;
    // A packable key has exactly one encoding: the packed one.
    packed_key(key).is_none().then(|| key.to_owned())
}

fn decode_bytes(bytes: &[u8]) -> Option<(InvitePayload, Extensions)> {
    if bytes.len() > MAX_INVITE_BYTES || bytes.len() < 1 + CHECKSUM_LEN {
        return None;
    }
    let (body, sum) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
    if checksum(body) != sum || body[0] != FORMAT_VERSION {
        return None;
    }
    let mut input = &body[1..];
    let mut channel_key = None;
    let mut content_key = None;
    let mut bootstrap = Vec::new();
    let mut communities = Vec::new();
    let mut extensions = Extensions::new();
    let mut last_tag = 0;
    while !input.is_empty() {
        let tag = *take(&mut input, 1)?.first()?;
        let len = read_len(&mut input)?;
        let value = take(&mut input, len)?;
        let repeats = matches!(tag, TAG_BOOTSTRAP | TAG_COMMUNITY);
        if tag < last_tag || (tag == last_tag && !repeats) {
            return None;
        }
        last_tag = tag;
        match tag {
            TAG_CHANNEL_PACKED | TAG_CHANNEL_RAW if channel_key.is_none() => {
                channel_key = Some(read_key(value, tag == TAG_CHANNEL_PACKED)?);
            }
            TAG_CONTENT_PACKED | TAG_CONTENT_RAW if content_key.is_none() => {
                content_key = Some(read_key(value, tag == TAG_CONTENT_PACKED)?);
            }
            TAG_BOOTSTRAP => {
                let mut value = value;
                bootstrap.push(read_peer(&mut value)?);
                if !value.is_empty() {
                    return None;
                }
            }
            TAG_COMMUNITY => {
                let mut value = value;
                let len = usize::from(*take(&mut value, 1)?.first()?);
                let language = std::str::from_utf8(take(&mut value, len)?).ok()?.to_owned();
                let mut peers = Vec::new();
                while !value.is_empty() {
                    peers.push(read_peer(&mut value)?);
                }
                communities.push(CommunityPeers { language, peers });
            }
            APP_TAG_MIN..=APP_TAG_MAX => {
                extensions.insert(tag, value.to_vec());
            }
            _ => return None,
        }
    }
    let payload = InvitePayload {
        channel_key: channel_key?,
        content_key,
        bootstrap,
        communities,
    };
    payload.validate().ok()?;
    Some((payload, extensions))
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

    fn seal(body: &[u8]) -> String {
        let mut bytes = body.to_vec();
        bytes.extend_from_slice(&checksum(body));
        format!("app://{}", to_base64url(&bytes))
    }

    fn minimal(channel_key: &str) -> InvitePayload {
        InvitePayload {
            channel_key: channel_key.into(),
            content_key: None,
            bootstrap: vec![],
            communities: vec![],
        }
    }

    #[test]
    fn extensions_round_trip_and_stay_in_the_application_range() {
        let payload = minimal("chan");
        let extensions = Extensions::from([
            (APP_TAG_MIN, b"cd".repeat(16)),
            (APP_TAG_MAX, "The Warren".as_bytes().to_vec()),
            (0x50, vec![]),
        ]);
        let encoded = payload.encode_with("app://", &extensions).unwrap();
        let (decoded, back) = InvitePayload::decode_with("app://", &encoded).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(back, extensions);
        // Callers that ignore extensions still get the shared payload.
        assert_eq!(InvitePayload::decode("app://", &encoded).unwrap(), payload);
        for tag in [
            0x00,
            TAG_CHANNEL_RAW,
            APP_TAG_MIN - 1,
            APP_TAG_MAX + 1,
            0xff,
        ] {
            let err = payload
                .encode_with("app://", &Extensions::from([(tag, vec![1])]))
                .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "tag {tag:#x}");
        }
    }

    #[test]
    fn size_bound_applies_to_encode_and_decode() {
        let payload = minimal("chan");
        let with = |len: usize| Extensions::from([(APP_TAG_MIN, vec![b'x'; len])]);
        let fill = 200 + MAX_INVITE_BYTES - payload.encode_bytes(&with(200)).len();
        assert_eq!(payload.encode_bytes(&with(fill)).len(), MAX_INVITE_BYTES);
        let encoded = payload.encode_with("app://", &with(fill)).unwrap();
        assert_eq!(encoded.len() - "app://".len(), MAX_INVITE_TEXT);
        assert!(InvitePayload::decode_with("app://", &encoded).is_some());
        let err = payload.encode_with("app://", &with(fill + 1)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let forged = format!(
            "app://{}",
            to_base64url(&payload.encode_bytes(&with(fill + 1)))
        );
        assert!(InvitePayload::decode("app://", &forged).is_none());
        let oversized = format!("app://{}", "A".repeat(MAX_INVITE_TEXT + 1));
        assert!(InvitePayload::decode("app://", &oversized).is_none());
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
        let untrusted = format!(
            "app://{}",
            to_base64url(&payload.encode_bytes(&Extensions::new()))
        );
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
    fn hex_keys_pack_and_every_other_key_round_trips_verbatim() {
        let hex = "ab".repeat(32);
        let packed = minimal(&hex).encode_bytes(&Extensions::new());
        let raw = minimal(&"ab".repeat(31)).encode_bytes(&Extensions::new());
        assert_eq!(packed.len(), 1 + 2 + 32 + CHECKSUM_LEN);
        assert_eq!(raw.len(), 1 + 2 + 62 + CHECKSUM_LEN);
        let keys = [
            hex.clone(),
            hex.to_uppercase(),
            format!("{}A", &hex[..63]),
            format!("{hex}0"),
            "ab".repeat(31),
            "chan".into(),
            "känäl 🔑".into(),
        ];
        for channel_key in &keys {
            for content_key in [
                None,
                Some(String::new()),
                Some(hex.clone()),
                Some("c".into()),
            ] {
                let payload = InvitePayload {
                    content_key,
                    ..minimal(channel_key)
                };
                let decoded =
                    InvitePayload::decode("app://", &payload.encode("app://").unwrap()).unwrap();
                assert_eq!(decoded, payload, "{channel_key:?}");
            }
        }
    }

    #[test]
    fn peers_decode_in_canonical_form() {
        let payload = InvitePayload {
            bootstrap: vec![
                Peer {
                    node_id: "AB".repeat(32),
                    addr: "45.55.156.58:41800".into(),
                },
                Peer {
                    node_id: "cd".repeat(32),
                    addr: "[2001:0db8:0000::1]:9000".into(),
                },
            ],
            ..minimal("chan")
        };
        let decoded = InvitePayload::decode("app://", &payload.encode("app://").unwrap()).unwrap();
        assert_eq!(decoded.bootstrap[0].node_id, "ab".repeat(32));
        assert_eq!(decoded.bootstrap[0].addr, "45.55.156.58:41800");
        assert_eq!(decoded.bootstrap[1].addr, "[2001:db8::1]:9000");
        for addr in [
            "0.0.0.0:1",
            "127.0.0.1:0",
            "224.0.0.1:1",
            "host.example:1",
            "bad",
        ] {
            let mut bad = payload.clone();
            bad.bootstrap[0].addr = addr.into();
            assert!(bad.encode("app://").is_err(), "{addr}");
        }
        let mut bad = payload.clone();
        bad.bootstrap = vec![payload.bootstrap[0].clone(); MAX_BOOTSTRAP_PEERS + 1];
        assert!(bad.encode("app://").is_err());
    }

    /// Pins the wire bytes so a format change is a deliberate, visible edit.
    #[test]
    fn wire_format_is_pinned() {
        let payload = InvitePayload {
            channel_key: "01".repeat(32),
            content_key: Some("content".into()),
            bootstrap: vec![Peer {
                node_id: "ab".repeat(32),
                addr: "45.55.156.58:41800".into(),
            }],
            communities: vec![
                CommunityPeers {
                    language: "fa".into(),
                    peers: vec![Peer {
                        node_id: "cd".repeat(32),
                        addr: "[2001:db8::1]:9000".into(),
                    }],
                },
                CommunityPeers {
                    language: "en".into(),
                    peers: vec![],
                },
            ],
        };
        let extensions = Extensions::from([(APP_TAG_MIN, b"hi".to_vec())]);
        let encoded = payload.encode_with("app://", &extensions).unwrap();
        assert_eq!(
            encoded,
            "app://AQEgAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEEB2NvbnRlbnQFJ6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urBC03nDqjSAY2AmZhzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0GIAENuAAAAAAAAAAAAAAAASMoBgMCZW5AAmhpsMrHxQ"
        );
        assert_eq!(
            InvitePayload::decode_with("app://", &encoded),
            Some((payload, extensions))
        );
    }

    #[test]
    fn corruption_and_truncation_are_rejected() {
        let payload = InvitePayload {
            content_key: Some("cd".repeat(32)),
            bootstrap: vec![Peer {
                node_id: "ab".repeat(32),
                addr: "45.55.156.58:41800".into(),
            }],
            ..minimal(&"01".repeat(32))
        };
        let bytes = payload.encode_bytes(&Extensions::from([(APP_TAG_MIN, b"n".to_vec())]));
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut flipped = bytes.clone();
                flipped[i] ^= 1 << bit;
                assert!(decode_bytes(&flipped).is_none(), "byte {i} bit {bit}");
            }
        }
        for len in 0..bytes.len() {
            assert!(decode_bytes(&bytes[..len]).is_none(), "truncated to {len}");
        }
        assert!(decode_bytes(&bytes).is_some());
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        let hex = [0x11; 32];
        let record = |tag: u8, value: &[u8]| {
            let mut out = Vec::new();
            push_record(&mut out, tag, value);
            out
        };
        let body = |records: &[Vec<u8>]| {
            let mut out = vec![FORMAT_VERSION];
            records.iter().for_each(|r| out.extend_from_slice(r));
            out
        };
        let channel = record(TAG_CHANNEL_PACKED, &hex);
        assert!(
            InvitePayload::decode("app://", &seal(&body(std::slice::from_ref(&channel)))).is_some()
        );
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("no channel", body(&[])),
            ("unknown version", {
                let mut b = body(std::slice::from_ref(&channel));
                b[0] = 2;
                b
            }),
            (
                "repeated channel",
                body(&[channel.clone(), channel.clone()]),
            ),
            (
                "packed and raw channel",
                body(&[channel.clone(), record(TAG_CHANNEL_RAW, b"chan")]),
            ),
            (
                "out of order",
                body(&[record(TAG_CONTENT_RAW, b"c"), channel.clone()]),
            ),
            (
                "packable raw key",
                body(&[record(TAG_CHANNEL_RAW, "11".repeat(32).as_bytes())]),
            ),
            (
                "short packed key",
                body(&[record(TAG_CHANNEL_PACKED, &hex[..31])]),
            ),
            ("empty raw channel", body(&[record(TAG_CHANNEL_RAW, b"")])),
            (
                "invalid utf-8 key",
                body(&[record(TAG_CHANNEL_RAW, &[0xff])]),
            ),
            (
                "unassigned core tag",
                body(&[channel.clone(), record(0x07, b"")]),
            ),
            (
                "reserved high tag",
                body(&[channel.clone(), record(0x80, b"")]),
            ),
            (
                "repeated extension",
                body(&[
                    channel.clone(),
                    record(APP_TAG_MIN, b""),
                    record(APP_TAG_MIN, b""),
                ]),
            ),
            ("non-minimal length", {
                let mut b = body(&[]);
                b.extend_from_slice(&[TAG_CHANNEL_RAW, 0x84, 0x00]);
                b.extend_from_slice(b"chan");
                b
            }),
            ("length past end", {
                let mut b = body(&[]);
                b.extend_from_slice(&[TAG_CHANNEL_RAW, 0x10, b'c']);
                b
            }),
            ("unknown address family", {
                let mut peer = vec![0xab; 32];
                peer.extend_from_slice(&[5, 1, 2, 3, 4, 0, 80]);
                body(&[channel.clone(), record(TAG_BOOTSTRAP, &peer)])
            }),
            ("trailing peer bytes", {
                let mut peer = vec![0xab; 32];
                peer.extend_from_slice(&[FAMILY_V4, 1, 2, 3, 4, 0, 80, 0]);
                body(&[channel.clone(), record(TAG_BOOTSTRAP, &peer)])
            }),
        ];
        for (label, body) in cases {
            assert!(
                InvitePayload::decode("app://", &seal(&body)).is_none(),
                "{label}"
            );
        }
        let valid = seal(&body(&[channel]));
        for text in [
            format!("{valid}="),
            format!("{valid}A"),
            valid.replace('A', "+"),
        ] {
            assert!(InvitePayload::decode("app://", &text).is_none(), "{text}");
        }
    }

    #[test]
    fn base64url_is_strict_and_round_trips() {
        for len in 0..40usize {
            let bytes = (0..len).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>();
            let text = to_base64url(&bytes);
            assert_eq!(text.len(), (len * 4).div_ceil(3));
            assert_eq!(from_base64url(&text).unwrap(), bytes);
        }
        assert_eq!(to_base64url(&[0xfb, 0xff]), "-_8");
        for bad in ["A", "AB=", "AB+C", "AB/C", "AF", "AAB"] {
            assert!(from_base64url(bad).is_none(), "{bad}");
        }
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_keys_round_trip_exactly(
            channel in "\\PC{1,80}|[0-9a-fA-F]{60,68}",
            content in proptest::option::of("\\PC{0,80}|[0-9a-f]{64}"),
        ) {
            let payload = InvitePayload { content_key: content, ..minimal(&channel) };
            if payload.validate().is_ok() {
                let decoded = InvitePayload::decode("app://", &payload.encode("app://").unwrap());
                proptest::prop_assert_eq!(decoded, Some(payload));
            }
        }

        #[test]
        fn decoding_arbitrary_input_never_panics(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..512),
            text in "[A-Za-z0-9_=+/-]{0,700}",
        ) {
            let _ = decode_bytes(&bytes);
            let _ = InvitePayload::decode_with("app://", &format!("app://{text}"));
            let mut sealed = bytes.clone();
            sealed.extend_from_slice(&checksum(&bytes));
            let _ = decode_bytes(&sealed);
        }
    }
}
