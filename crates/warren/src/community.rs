//! Stable language-based community selection, independent of physical location.
use crate::invite::RegionalInvite;
use crate::util::{bytes_from_hex, to_hex};
use driver::next::OverlayId;
use language_tags::LanguageTag;
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Community {
    language: Option<String>,
    overlay: OverlayId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    language: Option<String>,
    overlay: String,
}

impl Community {
    /// Canonical language grouping ignores script, region and formatting extensions.
    /// Invalid, private-only and undetermined locales cannot silently select a DHT.
    pub fn from_locale(locale: &str) -> Option<Self> {
        if locale.len() > 256 {
            return None;
        }
        let normalized = locale.trim().split(['.', '@']).next()?.replace('_', "-");
        let tag = LanguageTag::parse(&normalized).ok()?;
        tag.validate().ok()?;
        let tag = tag.canonicalize().ok()?;
        if tag.as_str().starts_with("x-") {
            return None;
        }
        let language = tag.primary_language();
        if matches!(language, "und" | "mul" | "zxx" | "x") || language.len() < 2 {
            return None;
        }
        let language = language.to_ascii_lowercase();
        Some(Self {
            overlay: OverlayId::regional(&format!("warren:language:v1:{language}")),
            language: Some(language),
        })
    }
    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }
    pub fn overlay(&self) -> OverlayId {
        self.overlay
    }

    /// A local failure domain is supplied independently of language preferences.
    /// Peers agreeing on this domain maintain a full separate copy of discovery.
    pub fn local_overlay(&self, domain: &str) -> io::Result<OverlayId> {
        if domain.is_empty() || domain.len() > 128 {
            return Err(invalid("invalid local connectivity domain"));
        }
        let OverlayId::Regional(id) = self.overlay else {
            return Err(invalid("global community"));
        };
        Ok(OverlayId::regional(&format!(
            "warren:local:v1:{}:{domain}",
            to_hex(&id)
        )))
    }

    pub fn from_invite(invite: &RegionalInvite, now: u64) -> io::Result<Self> {
        if invite.expires <= now {
            return Err(invalid("expired invitation"));
        }
        if let Some(language) = &invite.community_language {
            return Self::from_locale(language)
                .ok_or_else(|| invalid("invalid invitation language"));
        }
        let bootstrap = invite
            .community_bootstrap
            .as_ref()
            .unwrap_or(&invite.bootstrap);
        if bootstrap.overlay() == OverlayId::Global {
            return Err(invalid("global invitation"));
        }
        Ok(Self {
            language: None,
            overlay: bootstrap.overlay(),
        })
    }

    /// Explicit choice > invitation > saved choice > first valid preferred locale.
    /// No preference means an explicit error, not an arbitrary English fallback.
    pub fn select(
        explicit: Option<&Self>,
        invite: Option<&RegionalInvite>,
        saved: Option<&Self>,
        locales: impl IntoIterator<Item = impl AsRef<str>>,
        now: u64,
    ) -> io::Result<Self> {
        if let Some(choice) = explicit {
            return Ok(choice.clone());
        }
        if let Some(invite) = invite {
            return Self::from_invite(invite, now);
        }
        if let Some(choice) = saved {
            return Ok(choice.clone());
        }
        locales
            .into_iter()
            .take(32)
            .find_map(|locale| Self::from_locale(locale.as_ref()))
            .ok_or_else(|| {
                invalid("no usable language preference; supply a community or invitation")
            })
    }

    /// Select from native locale when no override exists. Language overlay IDs are
    /// visible on the wire and enumerable by passive observers; applications should
    /// explain this exposure before enabling locale-derived networking.
    pub fn detect(
        explicit: Option<&Self>,
        invite: Option<&RegionalInvite>,
        saved: Option<&Self>,
    ) -> io::Result<Self> {
        if explicit.is_some() || invite.is_some() || saved.is_some() {
            return Self::select(
                explicit,
                invite,
                saved,
                std::iter::empty::<&str>(),
                crate::util::now_secs(),
            );
        }
        Self::select(
            explicit,
            invite,
            saved,
            sys_locale::get_locales(),
            crate::util::now_secs(),
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let OverlayId::Regional(id) = self.overlay else {
            unreachable!("community overlay")
        };
        serde_json::to_vec(&Stored {
            version: 1,
            language: self.language.clone(),
            overlay: to_hex(&id),
        })
        .expect("community state")
    }
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > 512 {
            return Err(invalid("oversized community state"));
        }
        let state: Stored =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid community state"))?;
        if state.version != 1 {
            return Err(invalid("unsupported community state"));
        }
        let overlay = OverlayId::Regional(
            bytes_from_hex(&state.overlay).ok_or_else(|| invalid("invalid overlay identifier"))?,
        );
        let community = Self {
            language: state.language,
            overlay,
        };
        if let Some(language) = &community.language {
            if Self::from_locale(language).as_ref() != Some(&community) {
                return Err(invalid("community language and overlay disagree"));
            }
        }
        Ok(community)
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Explicit network policy for a correlated-failure domain. The application
/// supplies reviewed ranges; locale and RTT cannot prove domestic reachability.
#[derive(Clone, Debug)]
pub struct ConnectivityDomain {
    label: String,
    ipv4: Vec<(u128, u128)>,
    ipv6: Vec<(u128, u128)>,
}
impl ConnectivityDomain {
    pub fn new(label: &str, networks: &[&str]) -> io::Result<Self> {
        if label.is_empty() || label.len() > 128 || networks.is_empty() || networks.len() > 16_384 {
            return Err(invalid(
                "local domain needs a label and bounded network ranges",
            ));
        }
        let networks = networks
            .iter()
            .map(|network| {
                network
                    .parse::<ipnet::IpNet>()
                    .map_err(|_| invalid("invalid network range"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        if networks.iter().any(|network| network.prefix_len() == 0) {
            return Err(invalid("a local domain cannot include the entire internet"));
        }
        let mut ipv4 = vec![];
        let mut ipv6 = vec![];
        for network in networks {
            match network {
                ipnet::IpNet::V4(network) => ipv4.push((
                    u32::from(network.network()) as u128,
                    u32::from(network.broadcast()) as u128,
                )),
                ipnet::IpNet::V6(network) => ipv6.push((
                    u128::from(network.network()),
                    u128::from(network.broadcast()),
                )),
            }
        }
        Ok(Self {
            label: label.to_owned(),
            ipv4: merge_ranges(ipv4),
            ipv6: merge_ranges(ipv6),
        })
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn allows(&self, address: std::net::SocketAddr) -> bool {
        let ip = match address.ip() {
            std::net::IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
            ip => ip,
        };
        let (ranges, address) = match ip {
            std::net::IpAddr::V4(ip) => (&self.ipv4, u32::from(ip) as u128),
            std::net::IpAddr::V6(ip) => (&self.ipv6, u128::from(ip)),
        };
        ranges
            .partition_point(|(start, _)| *start <= address)
            .checked_sub(1)
            .is_some_and(|index| address <= ranges[index].1)
    }
    pub fn address_filter(&self) -> driver::next::AddressFilter {
        let domain = self.clone();
        std::sync::Arc::new(move |address| domain.allows(address))
    }
}

fn merge_ranges(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u128, u128)> = vec![];
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locale_variants_share_community_but_not_connectivity_domains() {
        let fa = Community::from_locale("fa").unwrap();
        for locale in ["fa-IR", "fa-AF", "FA_Arab_IR.UTF-8", "fa-US-u-nu-latn"] {
            assert_eq!(Community::from_locale(locale), Some(fa.clone()));
        }
        assert_ne!(fa, Community::from_locale("ru-RU").unwrap());
        assert_ne!(
            fa.local_overlay("ir").unwrap(),
            fa.local_overlay("us").unwrap()
        );
        assert_ne!(fa.overlay(), fa.local_overlay("ir").unwrap());
        assert!(fa.local_overlay("").is_err());
    }
    #[test]
    fn saved_choice_survives_locale_change_and_explicit_choice_wins() {
        let fa = Community::from_locale("fa-IR").unwrap();
        let ru = Community::from_locale("ru").unwrap();
        let restored = Community::decode(&fa.encode()).unwrap();
        assert_eq!(
            Community::select(None, None, Some(&restored), ["en-US"], 1).unwrap(),
            fa
        );
        assert_eq!(
            Community::select(Some(&ru), None, Some(&fa), ["fa"], 1).unwrap(),
            ru
        );
        assert_eq!(
            Community::select(None, None, None, ["C", "invalid!", "fa-IR", "ru"], 1).unwrap(),
            fa
        );
        assert!(Community::select(None, None, None, ["C", "und", "x-private"], 1).is_err());
    }
    #[test]
    fn corrupt_persistence_cannot_reassign_a_language() {
        let fa = Community::from_locale("fa").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&fa.encode()).unwrap();
        value["language"] = "ru".into();
        assert!(Community::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(Community::decode(&vec![0; 513]).is_err());
    }
}
