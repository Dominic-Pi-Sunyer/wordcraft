//! `ssync://` capability tickets.
//!
//! A ticket is `ssync://` + URL-safe unpadded base64 of the bincode-encoded
//! ticket. It bundles everything a peer needs: how to dial the host, which
//! document to fetch (and verify), the gossip topic, and the cryptographic
//! capabilities (read key, write verifying key, optionally the write signing key).
//!
//! The Edit URI embeds the write signing key; the View-Only URI does not.
//! Both embed the read key, so treat any ticket like a password.

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const SCHEME: &str = "ssync://";
/// Bumped to 2 with the sequence-numbered frame format: tickets from 1 never mix with it.
const VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharePermission {
    ReadWrite,
    ReadOnly,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionTicket {
    /// Host's `EndpointId`, relay URL and direct addresses.
    pub host_addr: EndpointAddr,
    /// BLAKE3 hash of the base document; joiners verify the download against it.
    pub doc_hash: [u8; 32],
    /// Random gossip channel id.
    pub gossip_topic_id: [u8; 32],
    /// ChaCha20-Poly1305 key for all gossip payloads.
    pub read_key: [u8; 32],
    /// Ed25519 public key every peer uses to authorize incoming writes.
    pub write_verifying_key: [u8; 32],
    /// Ed25519 secret key; `Some` only in Edit tickets.
    pub write_signing_key: Option<[u8; 32]>,
    /// Name of the base document (informational).
    pub filename: String,
}

#[derive(Serialize, Deserialize)]
struct WireTicket {
    version: u8,
    host_addr: EndpointAddr,
    doc_hash: [u8; 32],
    gossip_topic_id: [u8; 32],
    read_key: [u8; 32],
    write_verifying_key: [u8; 32],
    write_signing_key: Option<[u8; 32]>,
    filename: String,
}

impl SessionTicket {
    /// Fresh ephemeral topic, read key and write keypair for a new session.
    pub fn generate(host_addr: EndpointAddr, doc_hash: [u8; 32], filename: &str) -> Self {
        let signing = SigningKey::from_bytes(&crate::crypto::random_key());
        Self {
            host_addr,
            doc_hash,
            gossip_topic_id: crate::crypto::random_key(),
            read_key: crate::crypto::random_key(),
            write_verifying_key: signing.verifying_key().to_bytes(),
            write_signing_key: Some(signing.to_bytes()),
            filename: filename.to_string(),
        }
    }

    pub fn permission(&self) -> SharePermission {
        if self.write_signing_key.is_some() {
            SharePermission::ReadWrite
        } else {
            SharePermission::ReadOnly
        }
    }

    /// "Anyone with this link can edit."
    pub fn to_edit_uri(&self) -> String {
        self.encode()
    }

    /// "Anyone with this link can view." Strips the write signing key.
    pub fn to_view_only_uri(&self) -> String {
        let mut t = self.clone();
        t.write_signing_key = None;
        t.encode()
    }

    fn encode(&self) -> String {
        let wire = WireTicket {
            version: VERSION,
            host_addr: self.host_addr.clone(),
            doc_hash: self.doc_hash,
            gossip_topic_id: self.gossip_topic_id,
            read_key: self.read_key,
            write_verifying_key: self.write_verifying_key,
            write_signing_key: self.write_signing_key,
            filename: self.filename.clone(),
        };
        let bytes = bincode::serialize(&wire).expect("ticket serialization is infallible");
        format!("{SCHEME}{}", BASE64URL_NOPAD.encode(&bytes))
    }

    pub fn from_uri(uri: &str) -> Result<Self> {
        let body = uri
            .trim()
            .strip_prefix(SCHEME)
            .ok_or_else(|| anyhow!("ticket must start with `{SCHEME}`"))?;
        let bytes = BASE64URL_NOPAD
            .decode(body.as_bytes())
            .map_err(|e| anyhow!("ticket is not valid base64url: {e}"))?;
        let w: WireTicket = bincode::deserialize(&bytes).context("malformed ticket")?;
        if w.version != VERSION {
            bail!("unsupported ticket version {}", w.version);
        }
        VerifyingKey::from_bytes(&w.write_verifying_key)
            .map_err(|_| anyhow!("ticket has an invalid write verifying key"))?;
        if let Some(sk) = &w.write_signing_key {
            if SigningKey::from_bytes(sk).verifying_key().to_bytes() != w.write_verifying_key {
                bail!("ticket signing key does not match its verifying key");
            }
        }
        Ok(Self {
            host_addr: w.host_addr,
            doc_hash: w.doc_hash,
            gossip_topic_id: w.gossip_topic_id,
            read_key: w.read_key,
            write_verifying_key: w.write_verifying_key,
            write_signing_key: w.write_signing_key,
            filename: w.filename,
        })
    }
}

impl Drop for SessionTicket {
    fn drop(&mut self) {
        self.read_key.zeroize();
        if let Some(k) = self.write_signing_key.as_mut() {
            k.zeroize();
        }
    }
}

// Never print key material in logs.
impl std::fmt::Debug for SessionTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTicket")
            .field("host", &self.host_addr.id)
            .field("filename", &self.filename)
            .field("permission", &self.permission())
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl std::str::FromStr for SessionTicket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_uri(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn sample() -> SessionTicket {
        let id = SecretKey::generate().public();
        let addr = EndpointAddr::new(id).with_ip_addr("127.0.0.1:4000".parse().unwrap());
        SessionTicket::generate(addr, [5; 32], "my doc.pdf")
    }

    #[test]
    fn edit_and_view_roundtrip() {
        let t = sample();
        let edit = SessionTicket::from_uri(&t.to_edit_uri()).unwrap();
        assert_eq!(edit, t);
        assert_eq!(edit.permission(), SharePermission::ReadWrite);

        let view = SessionTicket::from_uri(&t.to_view_only_uri()).unwrap();
        assert_eq!(view.permission(), SharePermission::ReadOnly);
        assert_eq!(view.write_signing_key, None);
        assert_eq!(view.read_key, t.read_key);
        assert_eq!(view.write_verifying_key, t.write_verifying_key);
        assert_eq!(view.host_addr, t.host_addr);
        assert_eq!(view.doc_hash, t.doc_hash);
        assert_eq!(view.gossip_topic_id, t.gossip_topic_id);
    }

    #[test]
    fn view_uri_does_not_leak_signing_key() {
        let t = sample();
        let sk = t.write_signing_key.unwrap();
        let view = t.to_view_only_uri();
        let raw = BASE64URL_NOPAD
            .decode(view.trim_start_matches(SCHEME).as_bytes())
            .unwrap();
        assert!(!raw.windows(32).any(|w| w == sk));
        assert!(view.len() < t.to_edit_uri().len());
    }

    #[test]
    fn uris_are_url_safe() {
        let u = sample().to_edit_uri();
        assert!(u[SCHEME.len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn rejects_garbage_and_inconsistent_tickets() {
        assert!(SessionTicket::from_uri("http://x").is_err());
        assert!(SessionTicket::from_uri("ssync://!!!").is_err());
        assert!(SessionTicket::from_uri("ssync://AAAA").is_err());

        // Edit ticket whose signing key does not belong to its verifying key.
        let mut t = sample();
        t.write_signing_key = Some([9; 32]);
        assert!(SessionTicket::from_uri(&t.to_edit_uri()).is_err());
    }

    #[test]
    fn debug_hides_keys() {
        let t = sample();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("redacted") && !dbg.contains(&format!("{:?}", t.read_key)));
    }
}
