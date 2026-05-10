use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};

const IDENTITY_FILE: &str = "identity.json";
const IDENTITY_VERSION: u8 = 1;

/// Per-device identity: an Ed25519 signing keypair plus an X25519 key-exchange
/// keypair.
///
/// The Ed25519 key is the durable handle for a Crow node — it's what mDNS
/// advertises (truncated, in the instance name; in full, in the TXT records),
/// what `crow peers` displays, and what new file/directory manifests are
/// signed with. The X25519 key is held in reserve for future peer-to-peer
/// authentication.
pub struct Identity {
    pub signing: SigningKey,
    pub kx: StaticSecret,
}

#[derive(Serialize, Deserialize)]
struct IdentityJson {
    version: u8,
    signing_secret: String,
    kx_secret: String,
}

impl Identity {
    pub fn random() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
            kx: StaticSecret::random_from_rng(OsRng),
        }
    }

    pub fn signing_pubkey(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn kx_pubkey(&self) -> [u8; 32] {
        PublicKey::from(&self.kx).to_bytes()
    }

    /// The stable per-node identifier — the Ed25519 verifying-key bytes,
    /// wrapped in a typed [`NodeId`] for use by discovery, peer lists, and
    /// (eventually) signed manifests.
    pub fn node_id(&self) -> NodeId {
        NodeId(self.signing_pubkey())
    }

    /// Load the identity from `<home>/identity.json`, generating and persisting
    /// a fresh one if the file does not exist. Idempotent: a second call at
    /// the same `home` returns the same identity bytes.
    pub fn load_or_create(home: impl AsRef<Path>) -> Result<Self> {
        let home = home.as_ref();
        let path = home.join(IDENTITY_FILE);
        if path.exists() {
            Self::load(&path)
        } else {
            let identity = Self::random();
            identity.save(home)?;
            Ok(identity)
        }
    }

    fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let json: IdentityJson = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Identity(format!("deserialize {}: {e}", path.display())))?;
        if json.version != IDENTITY_VERSION {
            return Err(Error::Identity(format!(
                "unsupported identity version {}; this build supports {}",
                json.version, IDENTITY_VERSION
            )));
        }
        let signing_bytes = decode_hex32(&json.signing_secret)
            .ok_or_else(|| Error::Identity("signing_secret must be 64 hex chars".into()))?;
        let kx_bytes = decode_hex32(&json.kx_secret)
            .ok_or_else(|| Error::Identity("kx_secret must be 64 hex chars".into()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&signing_bytes),
            kx: StaticSecret::from(kx_bytes),
        })
    }

    fn save(&self, home: &Path) -> Result<()> {
        fs::create_dir_all(home)?;
        let target = home.join(IDENTITY_FILE);
        let tmp = home.join(format!("{IDENTITY_FILE}.{}.tmp", std::process::id()));
        let json = IdentityJson {
            version: IDENTITY_VERSION,
            signing_secret: hex(&self.signing.to_bytes()),
            kx_secret: hex(&self.kx.to_bytes()),
        };
        let bytes = serde_json::to_vec_pretty(&json)
            .map_err(|e| Error::Identity(format!("serialize: {e}")))?;
        write_private(&tmp, &bytes)?;
        fs::rename(&tmp, &target)?;
        Ok(())
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show only the public halves; never the secrets.
        f.debug_struct("Identity")
            .field("signing_pubkey", &hex(&self.signing_pubkey()))
            .field("kx_pubkey", &hex(&self.kx_pubkey()))
            .finish()
    }
}

/// Stable per-node identifier — the Ed25519 verifying-key bytes.
///
/// Used by mDNS discovery (the first 16 hex chars become the service instance
/// name; the full 64-char hex sits in the TXT record), by `crow peers` for
/// display, and by `crow fetch <prefix>` for friendly addressing of known
/// peers. Equality and ordering are byte-wise on the inner key.
///
/// Serialisation is format-aware: a human-readable format (JSON, YAML) emits
/// the 64-char hex string; a binary format (postcard, bincode) emits the raw
/// 32 bytes. This keeps `peers.json` greppable while staying compact on the
/// wire.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    pub const SIZE: usize = 32;

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 16-hex-character prefix — short enough for `crow peers` columns and
    /// mDNS instance names, long enough that LAN-scale collisions are very
    /// unlikely.
    pub fn short(&self) -> String {
        hex(&self.0[..8])
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

impl std::str::FromStr for NodeId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        decode_hex32(s).map(Self).ok_or_else(|| {
            Error::Identity(format!(
                "NodeId expects 64 hex characters, got {} ({:?})",
                s.len(),
                s
            ))
        })
    }
}

impl Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex(&self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = NodeId;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("64-character hex string or 32-byte array")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<NodeId, E> {
                decode_hex32(v.trim())
                    .map(NodeId)
                    .ok_or_else(|| E::custom(format!("invalid hex node id: {v:?}")))
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> std::result::Result<NodeId, E> {
                if v.len() != 32 {
                    return Err(E::invalid_length(v.len(), &"32 bytes"));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(v);
                Ok(NodeId(out))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<NodeId, A::Error> {
                let mut out = [0u8; 32];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"32 bytes"))?;
                }
                Ok(NodeId(out))
            }
        }

        if d.is_human_readable() {
            d.deserialize_str(V)
        } else {
            d.deserialize_bytes(V)
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true).mode(0o600);
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn random_produces_distinct_identities() {
        let a = Identity::random();
        let b = Identity::random();
        assert_ne!(a.signing_pubkey(), b.signing_pubkey());
        assert_ne!(a.kx_pubkey(), b.kx_pubkey());
    }

    #[test]
    fn pubkey_sizes_match_curve_definitions() {
        let id = Identity::random();
        assert_eq!(id.signing_pubkey().len(), 32); // Ed25519
        assert_eq!(id.kx_pubkey().len(), 32); // X25519
    }

    #[test]
    fn debug_shows_only_pubkeys() {
        let id = Identity::random();
        let dbg = format!("{id:?}");
        assert!(dbg.contains("signing_pubkey"));
        assert!(dbg.contains("kx_pubkey"));
        assert!(!dbg.to_lowercase().contains("secret"));
        assert!(!dbg.to_lowercase().contains("private"));
    }

    #[test]
    fn load_or_create_persists_across_calls() {
        let tmp = TempDir::new().unwrap();
        let first = Identity::load_or_create(tmp.path()).unwrap();
        let second = Identity::load_or_create(tmp.path()).unwrap();
        assert_eq!(first.signing_pubkey(), second.signing_pubkey());
        assert_eq!(first.kx_pubkey(), second.kx_pubkey());
    }

    #[test]
    fn load_or_create_persists_secret_bytes() {
        let tmp = TempDir::new().unwrap();
        let first = Identity::load_or_create(tmp.path()).unwrap();
        let second = Identity::load_or_create(tmp.path()).unwrap();
        // The actual secrets roundtrip, not just the public half.
        assert_eq!(first.signing.to_bytes(), second.signing.to_bytes());
        assert_eq!(first.kx.to_bytes(), second.kx.to_bytes());
    }

    #[test]
    fn load_or_create_creates_identity_file() {
        let tmp = TempDir::new().unwrap();
        let _ = Identity::load_or_create(tmp.path()).unwrap();
        assert!(tmp.path().join("identity.json").exists());
    }

    #[test]
    fn load_rejects_unknown_version() {
        let tmp = TempDir::new().unwrap();
        let bogus = serde_json::json!({
            "version": 99,
            "signing_secret": "00".repeat(32),
            "kx_secret":      "00".repeat(32),
        });
        fs::write(
            tmp.path().join("identity.json"),
            serde_json::to_vec(&bogus).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            Identity::load_or_create(tmp.path()),
            Err(Error::Identity(_))
        ));
    }

    #[test]
    fn node_id_matches_signing_pubkey() {
        let id = Identity::random();
        assert_eq!(id.node_id().as_bytes(), &id.signing_pubkey());
    }

    #[test]
    fn node_id_hex_roundtrip() {
        use std::str::FromStr;
        let id = Identity::random();
        let n = id.node_id();
        let s = n.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(NodeId::from_str(&s).unwrap(), n);
    }

    #[test]
    fn node_id_short_is_16_chars() {
        let n = Identity::random().node_id();
        assert_eq!(n.short().len(), 16);
        assert!(n.short().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn node_id_rejects_bad_input() {
        use std::str::FromStr;
        assert!(NodeId::from_str("abc").is_err());
        assert!(NodeId::from_str(&"z".repeat(64)).is_err());
        assert!(NodeId::from_str("").is_err());
    }

    #[test]
    fn node_id_serializes_as_hex_in_json() {
        let n = NodeId::from_bytes([0xABu8; 32]);
        let s = serde_json::to_string(&n).unwrap();
        // Quoted hex string of length 64 + 2 quotes.
        assert_eq!(s.len(), 66);
        assert_eq!(s, format!("\"{}\"", "ab".repeat(32)));
        let back: NodeId = serde_json::from_str(&s).unwrap();
        assert_eq!(back, n);
    }

    #[test]
    fn node_id_serializes_as_bytes_in_postcard() {
        let n = NodeId::from_bytes([0xCDu8; 32]);
        let bytes = postcard::to_allocvec(&n).unwrap();
        // postcard encodes a byte sequence as length-prefixed-varint + 32 bytes;
        // length 32 fits in a single varint byte (0x20).
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[0], 32);
        assert_eq!(&bytes[1..], &[0xCDu8; 32]);
        let back: NodeId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, n);
    }

    #[test]
    fn node_id_debug_uses_short_form() {
        let n = Identity::random().node_id();
        let dbg = format!("{n:?}");
        assert!(dbg.starts_with("NodeId("));
        assert!(dbg.contains(&n.short()));
    }

    #[test]
    fn load_rejects_bad_hex() {
        let tmp = TempDir::new().unwrap();
        let bogus = serde_json::json!({
            "version": 1,
            "signing_secret": "z".repeat(64),
            "kx_secret":      "00".repeat(32),
        });
        fs::write(
            tmp.path().join("identity.json"),
            serde_json::to_vec(&bogus).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            Identity::load_or_create(tmp.path()),
            Err(Error::Identity(_))
        ));
    }
}
