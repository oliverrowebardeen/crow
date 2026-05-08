use std::fmt;
use std::str::FromStr;

use bech32::{Bech32m, Hrp};

use crate::crypto::ManifestKey;
use crate::error::{Error, Result};
use crate::hash::ManifestHash;

pub const CAP_VERSION: u8 = 1;
pub const CAP_HRP: &str = "crow";
const PAYLOAD_LEN: usize = 1 + 1 + 32 + 32; // version | permission | manifest_hash | manifest_key

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Permission {
    Read = 0,
}

impl Permission {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Permission::Read),
            other => Err(Error::Cap(format!("unknown permission byte {other}"))),
        }
    }
}

/// Tahoe-LAFS-style read capability.
///
/// Bundles the manifest's content address with the key needed to decrypt it
/// and a permission tag. Holders of a valid Cap can fetch and decrypt the
/// referenced file; nothing else can.
#[derive(Clone)]
pub struct Cap {
    pub version: u8,
    pub permission: Permission,
    pub manifest_hash: ManifestHash,
    pub manifest_key: ManifestKey,
}

impl Cap {
    pub fn new_read(manifest_hash: ManifestHash, manifest_key: ManifestKey) -> Self {
        Self {
            version: CAP_VERSION,
            permission: Permission::Read,
            manifest_hash,
            manifest_key,
        }
    }

    pub fn encode(&self) -> String {
        let hrp = Hrp::parse(CAP_HRP).expect("static HRP is valid");
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = self.version;
        payload[1] = self.permission as u8;
        payload[2..34].copy_from_slice(self.manifest_hash.as_bytes());
        payload[34..66].copy_from_slice(self.manifest_key.as_bytes());
        bech32::encode::<Bech32m>(hrp, &payload)
            .expect("Bech32m encoding cannot fail with a valid HRP and ≤90-byte payload")
    }

    pub fn decode(s: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(s).map_err(|e| Error::Cap(format!("bech32: {e}")))?;
        if hrp.as_str() != CAP_HRP {
            return Err(Error::Cap(format!(
                "wrong HRP: expected {CAP_HRP}, got {}",
                hrp.as_str()
            )));
        }
        if data.len() != PAYLOAD_LEN {
            return Err(Error::Cap(format!(
                "expected {PAYLOAD_LEN} payload bytes, got {}",
                data.len()
            )));
        }
        let version = data[0];
        if version != CAP_VERSION {
            return Err(Error::Cap(format!(
                "unsupported cap version {version}; this build supports {CAP_VERSION}"
            )));
        }
        let permission = Permission::from_byte(data[1])?;
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&data[2..34]);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[34..PAYLOAD_LEN]);
        Ok(Self {
            version,
            permission,
            manifest_hash: ManifestHash::from_bytes(hash_bytes),
            manifest_key: ManifestKey::from_bytes(key_bytes),
        })
    }
}

impl fmt::Display for Cap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl fmt::Debug for Cap {
    // Never print the manifest key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cap")
            .field("version", &self.version)
            .field("permission", &self.permission)
            .field("manifest_hash", &self.manifest_hash)
            .field("manifest_key", &"<redacted>")
            .finish()
    }
}

impl FromStr for Cap {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cap() -> Cap {
        Cap::new_read(
            ManifestHash::from_bytes([0xABu8; 32]),
            ManifestKey::from_bytes([0xCDu8; 32]),
        )
    }

    #[test]
    fn encode_decode_roundtrip() {
        let cap = sample_cap();
        let encoded = cap.encode();
        let decoded = Cap::decode(&encoded).unwrap();
        assert_eq!(decoded.version, cap.version);
        assert_eq!(decoded.permission, cap.permission);
        assert_eq!(decoded.manifest_hash, cap.manifest_hash);
        assert_eq!(decoded.manifest_key.as_bytes(), cap.manifest_key.as_bytes());
    }

    #[test]
    fn encoded_string_starts_with_hrp() {
        let cap = sample_cap();
        let encoded = cap.encode();
        assert!(encoded.starts_with("crow1"));
    }

    #[test]
    fn encoded_length_in_expected_range() {
        // 66-byte payload via bech32m: HRP (4) + separator (1) + ~106 data
        // chars + 6-char checksum.
        let encoded = sample_cap().encode();
        assert!(
            encoded.len() >= 110 && encoded.len() <= 120,
            "unexpected encoded length {}: {encoded}",
            encoded.len()
        );
    }

    #[test]
    fn decode_rejects_wrong_hrp() {
        // Encode with a different HRP and try to decode as a Crow cap.
        let hrp = Hrp::parse("nope").unwrap();
        let bogus = bech32::encode::<Bech32m>(hrp, &[0u8; 66]).unwrap();
        match Cap::decode(&bogus) {
            Err(Error::Cap(msg)) => assert!(msg.contains("HRP")),
            other => panic!("expected Cap HRP error, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_corrupted_checksum() {
        let mut encoded = sample_cap().encode();
        // Flip the last character (checksum byte) — bech32m must reject.
        let last = encoded.pop().unwrap();
        let flipped = if last == 'q' { '0' } else { 'q' };
        encoded.push(flipped);
        assert!(matches!(Cap::decode(&encoded), Err(Error::Cap(_))));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        // Construct a payload with version=99 and bech32m-encode it.
        let hrp = Hrp::parse(CAP_HRP).unwrap();
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = 99;
        payload[1] = 0;
        let s = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        match Cap::decode(&s) {
            Err(Error::Cap(msg)) => assert!(msg.contains("version")),
            other => panic!("expected version error, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_unknown_permission() {
        let hrp = Hrp::parse(CAP_HRP).unwrap();
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = CAP_VERSION;
        payload[1] = 9;
        let s = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        match Cap::decode(&s) {
            Err(Error::Cap(msg)) => assert!(msg.contains("permission")),
            other => panic!("expected permission error, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_wrong_payload_length() {
        let hrp = Hrp::parse(CAP_HRP).unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[0u8; 32]).unwrap();
        match Cap::decode(&s) {
            Err(Error::Cap(msg)) => assert!(msg.contains("payload")),
            other => panic!("expected payload-length error, got {other:?}"),
        }
    }

    #[test]
    fn fromstr_works() {
        let cap = sample_cap();
        let encoded = cap.encode();
        let parsed: Cap = encoded.parse().unwrap();
        assert_eq!(parsed.manifest_hash, cap.manifest_hash);
    }

    #[test]
    fn debug_redacts_manifest_key() {
        let cap = sample_cap();
        let dbg = format!("{cap:?}");
        assert!(!dbg.contains("CDCDCD"));
        assert!(!dbg.contains("cdcdcd"));
        assert!(dbg.contains("redacted"));
    }
}
