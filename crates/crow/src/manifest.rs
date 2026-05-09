use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::crypto::{FileKey, ManifestKey, open_manifest, seal_manifest};
use crate::erasure::ErasureParams;
use crate::error::{Error, Result};
use crate::hash::ChunkHash;

pub const MANIFEST_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Aead {
    Aes256Gcm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kdf {
    HkdfSha256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErasureCode {
    ReedSolomon,
}

/// Algorithm declarations attached to every manifest. Present from v1 so the
/// future addition of e.g. ChaCha20-Poly1305 or fountain codes does not
/// require a manifest schema change — only new enum variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Algorithm {
    pub aead: Aead,
    pub kdf: Kdf,
    pub erasure_code: ErasureCode,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self {
            aead: Aead::Aes256Gcm,
            kdf: Kdf::HkdfSha256,
            erasure_code: ErasureCode::ReedSolomon,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stripe {
    pub data: Vec<ChunkHash>,
    pub parity: Vec<ChunkHash>,
}

/// 64-byte Ed25519 signature over the canonical-encoded manifest. Wrapping
/// the array is required because serde's built-in array support tops out at
/// 32 elements; serde-big-array provides the 64-byte derive.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "BigArray")] pub [u8; 64]);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature(<64 bytes>)")
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Signature {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub algorithm: Algorithm,
    pub file_size: u64,
    pub mime_type: String,
    pub file_key: FileKey,
    pub erasure: ErasureParams,
    pub chunk_size: u32,
    pub stripes: Vec<Stripe>,
    pub created_at: u64,
    /// Ed25519 public key of the manifest creator. Reserved for the future
    /// owner-pinning pass; always `None` in this version.
    pub creator_pubkey: Option<[u8; 32]>,
    /// Ed25519 signature over the canonical postcard encoding with this field
    /// taken as `None`. Reserved; always `None` in this version.
    pub signature: Option<Signature>,
}

impl Manifest {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|e| Error::Manifest(format!("postcard serialize: {e}")))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let (manifest, rest) = postcard::take_from_bytes::<Manifest>(bytes)
            .map_err(|e| Error::Manifest(format!("postcard deserialize: {e}")))?;
        if !rest.is_empty() {
            return Err(Error::Manifest(format!(
                "{} trailing bytes after manifest",
                rest.len()
            )));
        }
        if manifest.version != MANIFEST_VERSION {
            return Err(Error::Manifest(format!(
                "unsupported manifest version {}; this build supports {}",
                manifest.version, MANIFEST_VERSION
            )));
        }
        Ok(manifest)
    }

    pub fn seal(&self, key: &ManifestKey) -> Result<Vec<u8>> {
        let plaintext = self.serialize()?;
        seal_manifest(key, &plaintext)
    }

    pub fn open(ciphertext: &[u8], key: &ManifestKey) -> Result<Self> {
        let plaintext = open_manifest(key, ciphertext)?;
        Self::deserialize(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erasure::DEFAULT_CHUNK_SIZE;
    use crate::hash::ChunkHash;

    fn sample() -> Manifest {
        Manifest {
            version: MANIFEST_VERSION,
            algorithm: Algorithm::default(),
            file_size: 12345,
            mime_type: "text/plain".into(),
            file_key: FileKey::from_bytes([7u8; 32]),
            erasure: ErasureParams::default(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            stripes: vec![Stripe {
                data: vec![
                    ChunkHash::of(b"a"),
                    ChunkHash::of(b"b"),
                    ChunkHash::of(b"c"),
                ],
                parity: vec![ChunkHash::of(b"d"), ChunkHash::of(b"e")],
            }],
            created_at: 1_700_000_000,
            creator_pubkey: None,
            signature: None,
        }
    }

    #[test]
    fn serialize_then_deserialize_roundtrip() {
        let m = sample();
        let bytes = m.serialize().unwrap();
        let back = Manifest::deserialize(&bytes).unwrap();
        // Compare via re-serialization, since FileKey has no PartialEq.
        assert_eq!(bytes, back.serialize().unwrap());
    }

    #[test]
    fn serialize_is_deterministic() {
        // Two structurally identical manifests must serialize byte-for-byte
        // identically, otherwise content addressing breaks.
        let a = sample().serialize().unwrap();
        let b = sample().serialize().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let mut bytes = sample().serialize().unwrap();
        bytes.extend_from_slice(b"trailing");
        assert!(Manifest::deserialize(&bytes).is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_version() {
        let mut m = sample();
        m.version = 99;
        let bytes = m.serialize().unwrap();
        assert!(Manifest::deserialize(&bytes).is_err());
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = ManifestKey::random();
        let m = sample();
        let sealed = m.seal(&key).unwrap();
        let opened = Manifest::open(&sealed, &key).unwrap();
        assert_eq!(m.serialize().unwrap(), opened.serialize().unwrap());
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let k1 = ManifestKey::random();
        let k2 = ManifestKey::random();
        let sealed = sample().seal(&k1).unwrap();
        match Manifest::open(&sealed, &k2) {
            Err(Error::Aead) => {}
            other => panic!("expected Aead, got {other:?}"),
        }
    }

    #[test]
    fn signature_fields_serialize_present() {
        // Forward-compat: even None values should serialize cleanly so the
        // schema is locked. Asserts the bytes for a None Option<[u8; 32]> and
        // None Option<[u8; 64]> appear at the tail.
        let bytes = sample().serialize().unwrap();
        // Last two bytes are the two None tags (postcard encodes Option::None
        // as a single 0 byte).
        assert!(bytes.len() >= 2);
        assert_eq!(bytes[bytes.len() - 2], 0);
        assert_eq!(bytes[bytes.len() - 1], 0);
    }

    #[test]
    fn algorithm_default_is_aes_hkdf_rs() {
        let alg = Algorithm::default();
        assert_eq!(alg.aead, Aead::Aes256Gcm);
        assert_eq!(alg.kdf, Kdf::HkdfSha256);
        assert_eq!(alg.erasure_code, ErasureCode::ReedSolomon);
    }
}
