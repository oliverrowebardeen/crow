use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::crypto::{FileKey, ManifestKey, open_manifest, seal_manifest};
use crate::erasure::ErasureParams;
use crate::error::{Error, Result};
use crate::hash::ChunkHash;
use crate::identity::{Identity, NodeId};

use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier, VerifyingKey};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    Unsigned,
    Signed { creator: NodeId },
}

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
    /// Ed25519 public key of the manifest creator. `None` means legacy
    /// unsigned data.
    pub creator_pubkey: Option<[u8; 32]>,
    /// Ed25519 signature over the canonical postcard encoding with this field
    /// taken as `None`.
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
        manifest.signature_status()?;
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

    pub fn sign(&mut self, identity: &Identity) -> Result<()> {
        let creator = identity.signing_pubkey();
        self.creator_pubkey = Some(creator);
        self.signature = None;
        let payload = self.signing_payload(creator)?;
        let signature: Ed25519Signature = identity.signing.sign(&payload);
        self.signature = Some(Signature(signature.to_bytes()));
        Ok(())
    }

    pub fn signature_status(&self) -> Result<SignatureStatus> {
        match (self.creator_pubkey, self.signature) {
            (None, None) => Ok(SignatureStatus::Unsigned),
            (Some(creator), Some(signature)) => {
                let payload = self.signing_payload(creator)?;
                let verifying_key = VerifyingKey::from_bytes(&creator)
                    .map_err(|e| Error::Manifest(format!("invalid creator public key: {e}")))?;
                let signature = Ed25519Signature::from_bytes(&signature.0);
                verifying_key
                    .verify(&payload, &signature)
                    .map_err(|_| Error::Manifest("invalid manifest signature".into()))?;
                Ok(SignatureStatus::Signed {
                    creator: NodeId::from_bytes(creator),
                })
            }
            _ => Err(Error::Manifest(
                "malformed manifest signature fields".into(),
            )),
        }
    }

    fn signing_payload(&self, creator: [u8; 32]) -> Result<Vec<u8>> {
        let mut canonical = self.clone();
        canonical.creator_pubkey = Some(creator);
        canonical.signature = None;
        canonical.serialize()
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

    fn signed_sample() -> (Manifest, Identity) {
        let identity = Identity::random();
        let mut manifest = sample();
        manifest.sign(&identity).unwrap();
        (manifest, identity)
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
    fn sign_records_creator_and_signature() {
        let (manifest, identity) = signed_sample();

        assert_eq!(manifest.creator_pubkey, Some(identity.signing_pubkey()));
        assert!(manifest.signature.is_some());
        assert_eq!(
            manifest.signature_status().unwrap(),
            SignatureStatus::Signed {
                creator: identity.node_id()
            }
        );
    }

    #[test]
    fn signed_manifest_seal_open_roundtrip() {
        let key = ManifestKey::random();
        let (manifest, _) = signed_sample();
        let sealed = manifest.seal(&key).unwrap();
        let opened = Manifest::open(&sealed, &key).unwrap();

        assert_eq!(manifest.serialize().unwrap(), opened.serialize().unwrap());
        assert!(matches!(
            opened.signature_status().unwrap(),
            SignatureStatus::Signed { .. }
        ));
    }

    #[test]
    fn signing_is_deterministic_for_same_manifest_and_identity() {
        let identity = Identity::random();
        let mut a = sample();
        let mut b = sample();

        a.sign(&identity).unwrap();
        b.sign(&identity).unwrap();

        assert_eq!(a.signature, b.signature);
        assert_eq!(a.serialize().unwrap(), b.serialize().unwrap());
    }

    #[test]
    fn unsigned_manifest_is_legacy_compatible() {
        assert_eq!(
            sample().signature_status().unwrap(),
            SignatureStatus::Unsigned
        );
        let bytes = sample().serialize().unwrap();
        assert!(Manifest::deserialize(&bytes).is_ok());
    }

    #[test]
    fn signed_manifest_rejects_tampering() {
        let (mut manifest, _) = signed_sample();
        manifest.file_size += 1;

        let err = manifest
            .signature_status()
            .expect_err("expected invalid signature");

        assert!(err.to_string().contains("invalid manifest signature"));
        assert!(Manifest::deserialize(&manifest.serialize().unwrap()).is_err());
    }

    #[test]
    fn partial_signature_fields_are_rejected() {
        let identity = Identity::random();
        let mut creator_only = sample();
        creator_only.creator_pubkey = Some(identity.signing_pubkey());
        assert!(creator_only.signature_status().is_err());

        let mut signature_only = sample();
        signature_only.sign(&identity).unwrap();
        signature_only.creator_pubkey = None;
        assert!(signature_only.signature_status().is_err());
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
