use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::error::{Error, Result};

const CHUNK_NONCE_INFO: &[u8] = b"crow:chunk-nonce:v1";
const MANIFEST_NONCE_INFO: &[u8] = b"crow:manifest-nonce:v1";

/// Per-file symmetric key. Encrypts data shares only; parity shares are not
/// AEAD-protected (their integrity is via the manifest-recorded BLAKE3 hash
/// plus the AEAD failure that follows on the recovered ciphertext).
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct FileKey([u8; 32]);

/// Per-file symmetric key encrypting the serialized manifest. Carried in the
/// capability so a holder of the cap can decrypt the manifest and from there
/// the file.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct ManifestKey([u8; 32]);

macro_rules! key_methods {
    ($name:ident) => {
        impl $name {
            pub fn random() -> Self {
                let mut bytes = [0u8; 32];
                OsRng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            // Never print key material.
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

key_methods!(FileKey);
key_methods!(ManifestKey);

fn derive_chunk_nonce(file_key: &FileKey, stripe_idx: u64, data_idx: u32) -> [u8; 12] {
    // Inputs are uniformly random 32-byte keys, so HKDF::from_prk skips the
    // extract step; we only need the expand pass to bind (stripe, data) into
    // a 12-byte nonce.
    let hk = Hkdf::<Sha256>::from_prk(file_key.as_bytes())
        .expect("FileKey is 32 bytes; from_prk requires >= HashLen");
    let mut info = [0u8; CHUNK_NONCE_INFO_LEN];
    info[..CHUNK_NONCE_INFO.len()].copy_from_slice(CHUNK_NONCE_INFO);
    info[CHUNK_NONCE_INFO.len()..CHUNK_NONCE_INFO.len() + 8]
        .copy_from_slice(&stripe_idx.to_be_bytes());
    info[CHUNK_NONCE_INFO.len() + 8..].copy_from_slice(&data_idx.to_be_bytes());
    let mut nonce = [0u8; 12];
    hk.expand(&info, &mut nonce)
        .expect("12 bytes is well within HKDF-SHA256 expand limits");
    nonce
}

const CHUNK_NONCE_INFO_LEN: usize = CHUNK_NONCE_INFO.len() + 8 + 4;

fn derive_manifest_nonce(manifest_key: &ManifestKey) -> [u8; 12] {
    let hk = Hkdf::<Sha256>::from_prk(manifest_key.as_bytes())
        .expect("ManifestKey is 32 bytes");
    let mut nonce = [0u8; 12];
    hk.expand(MANIFEST_NONCE_INFO, &mut nonce)
        .expect("12 bytes within limits");
    nonce
}

pub fn seal_chunk(
    file_key: &FileKey,
    stripe_idx: u64,
    data_idx: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(file_key.as_bytes()));
    let nonce_bytes = derive_chunk_nonce(file_key, stripe_idx, data_idx);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.encrypt(nonce, plaintext).map_err(|_| Error::Aead)
}

pub fn open_chunk(
    file_key: &FileKey,
    stripe_idx: u64,
    data_idx: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(file_key.as_bytes()));
    let nonce_bytes = derive_chunk_nonce(file_key, stripe_idx, data_idx);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|_| Error::Aead)
}

pub fn seal_manifest(manifest_key: &ManifestKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(manifest_key.as_bytes()));
    let nonce_bytes = derive_manifest_nonce(manifest_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.encrypt(nonce, plaintext).map_err(|_| Error::Aead)
}

pub fn open_manifest(manifest_key: &ManifestKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(manifest_key.as_bytes()));
    let nonce_bytes = derive_manifest_nonce(manifest_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|_| Error::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_seal_open_roundtrip() {
        let key = FileKey::random();
        let pt = b"the quick brown fox jumps over the lazy dog";
        let ct = seal_chunk(&key, 0, 0, pt).unwrap();
        let back = open_chunk(&key, 0, 0, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn chunk_ciphertext_includes_aead_tag() {
        // GCM appends a 16-byte tag.
        let key = FileKey::random();
        let pt = b"x";
        let ct = seal_chunk(&key, 0, 0, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
    }

    #[test]
    fn chunk_open_with_wrong_key_fails() {
        let k1 = FileKey::random();
        let k2 = FileKey::random();
        let ct = seal_chunk(&k1, 0, 0, b"secret").unwrap();
        assert!(matches!(open_chunk(&k2, 0, 0, &ct), Err(Error::Aead)));
    }

    #[test]
    fn chunk_open_with_wrong_position_fails() {
        let key = FileKey::random();
        let ct = seal_chunk(&key, 0, 0, b"secret").unwrap();
        // Same key, but different (stripe, data) → different nonce → AEAD fails.
        assert!(matches!(open_chunk(&key, 1, 0, &ct), Err(Error::Aead)));
        assert!(matches!(open_chunk(&key, 0, 1, &ct), Err(Error::Aead)));
    }

    #[test]
    fn chunk_tampered_ciphertext_fails() {
        let key = FileKey::random();
        let mut ct = seal_chunk(&key, 0, 0, b"secret").unwrap();
        ct[0] ^= 1;
        assert!(matches!(open_chunk(&key, 0, 0, &ct), Err(Error::Aead)));
    }

    #[test]
    fn chunk_nonce_is_deterministic() {
        let key = FileKey::from_bytes([1u8; 32]);
        let n1 = derive_chunk_nonce(&key, 7, 3);
        let n2 = derive_chunk_nonce(&key, 7, 3);
        assert_eq!(n1, n2);
    }

    #[test]
    fn chunk_nonce_distinguishes_position() {
        let key = FileKey::from_bytes([1u8; 32]);
        let base = derive_chunk_nonce(&key, 0, 0);
        assert_ne!(base, derive_chunk_nonce(&key, 1, 0));
        assert_ne!(base, derive_chunk_nonce(&key, 0, 1));
        // Asymmetric: (stripe=1, data=0) must differ from (stripe=0, data=1).
        assert_ne!(
            derive_chunk_nonce(&key, 1, 0),
            derive_chunk_nonce(&key, 0, 1)
        );
    }

    #[test]
    fn chunk_nonce_distinguishes_keys() {
        let k1 = FileKey::from_bytes([1u8; 32]);
        let k2 = FileKey::from_bytes([2u8; 32]);
        assert_ne!(
            derive_chunk_nonce(&k1, 0, 0),
            derive_chunk_nonce(&k2, 0, 0)
        );
    }

    #[test]
    fn manifest_seal_open_roundtrip() {
        let key = ManifestKey::random();
        let pt = b"manifest payload";
        let ct = seal_manifest(&key, pt).unwrap();
        let back = open_manifest(&key, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn manifest_open_with_wrong_key_fails() {
        let k1 = ManifestKey::random();
        let k2 = ManifestKey::random();
        let ct = seal_manifest(&k1, b"manifest").unwrap();
        assert!(matches!(open_manifest(&k2, &ct), Err(Error::Aead)));
    }

    #[test]
    fn key_debug_does_not_leak_bytes() {
        let k = FileKey::from_bytes([0xAAu8; 32]);
        let dbg = format!("{k:?}");
        assert!(!dbg.contains("AA"));
        assert!(dbg.contains("redacted"));
    }
}
