use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Per-device identity: an Ed25519 signing keypair plus an X25519 key-exchange
/// keypair. Both are placeholders this version — neither is wired into the
/// pipeline yet.
///
/// The Ed25519 key will eventually populate `Manifest::creator_pubkey` and
/// sign manifests for owner-pinning. The X25519 key is reserved for future
/// peer-to-peer transport authentication. Generation lives here now so those
/// passes are additive and do not change manifest hashes when they land.
pub struct Identity {
    pub signing: SigningKey,
    pub kx: StaticSecret,
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

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // No "secret" or "private" string should appear.
        assert!(!dbg.to_lowercase().contains("secret"));
        assert!(!dbg.to_lowercase().contains("private"));
    }
}
