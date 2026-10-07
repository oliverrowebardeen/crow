use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 32-byte BLAKE3 content address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    pub const SIZE: usize = 32;

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    pub fn of(bytes: &[u8]) -> Self {
        Hash(*blake3::hash(bytes).as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

impl FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Hash(format!(
                "expected 64 hex chars, got {}",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = &s[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|e| Error::Hash(format!("invalid hex {pair:?}: {e}")))?;
        }
        Ok(Hash(out))
    }
}

macro_rules! hash_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(pub Hash);

        impl $name {
            pub fn of(bytes: &[u8]) -> Self {
                Self(Hash::of(bytes))
            }

            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(Hash::from_bytes(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            pub const fn inner(&self) -> &Hash {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                Hash::from_str(s).map(Self)
            }
        }
    };
}

hash_newtype!(ChunkHash, "Content address of a stored chunk.");
hash_newtype!(ManifestHash, "Content address of an encrypted manifest.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_unicode_hex_is_rejected_without_panicking() {
        assert!(format!("{}a", "€".repeat(21)).parse::<Hash>().is_err());
    }

    #[test]
    fn blake3_empty_known_vector() {
        // BLAKE3 of the empty input — official test vector.
        let h = Hash::of(b"");
        assert_eq!(
            h.to_string(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn deterministic() {
        assert_eq!(Hash::of(b"hello world"), Hash::of(b"hello world"));
    }

    #[test]
    fn distinct_inputs_distinct_hashes() {
        assert_ne!(Hash::of(b"foo"), Hash::of(b"bar"));
    }

    #[test]
    fn hex_roundtrip() {
        let h = Hash::of(b"crow");
        let parsed: Hash = h.to_string().parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!("abcd".parse::<Hash>().is_err());
        assert!("".parse::<Hash>().is_err());
    }

    #[test]
    fn rejects_non_hex() {
        let bad = "z".repeat(64);
        assert!(bad.parse::<Hash>().is_err());
    }

    #[test]
    fn debug_format() {
        let h = Hash::of(b"x");
        let dbg = format!("{h:?}");
        assert!(dbg.starts_with("Hash("));
        assert!(dbg.ends_with(')'));
    }

    #[test]
    fn newtypes_share_inner_bytes() {
        let bytes = [7u8; 32];
        let chunk = ChunkHash::from_bytes(bytes);
        let manifest = ManifestHash::from_bytes(bytes);
        assert_eq!(chunk.as_bytes(), manifest.as_bytes());
    }

    #[test]
    fn newtype_hex_roundtrip() {
        let h = ChunkHash::of(b"chunk");
        let parsed: ChunkHash = h.to_string().parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn newtype_debug_uses_own_name() {
        let h = ManifestHash::of(b"m");
        let dbg = format!("{h:?}");
        assert!(dbg.starts_with("ManifestHash("));
    }
}
