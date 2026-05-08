//! Crow — content-addressed, erasure-coded file storage with capabilities.
//!
//! The crate is organised in layers, bottom-up:
//!
//! - [`hash`] — BLAKE3 content addresses, with newtypes that distinguish
//!   chunk hashes from manifest hashes.
//! - [`chunk`] — the [`chunk::ChunkStore`] trait and an in-memory implementation.
//! - [`crypto`] — file-key / manifest-key types and AES-256-GCM seal/open with
//!   HKDF-derived nonces.
//! - [`erasure`] — Reed–Solomon stripe encode/decode.
//! - [`manifest`] — the encrypted, content-addressed file manifest.
//! - [`cap`] — Tahoe-LAFS-style capabilities encoded with Bech32m.
//! - [`identity`] — Ed25519 + X25519 keypair holder (placeholder; not yet
//!   wired into the pipeline).
//! - [`pipeline`] — the [`pipeline::Crow`] facade tying everything together.
//!
//! Networking, persistence, gossip discovery, the metadata CRDT, and live
//! manifest signing are out of scope for this crate version.

pub mod cap;
pub mod chunk;
pub mod crypto;
pub mod erasure;
pub mod error;
pub mod hash;
pub mod identity;
pub mod manifest;

pub use cap::{CAP_HRP, CAP_VERSION, Cap, Permission};
pub use chunk::{ChunkStore, MemStore, Namespace};
pub use crypto::{FileKey, ManifestKey};
pub use erasure::{DEFAULT_CHUNK_SIZE, ErasureParams};
pub use error::{Error, Result};
pub use hash::{ChunkHash, Hash, ManifestHash};
pub use identity::Identity;
pub use manifest::{
    Aead, Algorithm, ErasureCode, Kdf, MANIFEST_VERSION, Manifest, Signature, Stripe,
};
