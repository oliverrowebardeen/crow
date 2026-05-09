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
//! Networking discovery, automatic replication, replicated metadata sync, and
//! live manifest signing are out of scope for this crate version.

pub mod cap;
pub mod catalog;
pub mod chunk;
pub mod crypto;
pub mod erasure;
pub mod error;
pub mod fs_store;
pub mod gc;
pub mod hash;
pub mod identity;
pub mod manifest;
pub mod pin;
pub mod pipeline;

pub use cap::{CAP_HRP, CAP_VERSION, Cap, Permission};
pub use catalog::{CatalogEntry, CatalogIndex, CatalogOp, CatalogPath, CatalogView, EntryKind};
pub use chunk::{ChunkStore, MemStore, Namespace};
pub use crypto::{FileKey, ManifestKey};
pub use erasure::{DEFAULT_CHUNK_SIZE, ErasureParams};
pub use error::{Error, Result};
pub use fs_store::FsStore;
pub use gc::{
    GcOptions, GcReport, LiveSet, compute_live_set, compute_live_set_from_catalog,
    compute_live_set_from_roots, sweep, targeted_remove,
};
pub use hash::{ChunkHash, Hash, ManifestHash};
pub use identity::Identity;
pub use manifest::{
    Aead, Algorithm, ErasureCode, Kdf, MANIFEST_VERSION, Manifest, Signature, Stripe,
};
pub use pin::{PinIndex, PinRecord};
pub use pipeline::Crow;
