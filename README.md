# Crow

Content-addressed, erasure-coded file storage with Tahoe-LAFS-style capabilities.

Crow chunks files, addresses chunks by their BLAKE3 hash, encrypts them with AES-256-GCM, and erasure-codes them with Reed–Solomon so a file can be reconstructed even when some chunk holders are unreachable. Files are referenced by a capability — a small token bundling the manifest hash, the manifest decryption key, and a permission. Sharing a file means sharing its capability.

## Status

Early. The current crate ships only the data model:

- BLAKE3-addressed chunks and an in-memory chunk store
- AES-256-GCM encryption with HKDF-derived per-chunk nonces
- Reed–Solomon stripe encoding (default 3-of-5)
- Postcard-serialized, encrypted manifests
- Bech32m-encoded capabilities

Not yet wired up: persistence, networking, gossip discovery, owner-pinning GC, the metadata CRDT, and identity-based manifest signing. The pipeline runs end-to-end on a single process against an in-memory store.

## Layout

```
crates/crow/        # library: chunk, manifest, capability, pipeline
examples/           # runnable demos
tests/              # end-to-end integration tests
```

## Quick taste

```rust
use crow::{Crow, ErasureParams, MemStore};

let crow = Crow::new(MemStore::new());
let cap = crow.put_bytes(b"hello world", "text/plain", ErasureParams::default())?;
let restored = crow.get_bytes(&cap)?;
assert_eq!(restored, b"hello world");
println!("{}", cap.encode()); // crow1...
```
