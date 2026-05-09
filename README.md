# Crow

Decentralized, content-addressed, erasure-coded file storage with Tahoe-LAFS-style capabilities.

Crow is part of **Nest**, a family of bird-named peer-to-peer apps. Pigeon does messaging (BLE / LoRa mesh); Finch does payments; Crow does files.

A file in Crow is encrypted, chunked, hashed, erasure-coded, and stored as a set of content-addressed shares. The pointer to a file is a small token called a **capability** that bundles the manifest's content hash, its decryption key, and a permission. Sharing a file means sharing its capability. There are no accounts and no servers required; any device that holds at least *K* of *N* shares can reconstruct the file.

## Status

This crate ships the **data model**: chunks, manifests, capabilities, and the put / get pipeline that ties them together, plus an in-memory and an on-disk `ChunkStore`. The core invariant — file → cap → reconstructed file, including with shares missing — is covered end-to-end by integration tests.

Networking, gossip discovery, owner-pinning GC, the metadata CRDT, and live identity-based manifest signing are deferred to follow-up passes. See [Out of scope](#out-of-scope) below.

## How it works

```
plaintext  →  encrypt  →  chunk  →  Reed–Solomon  →  store as content-addressed shares
                                                          ↑
                                                manifest references each share's BLAKE3 hash
                                                manifest is itself encrypted and stored
                                                a capability points at the manifest
```

| Layer       | What it does                                                                                      | Module                            |
| ----------- | ------------------------------------------------------------------------------------------------- | --------------------------------- |
| Hash        | BLAKE3-256, with `ChunkHash` / `ManifestHash` newtypes                                            | `crow::hash`                      |
| Chunk store | Content-addressed byte store, namespaced by chunks vs manifests; in-memory or on-disk            | `crow::chunk`, `crow::fs_store`   |
| Crypto      | AES-256-GCM with HKDF-SHA-256-derived per-share nonces; keys zeroize on drop                      | `crow::crypto`                    |
| Erasure     | Reed–Solomon stripe encoding (default 3-of-5) via `reed-solomon-simd`                             | `crow::erasure`                   |
| Manifest    | Postcard-serialized, AES-256-GCM-sealed; declares its algorithm tuple; reserved signature fields  | `crow::manifest`                  |
| Capability  | Bech32m `crow1…` string carrying (version, permission, manifest hash, manifest key)               | `crow::cap`                       |
| Pipeline    | `Crow<S>::put_bytes` / `get_bytes` orchestration                                                  | `crow::pipeline`                  |

### Data flow

**put** splits the plaintext into K-sized stripes of `chunk_size` plaintext bytes each (last padded to `chunk_size`, last stripe padded to K plaintext chunks). Each plaintext chunk is AEAD-encrypted under a fresh `FileKey` with a nonce derived from `(stripe_idx, data_idx)`. Reed–Solomon expands the K data ciphertexts into N − K parity ciphertexts. All N shares are BLAKE3-hashed and written to the chunk store. Then the manifest is built, postcard-serialized, AEAD-sealed under a fresh `ManifestKey`, BLAKE3-hashed, and written. The capability returned is `(manifest_hash, manifest_key)`.

**get** is the inverse. Fetch the sealed manifest by `cap.manifest_hash`, decrypt with `cap.manifest_key`. For each stripe, fetch shares; if at least K are present, RS-decode any missing data ciphertexts, AEAD-decrypt all K plaintext chunks. Concatenate, truncate to `file_size`.

A tampered data share fails AEAD on decrypt. A tampered parity share also fails AEAD: RS-decode produces a wrong ciphertext from the corrupted parity, and AEAD then rejects it.

## Install

Crow is not published to crates.io yet. Install the CLI from the workspace:

```sh
git clone https://github.com/oliverrowebardeen/crow
cd crow
cargo install --path crates/crow-cli
```

That puts a `crow` binary on your `$PATH`. Uninstall with `cargo uninstall crow-cli`.

If you'd rather not install, every `crow …` command below has an in-place equivalent:

```sh
cargo run -q -p crow-cli -- <args…>
```

## CLI

```
crow put <file> [--mime MIME] [--chunk-size N]
crow get <cap> <out>
crow info <cap>
```

`<file>` and `<out>` accept `-` for stdin / stdout. Storage lives at `$CROW_HOME` (default `~/.crow`); override per-invocation with `--home PATH`.

### Walkthrough

```sh
$ echo 'hello, crow' > note.txt

$ crow put note.txt
crow1qyq...m0r

$ crow info crow1qyq...m0r
hash      3b52b656c0d0823c48db49446832a1c22cba58be9041184b4e24a5a251872f3b
size      12 B
mime      text/plain
erasure   3-of-5
stripes   1
shares    5
chunk     240 (240 B)
created   1778287037
algo      Aes256Gcm / HkdfSha256 / ReedSolomon

$ crow get crow1qyq...m0r restored.txt
$ diff note.txt restored.txt && echo ok
ok
```

Each `crow put` generates fresh keys, so the same bytes produce a different capability each time. Content-addressing happens at the *share* level, not the cap.

### Sharing

The cap is the only thing a holder needs. It's ASCII, ~117 chars, paste-friendly:

```sh
$ CAP=$(crow put report.pdf)
$ echo "$CAP" | pbcopy             # paste into Signal, Notion, chat, …

# elsewhere, on a machine that has the same chunks:
$ crow get "$CAP" report.pdf
```

Networked share fetching is not yet implemented — for now both machines must share the same `~/.crow/chunks/` directory or sync it some other way.

### Pipelines

```sh
# bundle a directory and store the tarball
tar cf - ~/Documents | crow put -

# write the bytes back to stdout
crow get crow1qyq...m0r - > backup.tar

# end-to-end stream
echo 'secret' | crow put - > note.cap
crow get "$(cat note.cap)" -
```

### Storage layout

```
~/.crow/
├── chunks/        # data and parity shares, file name = hex BLAKE3
└── manifests/     # AES-GCM-sealed postcard manifests, file name = hex BLAKE3
```

Each chunk file is exactly `chunk_size + 16` bytes (the AEAD tag). Writes are content-addressed, so identical bytes always land in the same hex filename — re-`put`ting the same file is a no-op. Writes are atomic via temp file + rename, so partial writes never leak.

### Configuration

| Knob           | How                                          | Default                                                                                                  |
| -------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Storage dir    | `--home PATH`, `$CROW_HOME`                  | `$HOME/.crow`                                                                                            |
| MIME type      | `--mime …` on `put`                          | inferred from extension, else `application/octet-stream`                                                 |
| Chunk size     | `--chunk-size N` on `put`                    | auto-tuned to ≈ `file_size / K`, capped at 1 MiB − 16; minimum 240; aligned so `(N + 16) % 64 == 0`      |
| Erasure params | (not yet exposed at the CLI)                 | 3-of-5                                                                                                   |

## Library

```rust
use crow::{Crow, ErasureParams, MemStore};

let crow = Crow::new(MemStore::new());

let cap = crow.put_bytes(
    b"hello, crow",
    "text/plain",
    ErasureParams::default(),  // 3-of-5
)?;

println!("{}", cap.encode());                 // crow1...
let restored = crow.get_bytes(&cap)?;
assert_eq!(restored, b"hello, crow");
```

For a persistent store, swap in `FsStore`:

```rust
use crow::{Crow, ErasureParams, FsStore};

let crow = Crow::new(FsStore::open("/tmp/crow-data")?);
let cap = crow.put_bytes(b"hi", "text/plain", ErasureParams::default())?;
```

Both stores implement the `ChunkStore` trait; `Crow<S>` is generic over it. Add your own backend (sled, redb, RocksDB, S3, …) by implementing five methods: `put`, `put_unverified`, `get`, `has`, `delete`.

The full demo — generate 5 MiB random, put, drop two shares per stripe, reconstruct from the cap — runs as:

```sh
cargo run -p crow --example roundtrip
```

## Layout

```
crow/
├── Cargo.toml                      # workspace
├── crates/
│   ├── crow/                       # library
│   │   ├── src/                    # hash · chunk · crypto · erasure · manifest · cap · identity · pipeline · fs_store
│   │   ├── examples/roundtrip.rs   # 5 MiB end-to-end demo
│   │   └── tests/integration.rs    # cross-module tests
│   └── crow-cli/                   # `crow` binary
│       └── src/main.rs
├── .github/workflows/ci.yml        # fmt + clippy + test
├── LICENSE-APACHE
├── LICENSE-MIT
└── README.md
```

## Development

```sh
cargo test --workspace
cargo run -p crow --example roundtrip
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

CI runs the same fmt / clippy / test triple on every push to `main` and every pull request — see `.github/workflows/ci.yml`.

Commits go on feature branches via pull requests — never push directly to `main`. Each commit does one thing (one feature, one bugfix, one refactor) and the message explains the *why*, not just the *what*.

## Out of scope

Roughly in landing order:

- **Persistence flavours** — sled / redb / RocksDB backends behind `ChunkStore`
- **Networking** — QUIC transport, LAN mDNS discovery
- **Gossip discovery** — chunk-have announcements + want broadcasts (BitTorrent PEX-style, not DHT)
- **Metadata CRDT** — LWW-Map for `name → manifest_hash`, ACLs, version history, holder hints
- **Owner-pinning GC** — TTL on unpinned chunks, owner liveness probes
- **Manifest signing** — wire `Identity` into put / get; populate the `creator_pubkey` and `signature` fields the manifest already carries
- **Write capabilities** — only `Read` exists today
- **Convergent encryption** for cross-file dedup
- **Content-defined chunking** (FastCDC) for similar-file dedup
- **Foreign transports** — BLE, LoRa via Pigeon, Wi-Fi Direct
- **Integration with sibling Nest projects** (Pigeon, Finch)

The data model is built so each of these lands additively. Manifests already declare their algorithm tuple, carry placeholder signature fields, and the chunk store is namespaced for GC.

## License

Dual-licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
