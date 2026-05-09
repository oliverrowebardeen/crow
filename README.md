# Crow

Decentralized, content-addressed, erasure-coded file storage with Tahoe-LAFS-style capabilities.

Crow is part of **Nest**, a family of bird-named peer-to-peer apps. Pigeon does messaging (BLE / LoRa mesh); Finch does payments; Crow does files.

A file in Crow is encrypted, chunked, hashed, erasure-coded, and stored as a set of content-addressed shares. The pointer to a file is a small token called a **capability** that bundles the manifest's content hash, its decryption key, and a permission. Sharing a file means sharing its capability. There are no accounts and no servers required; any device that holds at least *K* of *N* shares can reconstruct the file.

## Status

This crate ships the **data model**, a **daily-driver CLI**, a local filesystem-style catalog, and the first **manual LAN fetch** pass: chunks, manifests, capabilities, in-memory and on-disk stores, pinning, garbage collection, QUIC chunk serving, and subcommands such as `put`, `get`, `mkdir`, `ls`, `mv`, `put-dir`, `get-dir`, `rm`, `gc`, `serve`, and `fetch`. The core invariant — file → cap → reconstructed file, including with shares missing — is covered end-to-end by integration tests against a real on-disk store.

mDNS discovery, automatic replication policy, replicated metadata sync, friend-scoped sharing, and live identity-based manifest signing are deferred. See [Roadmap](#roadmap).

## How it works

```
plaintext  →  encrypt  →  chunk  →  Reed–Solomon  →  store as content-addressed shares
                                                          ↑
                                                manifest references each share's BLAKE3 hash
                                                manifest is itself encrypted and stored
                                                a capability points at the manifest
```

| Layer       | What it does                                                                                      | Module                              |
| ----------- | ------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Hash        | BLAKE3-256, with `ChunkHash` / `ManifestHash` newtypes                                            | `crow::hash`                        |
| Chunk store | Content-addressed byte store, namespaced by chunks vs manifests; in-memory or on-disk             | `crow::chunk`, `crow::fs_store`     |
| Crypto      | AES-256-GCM with HKDF-SHA-256-derived per-share nonces; keys zeroize on drop                      | `crow::crypto`                      |
| Erasure     | Reed–Solomon stripe encoding (default 3-of-5) via `reed-solomon-simd`                             | `crow::erasure`                     |
| Manifest    | Postcard-serialized, AES-256-GCM-sealed; declares its algorithm tuple; reserved signature fields  | `crow::manifest`                    |
| Capability  | Bech32m `crow1…` string carrying (version, permission, manifest hash, manifest key)               | `crow::cap`                         |
| Pin index   | Per-pin JSON files at `<home>/pins/<hash>.json`, atomic writes, prefix lookup                     | `crow::pin`                         |
| Catalog     | CRDT-shaped append-only path event log at `<home>/catalog/events.jsonl`                           | `crow::catalog`                     |
| GC          | Mark-and-sweep over the chunk store; flat pins and catalog paths are retention roots               | `crow::gc`                          |
| Network     | QUIC chunk-fetch protocol with shared-token personal-cluster auth                                 | `crow-net`                          |
| Pipeline    | `Crow<S>::put_bytes` / `get_bytes` orchestration                                                  | `crow::pipeline`                    |

### Data flow

**put** splits the plaintext into K-sized stripes of `chunk_size` plaintext bytes each (last padded to `chunk_size`, last stripe padded to K plaintext chunks). Each plaintext chunk is AEAD-encrypted under a fresh `FileKey` with a nonce derived from `(stripe_idx, data_idx)`. Reed–Solomon expands the K data ciphertexts into N − K parity ciphertexts. All N shares are BLAKE3-hashed and written to the chunk store. Then the manifest is built, postcard-serialized, AEAD-sealed under a fresh `ManifestKey`, BLAKE3-hashed, and written. The capability returned is `(manifest_hash, manifest_key)`.

**get** is the inverse: fetch the sealed manifest by `cap.manifest_hash`, decrypt with `cap.manifest_key`. For each stripe, fetch shares; if at least K are present, RS-decode any missing data ciphertexts, AEAD-decrypt all K plaintext chunks. Concatenate, truncate to `file_size`.

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
crow put <file> [catalog-path] [--name NAME] [--mime MIME] [--chunk-size N]
crow get <path-or-cap-or-prefix> <out>
crow info <path-or-cap-or-prefix>
crow mkdir [-p] <catalog-path>
crow ls [catalog-path] [--long] [--pins]
crow mv <from-path> <to-path>
crow put-dir <local-dir> [catalog-dir] [--yes]
crow get-dir <catalog-dir> <local-dir> [--yes]
crow pin  <cap> [--name NAME]
crow unpin [-r] <path-or-cap-or-prefix>
crow rm   <path-or-cap-or-prefix> [--dry-run]
crow gc   [--dry-run]
crow stat
crow token init|show|set
crow serve [--bind ADDR]
crow fetch <peer-addr> <cap-or-prefix> [--name NAME]
```

`<file>` and `<out>` accept `-` for stdin / stdout. Storage lives at `$CROW_HOME` (default `~/.crow`); override per-invocation with `--home PATH`.

`<path-or-cap-or-prefix>` accepts a local catalog path (`/docs/report.pdf`), a full bech32m `crow1…` string, or a hex prefix of a pinned manifest hash. Prefix resolution goes through the flat pin index — caps that aren't pinned still work, but only via their full string or catalog path. Ambiguous prefixes get an explicit error listing the candidates.

Catalog folders are local organization only. Files remain the shareable unit: send someone the file's `crow1…` capability, not a folder path. Shareable directory manifests are intentionally deferred.

### Walkthrough

```sh
$ echo 'hello, crow' > note.txt

$ crow put note.txt
crow1qyq...m0r

$ crow ls
HASH         SIZE  MIME            PINNED      NAME
3b52b656     12 B  text/plain      2026-05-09  note.txt

$ crow info 3b52
hash      3b52b656c0d0823c48db49446832a1c22cba58be9041184b4e24a5a251872f3b
size      12 B
mime      text/plain
erasure   3-of-5
stripes   1
shares    5
chunk     240 (240 B)
created   2026-05-09T01:17:32Z
algo      Aes256Gcm / HkdfSha256 / ReedSolomon
pinned    2026-05-09T01:17:32Z (note.txt)

$ crow get 3b52 restored.txt
$ diff note.txt restored.txt && echo ok
ok

$ crow rm 3b52
removed pin 3b52b656c0d08234 (note.txt)
deleted 1 manifest / 5 chunks (1.48 KiB)

$ crow stat
store         /home/alice/.crow
manifests     0 files / 0 B
chunks        0 files / 0 B
pins          0
unreferenced  0 manifests / 0 chunks (0 B)
```

Each `crow put` generates fresh keys, so the same bytes produce a different capability and different encrypted shares each time. Content addressing happens at the *encrypted share* level, not the plaintext or the cap.

### Catalog workflow

If you pass a catalog destination to `put`, Crow stores the file under that path instead of creating a flat pin:

```sh
crow mkdir -p /docs/projects
crow put report.pdf /docs/projects/
crow ls /docs/projects
crow info /docs/projects/report.pdf
crow get /docs/projects/report.pdf restored.pdf
crow mv /docs/projects/report.pdf /docs/projects/q2-report.pdf
crow unpin /docs/projects/q2-report.pdf       # detach path; chunks remain until gc
crow unpin -r /docs/projects                  # detach a directory subtree
crow rm /docs/projects/q2-report.pdf --dry-run
```

Bulk folder import/export is explicit and asks for confirmation:

```sh
crow put-dir ./Photos /photos          # prompts y/N before storing
crow put-dir ./Photos /photos --yes
crow get-dir /photos ./RestoredPhotos
```

`put-dir` recursively stores regular files and records directory entries in the local catalog. Symlinks are rejected. `get-dir` creates the output directory if it does not exist, reconstructs the catalog subtree into it, and refuses to overwrite existing files.

### Pinning and garbage collection

`crow put <file>` without a catalog destination creates a flat pin with a default name (the input filename, or `(unnamed)` for stdin). `crow put <file> /path` and `crow put-dir` create catalog entries instead. Both flat pins and catalog file paths keep chunks alive; everything else is eligible for cleanup.

```sh
crow pin <cap> [--name NAME]          # add a flat pin (e.g. for a cap shared by someone else)
crow unpin [-r] <path-or-cap-or-prefix> # drop a flat pin or catalog path; chunks linger until `crow gc`
crow rm    <path-or-cap-or-prefix>    # drop the pin/path AND delete chunks not held elsewhere
crow gc    [--dry-run]                # sweep chunks/manifests not referenced by any pin or catalog path
```

The split between `unpin` and `rm` is deliberate: `unpin` is reversible if you still have the cap, since the chunks are still on disk, while `rm` is the unix-style "delete now." Catalog directories require `crow unpin -r /path` so a typo does not detach a whole subtree silently. Use `--dry-run` on `rm` and `gc` to see what would happen before committing.

### Personal-cluster fetch

Phase 1 networking is for trusted devices you own on the same LAN. It is not friend-scoped sharing yet: every device with the shared cluster token can ask a serving peer for encrypted chunks by hash. The peer never sees cap keys or plaintext.

One-time setup:

```sh
# On the source device:
crow token init
crow token show

# On the receiving device:
crow token set <64-hex-token>
```

Serve chunks from the source device:

```sh
crow serve
# serving /Users/you/.crow on 0.0.0.0:7070
# cluster token: configured
```

Fetch a cap from another device by LAN address:

```sh
crow fetch 192.168.1.42:7070 crow1qyq...m0r --name report.pdf
crow get <prefix> report.pdf
```

`fetch` pulls the encrypted manifest and missing shares, verifies every object by BLAKE3 hash before storing it, pins the cap locally, and exits successfully only when local reconstruction works. mDNS discovery, peer lists, and automatic replication are later Phase 1 steps.

### Sharing

The cap is the only thing a holder needs. It's ASCII, ~117 chars, paste-friendly:

```sh
$ CAP=$(crow put report.pdf)
$ echo "$CAP" | pbcopy             # paste into Signal, Notion, chat, …

# elsewhere, on a machine that has the same chunks:
$ crow pin "$CAP" --name report-from-friend.pdf
$ crow get  "$CAP" report.pdf
```

For personal devices on the same LAN, use `crow serve` + `crow fetch` as shown above. Specific file sharing with friends is deferred to Phase 2 so it can use scoped access instead of the personal-cluster token.

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
├── manifests/     # AES-GCM-sealed postcard manifests, file name = hex BLAKE3
├── pins/          # one JSON file per pin, file name = <hex_manifest_hash>.json
├── catalog/       # CRDT-shaped local path event log + device id
└── cluster-token  # shared personal-cluster token for QUIC fetch
```

Each chunk file is exactly `chunk_size + 16` bytes (the AEAD tag). Writes are content-addressed at the encrypted-byte level, and writes are atomic via temp-file + rename, so partial writes never leak.

### Configuration

| Knob           | How                                          | Default                                                                                                  |
| -------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Storage dir    | `--home PATH`, `$CROW_HOME`                  | `$HOME/.crow`                                                                                            |
| MIME type      | `--mime …` on `put`                          | inferred from extension, else `application/octet-stream`                                                 |
| Pin/name       | `--name …` on `put` or `pin`                 | basename of input file for flat pins and catalog file entries; absent for stdin or external `pin`        |
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

For a persistent store, swap in `FsStore`. To pin and garbage-collect:

```rust
use crow::{
    CatalogIndex, Crow, ErasureParams, FsStore, GcOptions, PinIndex,
    compute_live_set_from_roots, sweep,
};

let store = FsStore::open("/tmp/crow-data")?;
let pins  = PinIndex::open("/tmp/crow-data")?;
let catalog = CatalogIndex::open("/tmp/crow-data")?;
let crow  = Crow::new(store);

let cap = crow.put_bytes(b"hi", "text/plain", ErasureParams::default())?;
pins.add(cap.clone(), Some("note".into()), None)?;

// later, sweep anything not pinned or cataloged
let pin_caps = pins.list()?.into_iter().map(|r| r.cap).collect::<Vec<_>>();
let view = catalog.view()?;
let live = compute_live_set_from_roots(crow.store(), &pin_caps, &view)?;
let report = sweep(crow.store(), &live, GcOptions::default())?;
println!("freed {} chunks ({} bytes)", report.deleted_chunks, report.deleted_bytes);
```

Both stores implement the `ChunkStore` trait; `Crow<S>` is generic over it. Add your own backend (sled, redb, RocksDB, S3, …) by implementing six methods: `put`, `put_unverified`, `get`, `has`, `delete`, `list`. `size` has a default implementation but should be overridden for any backend with a metadata-only fast path.

The full data-model demo — generate 5 MiB random, put, drop two shares per stripe, reconstruct from the cap — runs as:

```sh
cargo run -p crow --example roundtrip
```

## Layout

```
crow/
├── Cargo.toml                      # workspace
├── crates/
│   ├── crow/                       # library
│   │   ├── src/                    # hash · chunk · crypto · erasure · manifest · cap · identity · pipeline · fs_store · pin · catalog · gc
│   │   ├── examples/roundtrip.rs   # 5 MiB end-to-end demo
│   │   └── tests/integration.rs    # cross-module + Phase 1 step 1 tests
│   ├── crow-net/                   # QUIC chunk-fetch protocol + token store
│   │   ├── src/
│   │   └── tests/
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

## Roadmap

Crow is being built in three phases. Phase 0 (the data model) and the start of Phase 1 are shipped; the rest is the plan.

### Phase 0 — data model (shipped)

BLAKE3 content addressing, AES-256-GCM with HKDF-SHA-256-derived nonces, Reed–Solomon erasure (default 3-of-5), postcard-serialized AEAD-sealed manifests, bech32m capabilities, in-memory and on-disk chunk stores, end-to-end put/get pipeline.

### Phase 1 — personal cluster

Several devices owned by one user, on the same network, syncing files between them.

1. **Storage hardening + local catalog — shipped.** Pinning, garbage collection, and the daily-driver CLI (`mkdir`, `ls`, `mv`, `put-dir`, `get-dir`, `pin`, `unpin`, `rm`, `gc`, `stat`) covered above. Per-pin JSON files at `<home>/pins/<hash>.json`, a CRDT-shaped catalog event log at `<home>/catalog/events.jsonl`, owner-pinning mark-and-sweep, hash-prefix resolution for every command that takes a flat pin, and path-aware `unpin` for non-destructive catalog detach.
2. **Daemon + chunk-fetch — shipped.** A long-running `crow serve` process listens over QUIC. Minimal protocol: *who are you*, *do you have hash X*, *send me hash X*. `crow fetch <peer> <cap>` pulls encrypted manifests and shares from a known peer after shared-token authorization.
3. **mDNS discovery — next.** Daemons announce themselves on the local network the same way AirPrint and Chromecast do; other Crows on the same Wi-Fi automatically add them to a peer list. Implementation should add a local peer registry, advertise the existing QUIC bind address plus device id, and let `crow fetch` accept a discovered device alias instead of only a raw socket address. No central server, no DHT.
4. **Replication policy.** Each device watches its pinned manifests and catalog file paths and quietly redistributes shares so any one device can drop offline without loss. Soft target: every share lives on at least two devices in the fleet.
5. **Replicated metadata sync.** Merge the local catalog event logs across devices, then add ACLs, version history, and holder hints. The on-disk catalog is already operation-log-shaped so this is a sync/merge step rather than a catalog rewrite.
6. **Identity wiring.** Sign manifests with the Ed25519 key Crow already generates; verify the signature before pinning so a foreign device on the same Wi-Fi can't inject pins or catalog entries into your fleet.

### Phase 2 — cross-person sharing

7. **Internet reachability.** A small zero-knowledge relay (à la pigeon-relay) plus NAT hole-punching for direct peer-to-peer between devices on different networks. The relay sees only opaque ciphertext.
8. **Sharing flow.** Explicit per-cap access lists, recipient pubkeys, optional expiry. Send a friend a cap, they pull from your devices (or via a relay), no Dropbox in the middle.

### Phase 3 — offline / mesh

9. **Pigeon transport integration.** Crow's chunk-fetch protocol over BLE, LoRa, and Wi-Fi-direct via Pigeon's existing mesh layer. Lower bandwidth, intermittent connectivity, but works without internet.

A stripped-down BLE-direct integration may move earlier (after Phase 1) if in-person tap-to-share becomes a headline feature; bandwidth tradeoffs are real but Pigeon already does the hard parts.

### Not yet on the roadmap

- Sled / redb backends — `FsStore` with temp+rename atomic writes is sufficient for the foreseeable workloads; revisit when concurrent access patterns demand it.
- Write capabilities — only `Read` exists today.
- Convergent encryption for cross-file dedup.
- Content-defined chunking (FastCDC) for similar-file dedup.
- Shareable directory manifests — folders are local catalog organization today; file caps are still the shareable unit.
- `--rm-local` / destructive local-file lifecycle management — unsafe until multi-device replication can prove data is durable elsewhere.

## License

Dual-licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
