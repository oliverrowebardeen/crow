# Crow

Decentralized, content-addressed, erasure-coded file storage with Tahoe-LAFS-style capabilities.

A file in Crow is encrypted, chunked, hashed, erasure-coded, and stored as a set of content-addressed shares. The pointer to a file is a small token called a **capability** that bundles the manifest's content hash, its decryption key, and a permission. Sharing a file means sharing its capability. There are no accounts and no servers required; any device that holds at least *K* of *N* shares can reconstruct the file.

## Status

This crate ships the **data model**, a **daily-driver CLI**, a local filesystem-style catalog, **manual LAN fetch/sync over QUIC**, and **mDNS LAN peer discovery**: chunks, manifests, capabilities, in-memory and on-disk stores, pinning, garbage collection, QUIC chunk serving, automatic peer discovery on the local network, and subcommands such as `setup`, `device`, `put`, `get`, `cat`, `cap`, `share`, `receive`, `mkdir`, `ls`, `tree`, `find`, `du`, `mv`, `cp`, `put-dir`, `get-dir`, `stat`, `grep`, `rm`, `gc`, `serve`, `peers`, `fetch`, and `sync`. The core invariant — file → cap → reconstructed file, including with shares missing — is covered end-to-end by integration tests against a real on-disk store.

Background replication policy, catalog event signing, and friend-scoped sharing are deferred. See [Roadmap](#roadmap).

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
| Manifest    | Postcard-serialized, AES-256-GCM-sealed, and Ed25519-signed for creator provenance                | `crow::manifest`                    |
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

Crow is not published to crates.io yet. Once this repository is public, install the CLI directly from GitHub:

```sh
cargo install --git https://github.com/oliverrowebardeen/crow.git --bin crow
```

For local development, install from a checkout:

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

Requirements: Rust 1.85+ and a network that allows UDP multicast for mDNS discovery. If discovery is blocked, `crow fetch` still works with an explicit `IP:port`.

## CLI

```
crow setup [--name NAME] [--token TOKEN] [--force-token]
crow device
crow device name <name>
crow put <file> [catalog-path] [--name NAME] [--mime MIME] [--chunk-size N]
crow get <path-or-cap-or-prefix> <out>
crow cat <path-or-cap-or-prefix>
crow cap <path-or-cap-or-prefix>
crow share <path-or-cap-or-prefix> [--name NAME] [--plain]
crow receive <peer> <cap-or-prefix> [catalog-path] [--name NAME]
crow info <path-or-cap-or-prefix>
crow mkdir [-p] <catalog-path>
crow ls [catalog-path] [--long] [--pins]
crow tree [catalog-path]
crow find <basename-glob>
crow du [catalog-path]
crow mv <from-path> <to-path>
crow cp <src-path-or-cap-or-prefix> <catalog-path>
crow put-dir <local-dir> [catalog-dir] [--yes]
crow cap-dir <catalog-dir> [--name NAME]
crow get-dir <catalog-dir-or-dir-cap> <local-dir> [--yes]
crow add-dir <dir-cap-or-prefix> <catalog-dir>
crow pin  <cap> [--name NAME]
crow unpin [-r] <path-or-cap-or-prefix>
crow rm   <path-or-cap-or-prefix> [--dry-run]
crow gc   [--dry-run]
crow stat [path-or-cap-or-prefix]
crow grep <regex> <path-or-cap-or-prefix>
crow token init|show|set
crow serve [--bind ADDR] [--name NAME]
crow peers [--long] [--json]
crow fetch <peer> <cap-or-prefix> [--name NAME]
crow sync <peer>
crow nest list
crow nest current
crow nest create <name>
crow nest use <name-or-id-prefix>
```

`<file>` and `<out>` accept `-` for stdin / stdout. Storage lives at `$CROW_HOME` (default `~/.crow`); override per-invocation with `--home PATH`.

Nest selection is per-invocation overridable with `--nest <name-or-id-prefix>`. The default is the persisted active nest from `crow nest use`. Upgrading from a single-catalog layout migrates `<home>/{catalog, pins, chunks, manifests}` under a new default `personal` nest the first time any nest-aware command runs.

`<path-or-cap-or-prefix>` accepts a local catalog path (`/docs/report.pdf`), a full bech32m `crow1…` string, or a hex prefix of a pinned manifest hash. Prefix resolution goes through the flat pin index — caps that aren't pinned still work, but only via their full string or catalog path. Ambiguous prefixes get an explicit error listing the candidates.

Catalog folders are mutable local organization. To share a folder, freeze it into an immutable directory snapshot cap with `crow cap-dir /path`; later catalog edits do not change that cap.

Device names are local convenience metadata. `crow serve` advertises the saved name on LAN mDNS, but caps never contain device names, IP addresses, or other locators.

Nests are named encrypted vaults on the local device. Each nest has its own catalog, pins, and encrypted shares under `<home>/nests/<id>/`, so files in different nests can never see each other. Use `crow nest list` / `create` / `use` to switch between them and `--nest <name>` to target a non-active nest for a single command. Today every nest shares the same device-level cluster token for LAN fetch; per-nest membership and scoped tokens are Phase 3.

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
signed    yes (8dad17fbe7b1f81c)
pinned    2026-05-09T01:17:32Z (note.txt)

$ crow get 3b52 restored.txt
$ diff note.txt restored.txt && echo ok
ok

$ crow cat 3b52
hello, crow

$ crow rm 3b52
removed pin 3b52b656c0d08234 (note.txt)
deleted 1 manifest / 5 chunks (1.48 KiB)

$ crow stat
store         /home/alice/.crow
manifests     0 files / 0 B
chunks        0 files / 0 B
pins          0
catalog files 0
unreferenced  0 manifests / 0 chunks (0 B)
```

Each `crow put` generates fresh keys, so the same bytes produce a different capability and different encrypted shares each time. Content addressing happens at the *encrypted share* level, not the plaintext or the cap.

### Catalog workflow

If you pass a catalog destination to `put`, Crow stores the file under that path instead of creating a flat pin:

```sh
crow mkdir -p /docs/projects
crow put report.pdf /docs/projects/
crow put notes.md /docs/projects/
crow ls /docs/projects
crow tree /docs
crow find '*.pdf'
crow du /docs
crow info /docs/projects/report.pdf
crow stat /docs/projects/report.pdf
crow get /docs/projects/report.pdf restored.pdf
crow cat /docs/projects/notes.md | grep TODO
crow grep TODO /docs
crow cp /docs/projects/report.pdf /docs/projects/q2-copy.pdf
crow mv /docs/projects/report.pdf /docs/projects/q2-report.pdf
crow unpin /docs/projects/q2-report.pdf       # detach path; chunks remain until gc
crow unpin -r /docs/projects                  # detach a directory subtree
crow rm /docs/projects/q2-report.pdf --dry-run
```

`tree`, `find`, and `du` work from catalog metadata plus local manifests: no network traversal is implied. `find` searches basenames only. `cp` is metadata-only and points another catalog path at the same cap without duplicating chunks. `cat` writes raw file bytes to stdout, while `grep` reconstructs and searches file contents; use `find` when you only need a cheap name search.

Bulk folder import/export is explicit and asks for confirmation:

```sh
crow put-dir ./Photos /photos          # prompts y/N before storing
crow put-dir ./Photos /photos --yes
DIR_CAP=$(crow cap-dir /photos)        # immutable shareable snapshot
crow get-dir /photos ./RestoredPhotos
crow get-dir "$DIR_CAP" ./SharedPhotos
crow add-dir "$DIR_CAP" /imports/photos
```

`put-dir` recursively stores regular files and records directory entries in the local catalog. Symlinks are rejected. `cap-dir` stores and pins an encrypted directory manifest containing relative paths plus child file caps. `get-dir` creates the output directory if it does not exist, reconstructs a catalog subtree or directory cap into it, and refuses to overwrite existing files. `add-dir` attaches a directory snapshot cap back into the local catalog; it does not create a live shared folder.

### Pinning and garbage collection

`crow put <file>` without a catalog destination creates a flat pin with a default name (the input filename, or `(unnamed)` for stdin). `crow put <file> /path` and `crow put-dir` create catalog entries instead. `crow cap-dir /path` creates a pinned directory snapshot cap. Flat pins, catalog file paths, and pinned directory caps keep chunks alive; everything else is eligible for cleanup.

```sh
crow pin <cap> [--name NAME]          # add a flat pin (e.g. for a cap shared by someone else)
crow unpin [-r] <path-or-cap-or-prefix> # drop a flat pin or catalog path; chunks linger until `crow gc`
crow rm    <path-or-cap-or-prefix>    # drop the pin/path AND delete chunks not held elsewhere
crow gc    [--dry-run]                # sweep chunks/manifests not referenced by any pin or catalog path
```

The split between `unpin` and `rm` is deliberate: `unpin` is reversible if you still have the cap, since the chunks are still on disk, while `rm` is the unix-style "delete now." Catalog directories require `crow unpin -r /path` so a typo does not detach a whole subtree silently. Use `--dry-run` on `rm` and `gc` to see what would happen before committing.

### Two-device test

Phase 1 networking is for trusted devices you own on the same LAN. It is not friend-scoped sharing yet: every device with the shared cluster token can ask a serving peer for encrypted chunks by hash. The peer never sees cap keys or plaintext.

One-time setup:

```sh
# On the first device:
crow setup --name laptop

# On the second device, paste the token printed by the first:
crow setup --name phone --token <64-hex-token>
```

Serve chunks from the source device:

```sh
crow serve
# serving /Users/you/.crow on 0.0.0.0:7070
# node 8dad17fbe7b1f81c (laptop)
# cluster token: configured
# mDNS service: _crow._udp.local.
```

`crow serve` now also advertises the device on mDNS — the same mechanism behind AirPrint and Chromecast — so other Crow daemons on the same Wi-Fi see it without configuration. The daemon writes a snapshot of every peer it has seen to `<home>/peers.json` every five seconds.

List the snapshot:

```sh
$ crow peers
NODE              NAME              ADDRESS                 LAST SEEN
abcdef0123456789  laptop            192.168.1.10:7070       3s ago

self: 8dad17fbe7b1f81c phone on 192.168.1.20:7070 (snapshot 4s old)
```

Fetch a cap from another device — by IP:port, by node-id hex prefix, or by friendly name (the latter two resolve through the snapshot):

```sh
# Any of these work, given a peer snapshot:
crow fetch 192.168.1.42:7070 crow1qyq...m0r --name report.pdf
crow fetch abcd                crow1qyq...m0r --name report.pdf
crow fetch laptop              crow1qyq...m0r --name report.pdf

crow get <prefix> report.pdf
```

`fetch` pulls one encrypted manifest and its missing shares, verifies every object by BLAKE3 hash before storing it, pins the cap locally, and exits successfully only when local reconstruction works.

For your own devices, `sync` is the easier path: it pulls the peer's catalog event log, merges paths locally, then fetches missing encrypted manifests and chunks for every cataloged file.

```sh
# On laptop:
crow put report.pdf /docs/
crow serve

# On phone:
crow sync laptop
crow tree /docs
crow get /docs/report.pdf report.pdf
```

`sync` is manual and pull-based today. It does not yet run in the background, enforce a replication target, or prove that data is safe after one device disappears. Friend-scoped access comes after scoped identity/workspace work.

### Sharing

The cap is the only secret a holder needs. It's ASCII, ~117 chars, paste-friendly. For your own devices, prefer `crow sync <peer>` so paths and chunks move together without manually copying caps. For one-off file or directory handoff, use `share` and `receive`:

```sh
# Source device:
crow put report.pdf /docs/
crow share /docs/report.pdf
# cap       crow1qyq...m0r
# receive   crow receive <peer> crow1qyq...m0r /docs/report.pdf

# Receiving device:
crow receive laptop crow1qyq...m0r /docs/report.pdf
crow get /docs/report.pdf report.pdf
```

If you only need the raw cap for a script or a message:

```sh
crow cap /docs/report.pdf
crow share /docs/report.pdf --plain
```

Catalog directories are shared as immutable snapshots:

```sh
crow share /photos --name photos-snapshot
crow receive laptop crow1qyq... /imports/photos
```

If two peers have the same friendly name, `crow receive laptop ...` or `crow sync laptop` fails with the matching node-id prefixes and IP:port addresses. Retry with a longer node-id prefix or explicit IP:port. Specific file sharing with friends is deferred until scoped access can replace the personal-cluster token.

### Security model

- Capabilities are bearer tokens: anyone with a `crow1…` cap can decrypt the referenced file or directory snapshot if they can fetch enough encrypted shares.
- Manifest signatures prove which Crow identity created a file or directory snapshot; they do not grant access or imply that the creator is trusted.
- The personal-cluster token is shared-secret authorization for LAN fetch. Treat it like a password for devices you own.
- `crow sync` gives a trusted personal device your catalog metadata and asks it for encrypted objects by hash. Do not use a shared cluster token with devices you do not control.
- Device names and mDNS discovery are only convenience metadata. They are advertised only while `crow serve` runs, are not trusted for authorization, and are never embedded in caps.
- Crow is alpha software. Keep independent backups of important data until automatic multi-device replication is shipped and battle-tested.

### Pipelines

```sh
# bundle a directory and store the tarball
tar cf - ~/Documents | crow put -

# write the bytes back to stdout
crow get crow1qyq...m0r - > backup.tar
crow cat crow1qyq...m0r > backup.tar

# end-to-end stream
echo 'secret' | crow put - > note.cap
crow cat "$(cat note.cap)"
```

### Storage layout

```
~/.crow/
├── chunks/        # data and parity shares, file name = hex BLAKE3
├── manifests/     # AES-GCM-sealed postcard manifests, file name = hex BLAKE3
├── pins/          # one JSON file per pin, file name = <hex_manifest_hash>.json
├── catalog/       # CRDT-shaped local path event log + device id
├── device.json    # optional friendly device name for LAN discovery
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
use crow::{Crow, ErasureParams, Identity, MemStore};

let crow = Crow::new(MemStore::new());
let identity = Identity::random();

let cap = crow.put_bytes(
    b"hello, crow",
    "text/plain",
    ErasureParams::default(),  // 3-of-5
    &identity,
)?;

println!("{}", cap.encode());                 // crow1...
let restored = crow.get_bytes(&cap)?;
assert_eq!(restored, b"hello, crow");
```

For a persistent store, swap in `FsStore`. To pin and garbage-collect:

```rust
use crow::{
    CatalogIndex, Crow, ErasureParams, FsStore, GcOptions, Identity, PinIndex,
    compute_live_set_from_roots, sweep,
};

let store = FsStore::open("/tmp/crow-data")?;
let pins  = PinIndex::open("/tmp/crow-data")?;
let catalog = CatalogIndex::open("/tmp/crow-data")?;
let crow  = Crow::new(store);
let identity = Identity::load_or_create("/tmp/crow-data")?;

let cap = crow.put_bytes(b"hi", "text/plain", ErasureParams::default(), &identity)?;
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
├── CONTRIBUTING.md
├── SECURITY.md
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

Commits should be focused and reviewed through pull requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for the short contribution guide and [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Roadmap

This roadmap describes where Crow is headed. Later phases are plans that may change as the project develops.

Crow is being built as a local-first storage protocol first. The primary product surface is a
personal encrypted file space across your own devices; the same primitives can also support shared
signed context/artifact storage for developers and agents. Those surfaces need the same foundations:
identity, signed provenance, CRDT metadata sync, durable replication, and transport that works over
LAN, mesh, and the internet.

### Target model

The long-term user model is a **nest**: a named encrypted vault shared by trusted devices. A nest has
its own file tree, device list, keys, sharing rules, and storage policy. Users should think in terms
of nests, paths, devices, safety, and availability. They should not need to think about manifests,
shares, shard indexes, or peer addresses during normal use.

- **Nest.** A named encrypted file space, e.g. `personal`, `work`, `family-photos`, or `agents`.
- **Device.** A trusted machine attached to a nest with a cryptographic identity and local friendly name.
- **Catalog.** The CRDT-shaped file tree every trusted device can merge.
- **Object.** Encrypted manifests and shares addressed by BLAKE3 hashes.
- **Cap.** A portable bearer token for one immutable object or directory snapshot; powerful but not the main daily UX.
- **Pin.** A policy saying "keep this path available on this device."
- **Cache.** Temporary local bytes Crow may delete when safe.
- **Mirror.** A policy saying "keep the whole nest available on this device."
- **Prime.** An operational command saying "this device is online; make it useful now."
- **Drain.** An operational command saying "this device is leaving; move hot responsibility elsewhere."
- **Sync.** Nest convergence, not "clone everything from one peer."
- **Health.** The user-facing answer to "can I open this now, and is it safe if a device disappears?"

### Execution rules

- Keep the current CLI working while adding the nest layer. Do not break existing `~/.crow` stores without a migration path.
- Use one coherent commit per step. Each CLI command or protocol change should usually be its own commit.
- Every CLI change needs help text, README updates, and tests covering success and important edge cases.
- Preserve existing low-level commands until their replacement is shipped. Hide or document them as advanced before removing anything.
- Do not make normal users manage shards directly. Sharding is an internal placement mechanism; the UI is safety, availability, pinning, cache, mirror, prime, and drain.
- Do not depend on users remembering `crow drain` for correctness. Sudden sleep, crash, power loss, and network loss must be repaired by background health checks.
- Do not add destructive local-file lifecycle management such as `--rm-local` until Crow can prove data is durable on independent devices.
- Treat mDNS names and friendly names as convenience only. Authorization must come from nest membership, scoped keys, and signed identity.
- Keep caps as stable protocol primitives even if daily UX moves toward nests and native sharing.
- Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test` before merging non-doc changes.

### Command fate audit

| Current feature | Future role | Recommendation |
| --- | --- | --- |
| `put`, `get`, `cat` | Core file I/O inside the active nest | Keep; later auto-fetch missing bytes from reachable devices when possible. |
| `mkdir`, `ls`, `tree`, `find`, `grep`, `du` | Core filesystem-style UX | Keep; scope to active nest and teach `du` to separate logical size, local bytes, cache, pins, and replicas. |
| `put-dir`, `get-dir` | Bulk import/export between regular filesystem and a nest | Keep; eventually integrate with first-class directory objects and FUSE/app surfaces. |
| `mv`, `cp`, `rm` | Catalog mutation | Keep; make mutations signed nest events and keep `rm --dry-run` safety. |
| `info`, `stat` | Object/path metadata | Consolidate semantics: `stat` for a path/object, future `status` for nest health. Keep aliases if useful. |
| `pin`, `unpin` | Local availability policy | Reframe: `pin` means keep bytes available here; `unpin` means stop requiring local availability, not necessarily delete from the nest. |
| `gc` | Local maintenance | Keep as advanced/manual; long-term daemon should perform safe cache cleanup automatically. |
| `cap` | Raw protocol link | Keep as advanced/power-user output for scripts and one-off object sharing. |
| `share`, `receive` | Transitional cap handoff | Keep now; later route normal sharing through offer/inbox/accept while preserving raw cap mode. |
| `cap-dir`, `add-dir` | Immutable directory snapshots | Keep as snapshot tools; long-term add first-class mutable shared directories. |
| `serve` | Local daemon | Keep; future app or service should run it automatically. |
| `peers` | Discovered network endpoints | Keep as diagnostic; future daily command is `crow nest devices`. |
| `device` | Local identity/name | Keep; nest membership should reference device identities, not just friendly names. |
| `setup` | Bootstrap wrapper | Keep; future `setup` should create or join a default nest. |
| `token` | Shared personal-cluster secret | Replace with nest invites and scoped keys. Keep temporarily as an advanced LAN testing bridge. |
| `fetch` | Low-level object transfer | Keep as advanced/debug. Normal use should be `sync`, lazy fetch, or native sharing. |
| `sync <peer>` | Manual peer pull | Reframe as `sync` for nest convergence; keep `sync <device>` as an explicit/debug override. |
| New `nest` | Named encrypted vaults | Add as the main namespace: `create`, `list`, `use`, `rename`, `devices`, `status`, `invite`, `join`, `leave`. |
| New `status` | Health and availability | Add as a first-class command before destructive storage controls. |
| New `mirror`, `evict` | Placement policy | Add after health exists. `evict` must refuse unsafe deletion. |
| New `prime`, `drain` | Temporary availability operations | Add after availability accounting exists; these should move hot shards/cache, not change permanent membership. |
| New `inbox`, `accept` | Native sharing | Add with offer objects so users can share through Crow without a separate chat app. |

### Phase 0 — shipped data model

BLAKE3 content addressing, AES-256-GCM with HKDF-SHA-256-derived nonces, Reed-Solomon erasure
(default 3-of-5), postcard-serialized AEAD-sealed manifests, bech32m capabilities, in-memory and
on-disk chunk stores, end-to-end put/get pipeline, and signed manifests.

Done means the current invariant stays true forever: a file can be put, represented by a cap,
fetched from content-addressed encrypted shares, and reconstructed even with up to `N - K` missing
shares per stripe.

### Phase 1 — shipped personal device foundation

Several devices owned by one user, initially on the same LAN, syncing files between them.

1. **Storage hardening + local catalog — shipped.** Pinning, garbage collection, local catalog paths, folder import/export, tree/find/du/cat/stat/grep, immutable directory snapshot caps, and path-aware `unpin`.
2. **Daemon + chunk-fetch — shipped.** `crow serve` listens over QUIC and serves encrypted manifests/chunks to authorized clients.
3. **mDNS discovery — shipped.** LAN discovery advertises node id, port, and friendly name; authorization still comes from the token, not mDNS.
4. **Manifest signing — shipped.** New manifests are signed with the device Ed25519 identity; invalid signed manifests are rejected.
5. **Manual sync — shipped.** `crow sync <peer>` pulls catalog events and enough encrypted objects to make catalog files locally reconstructable.

Phase 1 is useful for private LAN testing, but it is not the final product model. It currently
increases storage use when every device fully syncs every object. Future phases must move toward
metadata-first sync, selective local bytes, and policy-driven placement.

### Phase 2 — nest foundation

Turn the single local catalog into explicit named encrypted spaces without breaking the existing CLI.

1. **Nest metadata model.** Add a nest record with stable id, human name, created timestamp, creator device id, catalog root, storage policy, member list, and key material references. Keep the actual secret material separate from display metadata.
2. **Storage layout migration.** Introduce a future layout such as `<home>/nests/<nest-id>/catalog`, `<home>/nests/<nest-id>/pins`, and `<home>/nests/<nest-id>/policy.json`. Migrate the current single catalog/pin index into a default `personal` nest on first use.
3. **Active nest selection.** Add `crow nest list`, `crow nest create <name>`, `crow nest use <name-or-id>`, `crow nest current`, and `--nest <name-or-id>`. Existing commands should operate inside the active nest.
4. **Nest-safe setup.** Make `crow setup` create identity plus a default `personal` nest. If legacy setup data exists, adopt it instead of overwriting it.
5. **Nest devices view.** Add `crow nest devices` as the user-facing trusted-device list. Keep `crow peers` as lower-level LAN/network discovery.
6. **Migration tests.** Cover empty homes, legacy homes, active nest switching, duplicate names, invalid names, and rollback-safe partial migration.

Acceptance criteria: existing README workflows still work; new users see a default nest; multiple
nests can coexist without cross-contaminating catalog entries, pins, policies, or member metadata.

### Phase 3 — signed metadata and nest membership

Replace shared-token trust with explicit nest membership.

1. **Signed catalog events.** Sign every catalog event with the device identity. Validation should reject malformed signatures, unknown writers when policy requires membership, and event replay with mismatched ids.
2. **Member roles.** Start with simple roles: owner/admin, writer, reader, storage-only. Do not build SaaS/team admin UI yet; the CLI and data model are enough.
3. **Device invites.** Add `crow nest invite` and `crow nest join` for your own devices. The invite should carry nest id, bootstrap endpoint hints, allowed device pubkey or pairing secret, and scoped permissions.
4. **Scoped authorization.** Replace the shared cluster token with per-nest authorization. A device should only be able to request catalog data and objects for nests it belongs to.
5. **Revocation shape.** Add a first conservative revocation model: stop accepting future signed events from a removed device and stop serving new object requests to it. Historical objects already copied to the device remain out of scope until key rotation exists.
6. **Compatibility bridge.** Keep `token` and token-based LAN fetch as an advanced testing mode until nest invites are reliable.

Acceptance criteria: two devices can join the same nest without copying a raw shared cluster token;
catalog events show who created them; a non-member cannot sync nest metadata or fetch objects through
the normal protocol.

### Phase 4 — metadata-first sync

Make `sync` mean "converge this nest" instead of "download everything from that peer."

1. **Split catalog sync from object sync.** Pull and merge catalog events without automatically fetching every manifest and share.
2. **No-arg sync.** Add `crow sync` to sync the active nest with all reachable trusted devices. Keep `crow sync <device>` for explicit debugging or targeted repair.
3. **Object availability index.** Track which devices claim to hold which manifests/shares, when that claim was last seen, and whether it was verified.
4. **Lazy object fetch.** `get`, `cat`, `grep`, and `get-dir` should attempt to fetch missing objects from reachable trusted devices when local reconstruction fails.
5. **Bounded sync modes.** Support metadata-only, path-scoped, and full-local sync. The default should not silently clone the entire nest onto small devices.
6. **Conflict reporting.** Catalog CRDT conflicts should be deterministic and visible. Do not silently lose path updates.

Acceptance criteria: a phone or laptop can see a large file in the catalog without storing its bytes;
opening the file pulls enough encrypted shares from reachable devices; `crow sync` does not imply
"store everything locally" unless policy says so.

### Phase 5 — health, placement, and storage policy

Make Crow answer whether data is safe, available, local, cached, pinned, mirrored, or at risk.

1. **Health model.** Define states such as `local`, `available-now`, `available-if-device-online`, `under-replicated`, `unverified`, `at-risk`, and `missing`.
2. **`crow status`.** Add a nest-level health command that summarizes catalog events, local bytes, remote availability, missing shares, under-replicated paths, and unsafe-to-evict objects.
3. **`crow stat` detail.** Keep `stat` focused on one path/object: logical size, local bytes, cap, manifest hash, erasure params, signing key, pin/cache/mirror state, and known shard locations.
4. **Policy file.** Add per-nest policy for minimum replicas, shard target, local cache budget, path-specific pins, mirror devices, and whether friend/storage-only devices may hold encrypted shares.
5. **Pin semantics.** `crow pin /path` means keep this path locally available. `crow unpin /path` means remove that local requirement, not necessarily remove the path from the nest.
6. **Mirror semantics.** Add `crow mirror on|off [path]` after health exists. A mirror device keeps the whole nest or subtree reconstructable locally.
7. **Safe evict.** Add `crow evict [path]` only after health can prove the nest remains reconstructable elsewhere. It deletes local cache/temp shards, not catalog entries.
8. **Background healer.** The daemon should repair under-replicated objects when devices disappear, new storage appears, or policy changes.
9. **Prime and drain.** Add `crow prime [path]` to pull hot shards/cache onto this device for near-term availability. Add `crow drain [path]` to move hot shard responsibility elsewhere before leaving. Both commands must be best-effort accelerators, not correctness requirements.
10. **Shard placement scheduler.** Decide where encrypted shares live using free space, uptime, network quality, battery, trust level, and policy. Start simple and deterministic; optimize later.

Acceptance criteria: Crow can tell a user whether it is safe to evict local bytes; a laptop going
offline without `drain` marks affected objects as degraded and triggers repair when other storage is
available; users do not need to manually reason about 3-of-5 shards.

### Phase 6 — internet and mesh transport

Make nests work when devices are not on the same Wi-Fi.

1. **Transport abstraction.** Split "who is this device?" from "how can I reach it?" Keep QUIC/LAN as one route, not the whole network model.
2. **Stable device addressing.** Use cryptographic device ids as stable addresses. Friendly names remain local labels and are never authorization.
3. **NAT traversal.** Add direct internet connectivity where possible with hole punching.
4. **Zero-knowledge relay.** Add an optional relay that sees opaque ciphertext and routing metadata only. It should not see cap keys, plaintext, or decrypted catalog contents.
5. **Route selection.** Try LAN first, then direct internet, then relay, then mesh/offline routes. Report which route was used in debug output.
6. **Mesh route support.** Carry the same object-fetch/catalog-sync protocol over Wi-Fi Direct, BLE, LoRa, or community mesh links. Expect low bandwidth and intermittent availability.
7. **Resume and retry.** Large object transfer must resume after route changes, sleep, or flaky connectivity.

Acceptance criteria: a friend or second device on another network can participate in a scoped nest
test without opening router ports manually; relays cannot decrypt stored data; mesh is a route, not
a separate storage mode.

### Phase 7 — Crow-native sharing and friend backup

Make sharing happen through Crow instead of external chat plus manual caps.

1. **Offer object.** Define an encrypted share offer containing sender, recipient, path/cap, permissions, expiry, optional message, and retrieval hints.
2. **Inbox.** Add `crow inbox` to list pending offers delivered through reachable devices, relay, or mesh.
3. **Accept flow.** Add `crow accept <offer>` to materialize a shared file, directory snapshot, or nest invitation into a local path/nest.
4. **Scoped access.** Recipients should get only the caps/keys needed for the shared object or subtree, not the sender's whole nest.
5. **Friend backup.** Let a trusted friend hold encrypted backup shards for a nest/path without gaining read access. This requires scoped storage authorization distinct from content decryption.
6. **Directory sharing.** Keep immutable directory caps for snapshots, then add first-class shareable directory objects when catalog/live-folder semantics are ready.
7. **Abuse and privacy basics.** Add block/delete offer behavior, expiry, local audit logs, and clear display of what metadata a recipient or relay can see.

Acceptance criteria: a user can send a Crow-native offer to a friend, the friend can accept it, and
the friend can fetch/reconstruct the shared object without receiving the sender's whole nest token.

### Phase 8 — developer and agent surfaces

Expose Crow as infrastructure for dev teams and agent-heavy workflows without turning Crow into an
agent runner.

1. **Local HTTP API.** Expose put/get/list/pin/catalog/status/fetch/sync operations from the daemon over a local API so tools in any language can use Crow without shelling out.
2. **Streaming APIs.** Replace large-object paths that require whole-file `Vec<u8>` buffering with streaming put/get and resumable transfer.
3. **MCP server.** Provide a small MCP server that lets AI tools read catalog resources, store/retrieve caps, publish signed context bundles, and inspect status.
4. **Workspace object.** Add a signed workspace manifest/event log that names members, roles, trusted devices, and replication policy. This can reuse nest machinery but should not force personal users into team concepts.
5. **SDKs and CI.** Add Python SDK first, then JS/TS. Provide Docker/CI install paths for ephemeral jobs that need to fetch or publish signed artifacts quickly.
6. **Provenance UX.** Make signed producer identity visible for artifacts and agent outputs. Provenance is a core dev-team value, not just a security detail.
7. **Observability.** Add structured logs and optional Prometheus-style metrics for daemon health, transfer failures, object availability, and policy repair.

Acceptance criteria: a local agent or CI job can store an artifact, publish a signed reference, and
another process can fetch it through the local API without needing to parse CLI output.

### Phase 9 — public release hardening

Prepare the project for external users.

1. **README compression.** Turn this internal roadmap into a shorter public roadmap while moving execution detail to design docs if needed.
2. **Install path.** Decide on crates.io, GitHub release binaries, Homebrew, Docker, or a staged combination.
3. **Security review checklist.** Document bearer cap risks, token deprecation, relay privacy, local filesystem permissions, key storage, and backup warnings.
4. **Compatibility policy.** State what formats are stable and what can still change before 1.0.
5. **CLI polish.** Clearly separate daily commands from advanced protocol/debug commands in help output.
6. **Cross-platform tests.** Verify macOS, Linux, and Windows behavior, especially atomic rename, daemon binding, mDNS behavior, path normalization, and file permissions.
7. **Example scenarios.** Provide tested walkthroughs for one laptop, two personal devices on LAN, internet relay test, friend share, and agent artifact storage.

Acceptance criteria: a technical external user can install Crow, understand alpha safety limits, run
a two-device test, and avoid known footguns.

### Deferred or explicit non-goals

- Sled / redb backends: `FsStore` with temp+rename atomic writes is sufficient until concurrent access patterns demand a database.
- Write capabilities: only `Read` exists today; add write caps only after nest membership and signed catalog events are solid.
- Convergent encryption: useful for dedup, but dangerous for privacy if rushed.
- Content-defined chunking: FastCDC-style similar-file dedup can wait until storage placement works.
- Full live shared folders: directory caps are immutable snapshots today; mutable shared directories require catalog/nest semantics first.
- Agent runner / scheduler: Crow may expose storage to agents, but should not become the orchestration layer.
- Full team SaaS admin UI: useful later if workspaces land, but premature before protocol, local API, and workspace model are proven.
- Destructive local-file lifecycle management: `--rm-local` remains unsafe until multi-device health can prove data is durable elsewhere.

## License

Dual-licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
