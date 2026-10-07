# Crow

Local-first, content-addressed, erasure-coded encrypted file storage with read capabilities inspired by Tahoe-LAFS and LAN sync between trusted devices.

A file in Crow is chunked, each data chunk is encrypted, and Reed–Solomon parity is computed over the ciphertexts. The resulting shares are hashed and stored by content address. The pointer to a file is a small token called a **read capability** that bundles the manifest's content hash and decryption key. With the encrypted manifest and at least *K* of *N* shares from each stripe, a holder can reconstruct the file. Local storage needs no account or server; LAN transfer uses a serving device and the authentication described below.

## Status

The workspace ships the **data model**, an **experimental CLI**, a local filesystem-style catalog with **signed catalog events** and **per-nest membership**, **manual LAN fetch/sync over QUIC** with a **signed-challenge handshake** so two devices can share a nest without copying a raw cluster token, and **mDNS LAN peer discovery**: chunks, manifests, capabilities, in-memory and on-disk stores, pinning, garbage collection, QUIC chunk serving, automatic peer discovery on the local network, and subcommands such as `setup`, `device`, `put`, `get`, `cat`, `cap`, `share`, `receive`, `mkdir`, `ls`, `tree`, `find`, `du`, `mv`, `cp`, `put-dir`, `get-dir`, `stat`, `grep`, `rm`, `gc`, `serve`, `peers`, `fetch`, `sync`, and `nest invite` / `nest join`. Integration tests cover file → cap → reconstructed file, including missing-share recovery and tampering, using `MemStore`. Separate `FsStore` integration tests cover pin persistence, garbage collection, nest isolation, and migration with reconstruction.

Background replication policy and friend-scoped sharing are deferred. See [Roadmap](#roadmap).

## How it works

```
plaintext → chunk → encrypt each data chunk → Reed–Solomon over ciphertexts → store
                                                                              ↑
                                      manifest references each share's BLAKE3 hash
                                      manifest is itself encrypted and stored
                                      a capability points at the manifest
```

| Layer       | What it does                                                                                      | Module                              |
| ----------- | ------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Hash        | BLAKE3-256, with `ChunkHash` / `ManifestHash` newtypes                                            | `crow::hash`                        |
| Chunk store | Content-addressed byte store, namespaced by chunks vs manifests; in-memory or on-disk             | `crow::chunk`, `crow::fs_store`     |
| Crypto      | AES-256-GCM with HKDF-SHA-256-derived per-data-chunk nonces; parity shares have no nonces; keys zeroize on drop | `crow::crypto`             |
| Erasure     | Reed–Solomon stripe encoding (default 3-of-5) via `reed-solomon-simd`                             | `crow::erasure`                     |
| Manifest    | Postcard-serialized, AES-256-GCM-sealed, and Ed25519-signed for creator provenance                | `crow::manifest`                    |
| Capability  | Bech32m `crow1…` string carrying (version, permission, manifest hash, manifest key)               | `crow::cap`                         |
| Pin index   | Per-pin JSON files at `<home>/nests/<id>/pins/<hash>.json`, atomic writes, prefix lookup          | `crow::pin`                         |
| Catalog     | CRDT-shaped append-only path event log at `<home>/nests/<id>/catalog/events.jsonl`                | `crow::catalog`                     |
| GC          | Mark-and-sweep over the chunk store; flat pins and catalog paths are retention roots               | `crow::gc`                          |
| Network     | QUIC with nest-scoped signed-challenge client authentication; shared token for legacy access    | `crow-net`                          |
| Pipeline    | `Crow<S>::put_bytes` / `get_bytes` orchestration                                                  | `crow::pipeline`                    |

### Data flow

**put** splits the plaintext into stripes of K chunks of `chunk_size` bytes each (last chunk padded to `chunk_size`, last stripe padded to K plaintext chunks). A fresh `FileKey` is generated per file; each data chunk is AEAD-encrypted with a nonce derived from `(stripe_idx, data_idx)`. Reed–Solomon adds N − K parity shares computed over the K data ciphertexts. All N shares are BLAKE3-hashed and written to the chunk store. Then the manifest is built, postcard-serialized, AEAD-sealed under a fresh `ManifestKey`, BLAKE3-hashed, and written. The read capability contains `(manifest_hash, manifest_key)`.

**get** is the inverse: fetch the sealed manifest by `cap.manifest_hash`, decrypt with `cap.manifest_key`. For each stripe, fetch shares; if at least K are present, RS-decode any missing data ciphertexts, AEAD-decrypt all K plaintext chunks. Concatenate, truncate to `file_size`.

A tampered data share fails AEAD on decrypt. Corrupted parity can cause AEAD failure when that parity share is actually used to reconstruct a missing data ciphertext. If all data shares are present, parity is not used and its corruption is not detected by reconstruction. `FsStore::get` reads bytes without re-hashing them; network fetch checks object hashes before storing received bytes.

## Install

Crow is not published to crates.io yet. Install the CLI directly from GitHub:

```sh
cargo install --locked --git https://github.com/oliverrowebardeen/crow --bin crow
```

For local development, install from a checkout:

```sh
git clone https://github.com/oliverrowebardeen/crow
cd crow
cargo install --locked --path crates/crow-cli
```

That puts a `crow` binary on your `$PATH`. Uninstall with `cargo uninstall crow-cli`.

If you'd rather not install, every `crow …` command below has an in-place equivalent:

```sh
cargo run -q -p crow-cli -- <args…>
```

Requirements: Rust 1.88+ and the platform build prerequisites described in the [README](../README.md#install). UDP multicast is needed only for mDNS discovery. Both `crow sync` and `crow fetch` accept an explicit `IP:port` without a discovery snapshot; for reading after metadata-only sync without discovery, use `crow sync --full IP:port` to fetch the bytes first.

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
crow sync [--full] [peer]
crow nest list
crow nest current
crow nest devices [--long] [--json]
crow nest create <name>
crow nest use <name-or-id-prefix>
crow nest invite <recipient-node-id> [--expires-in DUR]
crow nest join <crowinvite1…>
```

`<file>` and `<out>` accept `-` for stdin / stdout. Storage lives at `$CROW_HOME` (default `~/.crow`); override per-invocation with the top-level option before the subcommand: `crow --home PATH <command>`.

Nest selection is per-invocation overridable with `--nest <name-or-id-prefix>`. The default is the persisted active nest from `crow nest use`. Upgrading from a single-catalog layout migrates `<home>/{catalog, pins, chunks, manifests}` under a new default `personal` nest the first time any nest-aware command runs.

`<path-or-cap-or-prefix>` accepts a local catalog path (`/docs/report.pdf`), a full bech32m `crow1…` string, or a hex prefix of a pinned manifest hash. Prefix resolution goes through the flat pin index — caps that aren't pinned still work, but only via their full string or catalog path. Ambiguous prefixes get an explicit error listing the candidates.

Catalog folders are mutable local organization. To share a folder, freeze it into an immutable directory snapshot cap with `crow cap-dir /path`; later catalog edits do not change that cap.

Device names are local convenience metadata. `crow serve` advertises the saved name on LAN mDNS, falling back to the OS hostname. Choose a name with `crow setup --name NAME` or override it with `crow serve --name NAME`. Caps never contain device names, IP addresses, or other locators.

Nests are named file spaces on the local device. Each nest has its own catalog, pins, encrypted shares, and **member list** under `<home>/nests/<id>/`. File contents and manifests are encrypted; catalog events and pin JSON contain plaintext paths/names and read capabilities. Use `crow nest list` / `create` / `use` to switch between nests and `--nest <name>` to target a non-active nest for a single command. Use `crow nest devices` to see the trusted devices in a nest; it combines signed membership with best-effort LAN presence from `crow serve`. `crow peers` remains the lower-level discovery diagnostic. Nest-scoped sync authenticates the client with a signed challenge; the server identity is not authenticated against a known device. Use recipient-bound `crow nest invite <node-id>` / `crow nest join` for sync. `crow serve` also accepts the legacy per-home `cluster-token`, which only authorizes fetching encrypted objects by hash.

### Walkthrough

Example output below uses placeholder hashes, capabilities, dates, and nest IDs.

```sh
$ echo 'hello, crow' > note.txt

$ crow put note.txt
crow1qyq...m0r

$ crow ls
HASH            SIZE  MIME                PINNED      NAME
3b52b656        12 B  text/plain          2026-05-09  note.txt

$ crow info 3b52
hash      3b52b656c0d0823c48db49446832a1c22cba58be9041184b4e24a5a251872f3b
type      file
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
removed pin 3b52b656c0d0823c (note.txt)
deleted 1 manifest / 5 chunks (1.58 KiB)

$ crow stat
store         /home/alice/.crow/nests/<nest-id>
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
crow rm /docs/projects/q2-report.pdf --dry-run
crow unpin /docs/projects/q2-report.pdf       # detach path; chunks remain until gc
crow unpin -r /docs/projects                  # detach a directory subtree
```

`tree`, `find`, and `du` work from catalog metadata plus local manifests: no network traversal is implied. `find` searches basenames only. `cp` is metadata-only and points another catalog path at the same cap without duplicating chunks. `get`, `cat`, `grep`, and `get-dir` try visible trusted nest devices when bytes are missing locally. `cat` writes raw file bytes to stdout and keeps lazy-fetch diagnostics on stderr, while `grep` reconstructs and searches file contents; use `find` when you only need a cheap name search.

`put-dir` asks for confirmation before import unless `--yes` is supplied. `get-dir` prompts only when the output directory already exists and is non-empty; `--yes` skips that prompt but does not allow overwriting files:

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

### Nests

A nest is a named file space on this device — its own catalog, pins, and encrypted shares living under `<home>/nests/<id>/`. Catalog events and pins store plaintext metadata and capabilities; the entire nest is not encrypted. Storage commands operate on one nest at a time; new homes get a `personal` nest automatically, and you can add more for project- or context-specific work.

```sh
$ crow nest list
ID         NAME                 CREATED      ACTIVE
1a638213   personal             2026-05-12   *

$ crow nest create work
created nest 'work' (b09af1ad)

$ crow nest use work
active nest: work (b09af1ad)

$ crow mkdir /docs

$ crow put report.pdf /docs/   # lands in `work`, not `personal`

$ crow ls /docs                # work's view
TYPE         SIZE  MIME                HASH      NAME
file         14 B  application/pdf     ffe72208  report.pdf

$ crow --nest personal ls      # one-shot override; active stays `work`
(no pinned files)

$ crow nest current
work  b09af1adba05923fc3e3961ade0cec3f
```

See trusted devices in a nest:

```sh
$ crow nest devices
NODE              NAME              ROLE    STATUS    ADDED       LAST SEEN   ADDRESS
8dad17fbe7b1f81c  laptop            owner   self      2026-05-09  -           192.168.1.8:7070
14a0f9d55e63b2a1  phone             owner   online    2026-05-09  8s ago      192.168.1.12:7070
```

`crow nest devices` is the membership view: it tells you which device identities are trusted in the nest. Online/offline status is a convenience hint from the local `crow serve` peer snapshot, not an authorization source. Use `crow peers --long` when debugging raw LAN discovery addresses.

Nests have separate on-disk catalogs, pins, and object directories. `crow sync` uses a signed challenge-response handshake for the selected nest; the server admits a current member or a device presenting a valid member grant from a current Owner. The legacy cluster token is per-home: `crow --nest X serve` lets any holder of that token fetch X's encrypted objects by hash, but not its catalog.

Upgrading from a pre-Phase-2 layout migrates `<home>/{catalog, pins, chunks, manifests}` under a fresh `personal` nest the first time any nest-aware command runs. Migration is crash-recoverable and idempotent: it moves directories individually and completes a partial migration on the next run. The index is published with an atomic write; the entire migration is not one atomic operation.

#### Sharing a nest with another device

Two-device setup using `crow nest invite` / `crow nest join` (no shared cluster token). Start with a local `report.pdf` on the laptop. Replace the example address with the laptop's LAN IP; the default serving port is 7070:

```sh
# On laptop:
crow setup --name laptop                  # creates a personal nest
crow nest create team
crow nest use team
crow mkdir /docs
crow put report.pdf /docs/

# On phone (a fresh home):
crow setup --name phone                   # phone has its own identity + token
crow device                               # copy the full "node" value

# On laptop:
# Paste the phone's full node id, then transfer the printed invite to the phone.
PHONE_NODE=0123...
crow nest invite "$PHONE_NODE"
crow serve                               # leave running in this terminal

# On phone:
INVITE='crowinvite1...'                   # paste the full invite from the laptop
crow nest join "$INVITE"
crow nest use team
crow sync --full 192.168.1.10:7070         # explicit address; no discovery snapshot needed
crow get /docs/report.pdf report.pdf      # bytes were fetched by --full
```

`crow nest invite <recipient-node-id>` requires the local device to already be an Owner of the named nest. `--expires-in` accepts `s` / `m` / `h` / `d` / `w` units (default `7d`); pass `0` or `never` to disable expiry. `crow nest join` verifies the granter's signature, checks the expiry (with a 5-minute clock-skew window), confirms the invite is bound to this device's NodeId, and writes a signed `MemberAdded` event into the new nest's catalog. The invite string is still sensitive in transit, but it cannot be redeemed by a different device key.

`crow sync` is metadata-first by default: it pulls signed catalog/member events from visible trusted devices in the active nest, but does not clone every file's bytes. `--full` in this example also fetches bytes, so the following `get` needs no discovery. Sync is nest-scoped only; a freshly joined invitee sends its signed membership proof during the first handshake so the inviter can authorize it before any prior sync. Copying a token with `setup --token` alone creates a different nest ID and does not enable sync.

### Two-device test

Networking is for trusted devices you own on the same LAN. It is not friend-scoped sharing yet. The legacy cluster token lets a holder fetch the served nest's encrypted objects by hash; catalog events, and the read capabilities in them, are served only to authenticated nest members.

For discovery-based sync and lazy fetch, first complete the invite/join setup above. Keep the laptop's `crow serve` running. On the phone, start a daemon for the joined nest too:

```sh
crow --nest team serve                    # leave running in a separate terminal
```

The laptop's daemon prints output like this (the directory is the served nest, not the home):

```sh
# serving /home/alice/.crow/nests/<nest-id> on 0.0.0.0:7070
# node 8dad17fbe7b1f81c (laptop)
# cluster token: configured
# mDNS service: _crow._udp.local.
```

`crow serve` advertises the device on mDNS so other Crow daemons on the same LAN can discover it when multicast is allowed. Each daemon writes its local peer snapshot to `<home>/peers.json` every five seconds. Starting `serve` only on the laptop does not populate the phone's snapshot.

In another terminal on the phone, use the same Crow home and wait until the laptop appears in `crow peers`:

```sh
$ crow peers
NODE              NAME              ADDRESS                 LAST SEEN
abcdef0123456789  laptop            192.168.1.10:7070       3s ago

self: 14a0f9d55e63b2a1 phone on 0.0.0.0:7070 (snapshot 4s old)
```

Now sync on the phone by name or sync all visible trusted devices:

```sh
crow sync laptop                         # metadata only
crow sync                                # all visible trusted devices
crow tree /docs
crow get /docs/report.pdf another-report.pdf
```

For newly cataloged files without local bytes, `get`, `cat`, `grep`, and `get-dir` use the local snapshot to try visible trusted devices. If discovery is unavailable, use `crow sync --full IP:port` before reading instead.

Legacy cap fetch is a separate path. On the receiving device, configure the serving laptop's cluster token (printed by its `setup`, or retrieved with `crow token show`). The token lets the receiver fetch encrypted objects by hash; it does not reveal the catalog or other capabilities. Then fetch by explicit address, or use a node-id prefix/name from the receiving device's snapshot:

```sh
crow token set <laptop-64-hex-token>
crow fetch 192.168.1.10:7070 crow1qyq...m0r --name report.pdf
# Alternatives, once `crow peers` lists the laptop:
# crow fetch abcd   crow1qyq...m0r --name report.pdf
# crow fetch laptop crow1qyq...m0r --name report.pdf
crow get <pinned-hash-prefix> fetched-report.pdf
```

`fetch` verifies received objects by BLAKE3 hash before storing them, pins the cap locally, and succeeds only when local reconstruction works. `sync` is manual and pull-based today. It does not yet run in the background, enforce a replication target, or prove that data is safe after one device disappears. Lazy fetch caches requested bytes locally; smarter shard placement and eviction come later. Friend-scoped access is planned.

### Sharing

The cap is the only secret needed to decrypt the referenced object once its encrypted manifest and enough shares are available. Fetching with `receive` or `fetch` also requires the serving device's cluster token, configured in the receiving home. That token lets the receiver download encrypted objects by hash but not the catalog, so without other capabilities they can decrypt only what you shared. A cap is ASCII, about 117 characters, and paste-friendly. For your own devices, prefer invite/join and `crow sync` so paths move through the nest without manually copying caps. For a token-authorized file or directory handoff, use `share` and `receive`:

```sh
# Source device (already set up; run `crow serve` in another terminal):
crow mkdir -p /docs
crow put report.pdf /docs/
crow share /docs/report.pdf
# type      file
# cap       crow1qyq...m0r
# token     configured
# receive   crow receive <peer> crow1qyq...m0r /docs/report.pdf

# Receiving device (configured with the source's cluster token as above):
crow receive 192.168.1.10:7070 crow1qyq...m0r /docs/report.pdf
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
- **Catalog changes from peers must come from members.** The CLI uses `merge_events_from_peer_for_nest`, which rejects unsigned or tampered events, checks authority for `MemberAdded` / `MemberRevoked`, and requires every new ordinary operation (`Mkdir`, `PutFile`, `Remove`, `Move`) to be signed by a member of the nest's resulting member set. A member's operations dated after their revocation are rejected (dates are signer-supplied). The whole batch is validated before anything is written, so a rejected sync leaves the catalog unchanged. Server certificates are self-signed and unpinned, so a connection does not authenticate a known server device.
- **Nest membership is per-device-identity-bound.** `crow nest invite <node-id>` produces a recipient-bound credential that the recipient redeems into a per-device `MemberAdded` catalog event. The first QUIC handshake can carry that signed membership proof so a newly joined device can bootstrap sync without copying the legacy cluster token. For nest-scoped requests, the daemon admits a peer iff that peer's signing key is a current member of the named nest or presents a valid grant from a current Owner.
- Invite strings are recipient-bound but still sensitive while in transit. Once redeemed, the new device's identity is independently recorded in the catalog, so a future Phase-5 revocation will be per-device rather than per-invite.
- `crow serve` also accepts the legacy cluster token, which authorizes only Hello/Have/Get of encrypted objects by hash. The legacy catalog request is always refused; catalog events are served only to authenticated nest members. `crow setup` prints the token: keep setup output out of screenshots and logs. Prefer `crow nest invite` / `crow nest join` for sync without copying the token.
- `crow sync` pulls catalog metadata and, with `--full`, encrypted objects by hash; lazy fetch retrieves missing bytes on read. These CLI paths use nest-scoped client authentication; legacy token holders can fetch the same encrypted objects by hash but not the catalog.
- Only file contents and manifests are encrypted at rest. Catalog events (`events.jsonl`) and pin JSON store plaintext paths/names and capabilities under the Crow home.
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
├── identity.json  # Ed25519 and X25519 SECRET keys; new files are 0600 on Unix
├── cluster-token  # per-home legacy token; fetch encrypted objects by hash
├── device.json    # friendly device name, written by setup/device name
├── nests.json     # nest index and active selection
├── peers.json     # discovery snapshot, written by serve
└── nests/
    └── <id>/
        ├── chunks/       # encrypted data and parity shares, named by hex BLAKE3
        ├── manifests/    # AES-GCM-sealed manifests, named by hex BLAKE3
        ├── pins/         # plaintext <hex_manifest_hash>.json: cap and pin metadata
        ├── catalog/      # plaintext events.jsonl, device-id, .founding-stamped
        └── policy.json   # placeholder for future storage policy
```

Files and directories are created as needed. Each data/parity share file is exactly `chunk_size + 16` bytes (data ciphertext includes an AEAD tag; parity is computed over ciphertext). Object writes are content-addressed at the encrypted-byte level and published atomically from temporary files. Interrupted writes may leave temporary files, but not a partially written hash-named object.

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
│   │   ├── src/                    # lib · cap · catalog · chunk · crypto · dir_manifest · erasure · error
│   │   │                           # fs_store · gc · hash · identity · invite · manifest · member · nest · pin · pipeline
│   │   ├── examples/roundtrip.rs   # 5 MiB end-to-end demo
│   │   └── tests/integration.rs    # recovery, pins, GC, catalog isolation, migration
│   ├── crow-net/                   # QUIC, nest auth, legacy tokens, discovery
│   │   ├── src/                    # lib.rs · discovery.rs · peer_snapshot.rs
│   │   └── tests/                  # integration.rs · quic.rs
│   └── crow-cli/                   # `crow` binary
│       └── src/main.rs
├── .github/workflows/ci.yml        # quality, test, minimum-rust, dependencies, secrets
├── docs/GUIDE.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE-APACHE
├── LICENSE-MIT
└── README.md
```

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo run --locked -p crow --example roundtrip
```

CI runs on pushes to `main`, pull requests, manual dispatch, and a weekly Monday 09:17 UTC schedule. Its jobs are `quality` (rustfmt and strict Clippy), `test` (Ubuntu and macOS, including doc tests and the roundtrip example), `minimum-rust` (Rust 1.88.0 workspace check), `dependencies` (`cargo-audit --deny warnings`), and `secrets` (Gitleaks over full history). See [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

Commits should be focused and reviewed through pull requests. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the short contribution guide and [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Roadmap

This roadmap describes where Crow is headed. Phases 0–2 have shipped; phases 3–4 have
partially shipped, as noted below. Later phases are plans that may change as the project develops.

Crow is being built as a local-first storage protocol first. The primary product surface is a
personal encrypted file space across your own devices; the same primitives can also support shared
signed context/artifact storage for developers and agents. Those surfaces need the same foundations:
identity, signed provenance, CRDT metadata sync, durable replication, and transport that works over
LAN, mesh, and the internet.

### Target model

The long-term user model is a **nest**: a named file space shared by trusted devices. File trees
and device lists have shipped; richer sharing rules and storage policies are planned. Encryption
keys are per object, and identity and legacy token files are per home. Users should think in terms
of nests, paths, devices, safety, and availability. They should not need to think about manifests,
shares, shard indexes, or peer addresses during normal use.

- **Nest — shipped.** A named file space with encrypted file contents and manifests, e.g. `personal`, `work`, `family-photos`, or `agents`; local catalog and pin metadata are plaintext.
- **Device — shipped.** A trusted machine attached to a nest with a cryptographic identity and local friendly name. Server identity authentication remains planned.
- **Catalog — shipped.** A CRDT-shaped file tree with signed events and manual merge; ordinary path-event signers are not authorized by membership.
- **Object — shipped.** Encrypted manifests and shares addressed by BLAKE3 hashes.
- **Cap — shipped.** A portable bearer decryption secret for one immutable file or directory snapshot.
- **Pin — retention shipped; availability policy planned.** Today `pin <cap>` records a GC retention root without fetching bytes. `unpin /path` removes the catalog entry. A policy meaning "keep this path available on this device" is planned.
- **Cache — policy planned.** Lazy fetch and `sync --full` store bytes today; automatic cache budgets and safe eviction are planned.
- **Mirror — planned.** A policy saying "keep the whole nest available on this device."
- **Prime — planned.** An operational command to pull hot shards/cache onto this device.
- **Drain — planned.** An operational command to move hot shard responsibility elsewhere before this device leaves.
- **Sync — manual metadata sync and optional full fetch shipped.** Automatic background convergence remains planned.
- **Health — planned.** Reporting whether bytes are available now and remain safe if a device disappears.

### Design principles

- Keep the current CLI working while adding the nest layer. Do not break existing `~/.crow` stores without a migration path.
- Keep changes focused. Each CLI command or protocol change should usually be its own commit.
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
| `put`, `get`, `cat` | Core file I/O inside the active nest | Shipped, including lazy fetch for `get` and `cat` from visible trusted devices. |
| `mkdir`, `ls`, `tree`, `find`, `grep`, `du` | Core filesystem-style UX | Active-nest scope and lazy fetch for `grep` shipped; richer local/cache/replica accounting in `du` is planned. |
| `put-dir`, `get-dir` | Bulk import/export between regular filesystem and a nest | Keep; eventually integrate with first-class directory objects and FUSE/app surfaces. |
| `mv`, `cp`, `rm` | Catalog mutation | Signed nest catalog events and `rm --dry-run` shipped; ordinary event signatures do not enforce membership authorization. |
| `info`, `stat` | Object/path metadata | Consolidate semantics: `stat` for a path/object, future `status` for nest health. Keep aliases if useful. |
| `pin`, `unpin` | Local availability policy | Reframe: `pin` means keep bytes available here; `unpin` means stop requiring local availability, not necessarily delete from the nest. |
| `gc` | Local maintenance | Keep as advanced/manual; long-term daemon should perform safe cache cleanup automatically. |
| `cap` | Raw protocol link | Keep as advanced/power-user output for scripts and one-off object sharing. |
| `share`, `receive` | Transitional cap handoff | Keep now; later route normal sharing through offer/inbox/accept while preserving raw cap mode. |
| `cap-dir`, `add-dir` | Immutable directory snapshots | Keep as snapshot tools; long-term add first-class mutable shared directories. |
| `serve` | Local daemon | Keep; future app or service should run it automatically. |
| `peers` | Discovered network endpoints | Keep as diagnostic; daily trusted-device view is `crow nest devices`. |
| `device` | Local identity/name | Shipped; nest membership already references device identities. |
| `setup` | Bootstrap wrapper | Default `personal` nest creation/migration shipped; joining another device's nest uses `nest join`. |
| `token` | Per-home secret for fetching encrypted objects by hash | Replace with scoped authorization; `serve` accepts it for object access only. |
| `fetch` | Low-level object transfer | Keep as advanced/debug. Normal use should be `sync`, lazy fetch, or native sharing. |
| `sync [peer]` | Nest metadata convergence and optional local caching | Default is metadata-first across visible trusted devices; `sync <device>` targets one device; `--full` explicitly caches cataloged bytes locally. |
| `nest` | Named file spaces with encrypted contents and plaintext catalog/pin metadata | `create`, `list`, `use`, `current`, `devices`, `invite`, and `join` shipped; `rename`, `status`, and `leave` planned. |
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
3. **mDNS discovery — shipped.** LAN discovery advertises node id, port, and friendly name. Authentication primarily uses the nest-scoped signed challenge, with a shared token for legacy access; mDNS names are not authorization.
4. **Manifest signing — shipped.** New manifests are signed with the device Ed25519 identity; invalid signed manifests are rejected.
5. **Manual full sync — superseded.** Early `crow sync <peer>` pulled catalog events plus enough encrypted objects to make every catalog file locally reconstructable. Phase 4 replaces that with metadata-first sync and lazy fetch.

Full sync increases storage use when every device fetches every cataloged object. Phase 4 has
shipped metadata-first sync and lazy fetch; policy-driven placement remains planned.

### Phase 2 — nest foundation

Turn the single local catalog into explicit named file spaces without breaking the existing CLI.

1. **Nest metadata model — shipped.** `Nest`, `NestId`, and `NestIndex` types persist to `<home>/nests.json`; atomic temp+rename writes; format-aware serde (hex string in JSON, raw bytes in postcard).
2. **Storage layout migration — shipped.** First nest-aware command on a legacy `<home>` moves `catalog/`, `pins/`, `chunks/`, and `manifests/` under `<home>/nests/<id>/`. Partial migrations finish moving any remaining legacy directories into the existing nest dir, then write `nests.json`. Refuses to overwrite conflicting directories or silently merge legacy directories into an existing index.
3. **Active nest selection — shipped.** `crow nest list`, `crow nest current`, `crow nest create <name>`, `crow nest use <name-or-id>`, and the global `--nest <name-or-id>` flag. Existing commands operate inside the active nest.
4. **Nest-safe setup — shipped.** `crow setup` now ensures the default `personal` nest exists (creating it on a fresh home, or migrating a legacy layout) and surfaces it in the success banner.
5. **Nest devices view — shipped.** `crow nest devices [--long] [--json]` is the user-facing trusted-device list. It reads signed nest membership from the catalog and overlays best-effort LAN presence from the `crow serve` peer snapshot. `crow peers` stays as lower-level network discovery.
6. **Migration tests — shipped.** Unit tests in `crow::nest` cover fresh/legacy/partial/idempotent migration paths plus create/use/resolve validation. Integration tests verify that legacy data reconstructs through the migrated nest, that two nests stay isolated, and that partial-migration crashes recover without data loss.

Acceptance criteria: existing README workflows still work; new users see a default nest; multiple
nests can coexist without cross-contaminating catalog entries, pins, policies, or member metadata.

### Phase 3 — signed metadata and nest membership

Replace shared-token trust with explicit nest membership.

1. **Signed catalog events — shipped.** Every `CatalogEvent` carries `signer: Option<NodeId>` and `signature: Option<Signature>`. The signing payload is the postcard encoding of the event with the signature field cleared, mirroring the manifest pattern. `merge_events` accepts unsigned events on local replay (Phase-2 events on disk still load); the CLI's `merge_events_from_peer_for_nest` rejects them. Tampering invalidates the signature in both modes. Remote path events must be signed by a current nest member.
2. **Member roles — Owner only.** `NestRole::Owner` is the only variant for now. Writer / Reader / Storage-only land in a follow-up phase when they have meaningful capability differences.
3. **Device invites — shipped.** `crow nest invite <recipient-node-id>` produces a signed `crowinvite1…` bech32m string with HRP `crowinvite`. `crow nest join <invite>` decodes, verifies the granter's invite signature, verifies the embedded member-grant signature over `(nest_id, granter, recipient, role, added_at)`, checks expiry, creates a local nest dir carrying the granter's `nest_id`, and writes a verifiable `MemberAdded` event into the catalog.
4. **Scoped authorization — shipped.** QUIC gains a per-connection challenge-response handshake (`NestHello` → `NestChallenge` → `NestAuthResponse`). The server issues a fresh random 32-byte challenge per connection, the client signs a domain-tagged payload with its identity key, and the server admits the peer iff the signer is a current non-revoked member of the named nest or presents a valid signed `MemberAdded` proof from a current Owner. Subsequent `NestHave` / `NestGet` / `NestCatalogEvents` on the connection are gated on the per-connection auth flag. Wire protocol version is now 3; signatures include a TLS exporter binding to prevent forwarding a proof between connections. Upgrade all peers together.
5. **Revocation — no CLI workflow.** `CatalogOp::MemberRevoked` and `MemberRecord::revoked_at` exist in the format and library; merge validates revocation authority and nest authentication checks `revoked_at`. There is no device-removal command or complete end-user revocation workflow. Copied capabilities, keys, and plaintext cannot be recalled.
6. **Legacy access — narrowed.** The `serve` daemon still accepts legacy `ClusterToken` Hello/Have/Get requests for encrypted objects on the same endpoint. The legacy `CatalogEvents` request is always refused, so token holders cannot read catalog capabilities. `crow sync` is nest-scoped only and does not fall back to the legacy cluster token.

Acceptance criteria: ✅ two devices can join the same nest without copying a raw shared cluster
token (`two_devices_share_a_nest_without_cluster_token` integration test); catalog events show who
signed them; a non-member without a valid grant is rejected by the nest-scoped handshake.
Legacy token holders can fetch encrypted objects by hash but not catalog events, and
remote catalog changes must be signed by a nest member.

### Phase 4 — metadata-first sync

Make `sync` mean "converge this nest" instead of "download everything from that peer."

1. **Split catalog sync from object sync — shipped.** Pull and merge catalog events without automatically fetching every manifest and share.
2. **No-arg sync — shipped.** `crow sync` syncs the active nest with all visible trusted devices from the local peer snapshot written by `crow serve` on this device. `crow sync <device>` targets a snapshot entry; `crow sync IP:port` needs no snapshot.
3. **Object availability index.** Track which devices claim to hold which manifests/shares, when that claim was last seen, and whether it was verified.
4. **Lazy object fetch — shipped.** `get`, `cat`, `grep`, and `get-dir` attempt to fetch missing objects from visible trusted devices when local reconstruction fails.
5. **Bounded sync modes — started.** Default sync is metadata-only; `--full` explicitly makes cataloged files locally reconstructable. Path-scoped sync is still pending.
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
8. **Authenticated server identities.** Bind server certificates or proofs to known device identities; current self-signed, unpinned certificates do not authenticate the server as a trusted device.

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

- [Apache License, Version 2.0](../LICENSE-APACHE)
- [MIT License](../LICENSE-MIT)

at your option.
