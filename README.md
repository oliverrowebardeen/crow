# Crow

Encrypted, content-addressed file storage in Rust, with capabilities, erasure coding,
and peer-to-peer sync on a trusted LAN.

Crow turns a file into encrypted shares and a small **read capability**. The
capability contains the manifest address and decryption key. With it and enough
shares from each stripe, another device can reconstruct the file. The default
layout needs any **3 of 5 shares per stripe**.

**Status: experimental alpha.** Keep independent backups. Crow has no independent
cryptographic audit, and its network protocol is intended for trusted LANs.
[Security model and limitations](SECURITY.md).

## Why this project

Crow combines a reusable storage library, a CLI, and a QUIC transport:

- **Encrypted storage:** AES-256-GCM, BLAKE3 content addresses, Reed–Solomon recovery.
- **Portable references:** Bech32m read capabilities; Ed25519 signatures record creator provenance.
- **Local catalog:** file and directory paths backed by signed events and immutable snapshots;
  changes received from peers must be signed by a current nest member.
- **Device sharing:** recipient-bound invites, per-nest membership, manual metadata or full sync.
- **Storage management:** pins and garbage collection (with `--dry-run`).

It does not yet provide automatic background replication, a mounted filesystem,
or an internet storage service. The current CLI loads whole files into memory.

## Install

Requires **Rust 1.88+** and a C compiler for the TLS dependency. Some targets also
need tools such as NASM; the locked non-FIPS `aws-lc-rs` build does not require
CMake. See the [aws-lc-rs build requirements](https://aws.github.io/aws-lc-rs/requirements/).
Crow is not published to crates.io. Install directly from GitHub:

```sh
cargo install --locked --git https://github.com/oliverrowebardeen/crow --bin crow
```

Or install from a local checkout:

```sh
git clone https://github.com/oliverrowebardeen/crow.git
cd crow
cargo install --locked --path crates/crow-cli
```

## A one-minute local demo

This stores and restores a small file in a fresh temporary home. No account,
network server, or API key is needed after installation.

```sh
demo_dir=$(mktemp -d)
export CROW_HOME="$demo_dir/store"
printf 'hello from Crow\n' > "$demo_dir/input.txt"
crow setup --name demo
crow mkdir /docs
crow put "$demo_dir/input.txt" /docs/hello.txt
crow ls /docs
crow get /docs/hello.txt "$demo_dir/restored.txt"
cmp "$demo_dir/input.txt" "$demo_dir/restored.txt"
```

`cmp` exits successfully when reconstruction matches. Your files remain in
`$demo_dir`. `CROW_HOME` (or the top-level `crow --home PATH <command>`) selects the store.
`crow cap /docs/hello.txt` prints a bearer capability: share it only
with intended readers, and keep it out of public screenshots and logs.
`crow setup` also prints the cluster token. It lets a holder download your encrypted
objects by hash (not the catalog or any capability), so keep it private too.
Keep setup output out of public screenshots and logs too.

For two-device setup, directory snapshots, pinning, and recovery, see the
[CLI and library guide](docs/GUIDE.md). The
[library example](crates/crow/examples/roundtrip.rs) demonstrates reconstruction.

## Architecture

```text
file → split into chunks → encrypt → add recovery shares → content-addressed store
                                                              ↑
read capability → encrypted, signed manifest → hashes for each share
```

| Crate | Responsibility |
| --- | --- |
| `crow` | Encryption, capabilities, manifests, catalogs, stores, and recovery |
| `crow-net` | QUIC requests, nest authentication, and mDNS discovery |
| `crow-cli` | Local commands, imports/exports, and sync |

Nest authentication signs a fresh challenge plus a TLS session binding. This
prevents moving a valid signature onto a different connection. Protocol **v3**
requires all peers to upgrade together; there is no insecure fallback to v2.
Self-signed server certificates are still not bound to a known device identity.
Use only a trusted LAN. `crow serve` also accepts the legacy shared token, which
only authorizes fetching encrypted objects by hash; the catalog is served only to
authenticated nest members. Catalog changes from peers must be signed by a
current nest member; a peer you sync from can still withhold or delay changes.

## Develop

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo run --locked -p crow --example roundtrip
```

Tests use temporary stores and local loopback connections. They do not need live
accounts or paid services. Network tests need permission to bind local UDP ports.
See [CONTRIBUTING.md](CONTRIBUTING.md) for dependency and secret scanning.
Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Compatibility and roadmap

Pre-1.0 file formats, CLI output, and wire protocols may change. Keep original
files and export data before upgrading. Wire protocol v3 is incompatible with
earlier builds; stored formats are unchanged. macOS and Linux are CI targets;
Windows support is provisional until its filesystem behavior is verified.

Next priorities are automatic replication and health reporting, authenticated
server identities, bounded streaming for large files, and broader platform tests.
The [detailed design and roadmap](docs/GUIDE.md#roadmap) separates shipped work
from planned features.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
