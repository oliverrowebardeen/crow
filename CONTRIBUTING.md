# Contributing

Crow is experimental storage software. Keep changes focused and include regression
tests for behavior changes, particularly destructive operations, authentication,
and storage recovery.

Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Setup and checks

Install Rust 1.88+ with Clippy and rustfmt and a C compiler. Some targets also
need tools such as NASM; the locked non-FIPS `aws-lc-rs` build does not require
CMake. See the [aws-lc-rs build requirements](https://aws.github.io/aws-lc-rs/requirements/).
Clone the repository and run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo run --locked -p crow --example roundtrip
```

Tests need temporary filesystem access and local UDP loopback sockets, including
IPv4 multicast on loopback. Discovery tests use `Discovery::start_loopback` and
do not depend on a physical LAN interface. Keep `Cargo.lock` committed and
use `--locked` for repeatable installation and CI.

For a dependency change, also run `cargo audit --deny warnings`. See
[SECURITY.md](SECURITY.md) for the scanner installation and full-history secret
scan. CI checks formatting, strict Clippy, macOS/Linux tests, the minimum Rust
version, secrets, and published dependency advisories.

## Pull requests

Describe the concrete problem, resulting behavior, compatibility changes, and
checks you ran. Use temporary Crow homes in CLI tests and keep real capabilities,
identity files, tokens, personal paths, and user data out of fixtures and logs.

Destructive commands must retain `--dry-run` and live-set retention logic.
Bulk import/export must retain their confirmation prompts (`put-dir` before
import; `get-dir` when the destination is non-empty), with `--yes` to skip them.
Do not change cryptographic formats or protocol versions without explicit
compatibility notes. Wire v3 requires every participating device to upgrade.

Please report vulnerabilities privately using [SECURITY.md](SECURITY.md).
Contributions are provided under the repository's existing MIT OR Apache-2.0 terms.
