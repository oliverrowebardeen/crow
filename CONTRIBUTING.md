# Contributing

Crow is experimental storage software. Keep changes focused and include regression
tests for behavior changes, particularly destructive operations, authentication,
and storage recovery.

## Setup and checks

Install Rust 1.88+ with Clippy and rustfmt, a C compiler, and CMake. Clone the
repository and run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo run --locked -p crow --example roundtrip
```

Tests need temporary filesystem access and local UDP loopback sockets. They do
not call model providers or require credentials. Keep `Cargo.lock` committed and
use `--locked` for repeatable installation and CI.

For a dependency change, also run `cargo audit --deny warnings`. See
[SECURITY.md](SECURITY.md) for the scanner installation and full-history secret
scan. CI checks formatting, strict Clippy, macOS/Linux tests, the minimum Rust
version, secrets, and published dependency advisories.

## Pull requests

Describe the concrete problem, resulting behavior, compatibility changes, and
checks you ran. Use temporary Crow homes in CLI tests and keep real capabilities,
identity files, tokens, personal paths, and user data out of fixtures and logs.

Behavior that can delete data must retain confirmation and reconstruction/retention
checks. Do not change cryptographic formats or protocol versions without explicit
compatibility notes. Wire v3 requires every participating device to upgrade.

Please report vulnerabilities privately using [SECURITY.md](SECURITY.md).
Contributions are provided under the repository's existing MIT OR Apache-2.0 terms.
