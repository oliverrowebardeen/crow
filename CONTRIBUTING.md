# Contributing

Crow is early-stage storage software. Small, focused changes are easiest to review.

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Please include tests for behavior changes. For CLI changes, prefer an end-to-end temp-home smoke test in addition to unit tests when practical.

## Pull Requests

- Keep commits focused.
- Explain user-visible behavior changes in the PR description.
- Do not commit generated OS/editor metadata such as `.DS_Store`.
- Avoid destructive storage behavior unless it is gated by explicit confirmation and documented safety checks.
