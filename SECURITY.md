# Security

Crow is experimental alpha storage software. Keep independent backups and use a
trusted LAN. This project has not received an independent cryptographic audit.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/oliverrowebardeen/crow/security/advisories/new)
with the affected commit/version, a minimal reproduction, expected and actual
behavior, and potential impact. Do not include real private keys, capabilities,
or personal files. Please avoid public issues for undisclosed vulnerabilities.

Only the current development branch is maintained; no long-term security support
or response-time guarantee is offered yet.

## What the design protects

- File contents and manifests are encrypted before storage or transfer.
- Capabilities (`crow1…`) are bearer decryption secrets. Possession of enough
  encrypted shares alone is insufficient to decrypt a file.
- Signed manifests identify a creator; a signature does not establish trust.
- Nest requests require membership and a signed fresh challenge bound to the
  QUIC TLS session. v3 peers reject older protocol versions.
- Directory exports use a directory-scoped filesystem API and create-new files
  to prevent writing through escaping symlinks or overwriting existing files.
- Unix pin/catalog directories are owner-only. New identity and pin files use
  private temporary files before atomic publication.

## Limits and deployment boundaries

- **Server identity:** clients accept self-signed certificates without pinning
  them to a known device. TLS handshake signatures are verified, and nest proofs
  are session-bound, but this does not provide mutual device authentication.
  An impostor server can observe requests, metadata, and legacy shared tokens.
  Use nest mode on a trusted LAN; do not expose the daemon to the public internet.
- **Metadata and secrets at rest:** the local catalog contains paths and read
  capabilities. Identity keys and legacy tokens are stored locally, not in an OS
  keychain. Protect the whole Crow home with your OS account permissions and disk
  encryption. Windows ACL hardening has not been verified. Processes running as
  your user can access these secrets.
- **Revocation:** membership checks restrict future requests; they cannot revoke
  capabilities, keys, or plaintext someone has already copied.
- **Availability:** Crow has no automatic replication guarantee or global service
  resource budget. Whole-file reads and reconstruction use memory proportional to
  file size. An authenticated peer can supply large data or metadata. Network
  frame and stream limits do not make this an internet-hardened service.
- **Concurrency and durability:** individual object writes are atomic and identity
  initialization has a single winner. Multi-command catalog/nest transactions
  are not serialized across processes, and power-loss durability is not guaranteed.
  Run one writer per home and retain independent original files.
- **Privacy:** mDNS advertises device names and addresses while serving. Peers and
  network observers may see timing, sizes, and connection metadata. Crow is not
  an anonymity system.

## Reproduce automated scans

```sh
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --deny warnings
gitleaks git . --log-opts="--all" --redact
```

Use a full-history clone. The repository's Gitleaks configuration extends the
standard rules to recognize Crow capabilities and serialized identity keys.
Never paste an unredacted scan report into a public issue.

Passing scans is evidence about these checks, not proof that all vulnerabilities
are absent. Review screenshots, issue attachments, releases, and previously
uploaded artifacts separately before publishing them.
