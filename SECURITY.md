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
- Nest-scoped requests require membership and a signed fresh challenge bound to
  the QUIC TLS session. The catalog is served only to authenticated members.
  `crow serve` also accepts the legacy cluster token, which authorizes fetching
  encrypted objects by hash only. v3 peers reject older protocol versions.
- Directory exports use a directory-scoped filesystem API and create-new files
  to prevent writing through escaping symlinks or overwriting existing files.
- Unix pin/catalog directories are owner-only. New identity and pin files use
  private temporary files before atomic publication.

## Limits and deployment boundaries

- **Cluster token:** lets a holder fetch encrypted manifests and chunks by hash
  from whichever nest that home serves. It does not grant catalog access, and
  decrypting anything still requires a read capability. A holder who already has
  hashes can download ciphertext and learn object sizes. `crow setup` prints the
  token; keep setup output out of screenshots and logs.
- **Catalog authorization:** every catalog change received from a peer must be
  signed by a current member of the nest, and a whole batch is rejected, without
  writing anything, if any event fails. Members can still make any change,
  including removing or moving paths. A revoked member's later events are rejected
  by their signer-supplied `created_at`, which a revoked device can backdate, so
  revocation is not a security boundary. A peer you sync from, including an
  impersonated server, can withhold events or block a sync with a bad batch, but
  cannot inject changes without a member's key.
- **Server identity:** clients accept self-signed certificates without pinning
  them to a known device. TLS handshake signatures are verified, and nest proofs
  are session-bound, but this does not provide mutual device authentication.
  An impostor server can observe requests, metadata, and legacy shared tokens.
  Use nest mode on a trusted LAN; do not expose the daemon to the public internet.
- **Metadata and secrets at rest:** catalog events (`events.jsonl`) and pin JSON
  contain plaintext paths/names and read capabilities. Only file contents and
  manifests are encrypted. Identity keys and legacy tokens are stored locally,
  not in an OS keychain. Protect the whole Crow home with OS account permissions and disk
  encryption. On Windows, Crow applies no permission restrictions to identity,
  token, pin, or catalog files. Processes running as your user can access these
  secrets.
- **Revocation:** there is currently no CLI command to remove a device from a
  nest. `MemberRevoked` exists in the catalog format and library, but there is no
  supported end-user revocation workflow. Anything a device has copied cannot
  be recalled.
- **Availability:** Crow has no automatic replication guarantee or global service
  resource budget. Whole-file reads and reconstruction use memory proportional to
  file size. An authenticated peer can supply large data or metadata. Network
  frame and stream limits do not make this an internet-hardened service.
- **Concurrency and durability:** individual object writes are atomic and identity
  initialization has a single winner. Multi-command catalog/nest transactions
  are not serialized across processes, and power-loss durability is not guaranteed.
  Run one writer per home and retain independent original files.
- **Privacy:** mDNS advertises device names and addresses while serving. Without
  a configured name, the OS hostname is advertised by default (setup saves a
  sanitized hostname). Set `crow setup --name NAME` or `crow serve --name NAME`
  to choose the advertised name. Peers and network observers may see timing,
  sizes, and connection metadata. Crow is not
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
