# Security

Crow is alpha software. Keep independent backups of important data.

## Reporting

Please do not open public issues for vulnerabilities. Email the maintainer or use GitHub private vulnerability reporting if enabled on the repository.

## Model

- `crow1...` capabilities are bearer tokens. Anyone with a cap can decrypt the referenced file or directory snapshot if they can fetch enough encrypted shares.
- The personal-cluster token authorizes LAN fetches. Treat it like a password shared only among devices you own.
- mDNS discovery is not trusted for authorization; it only helps find peer addresses.
