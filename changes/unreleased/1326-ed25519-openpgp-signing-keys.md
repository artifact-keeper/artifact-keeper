---
section: Added
issues: [#1326]
---
- **OpenPGP signing keys can now be Ed25519: `key_type = gpg` with `algorithm = ed25519`** (#1326). `POST /api/v1/signing/keys` used to generate RSA for every OpenPGP key. An Ed25519 key is generated as a v4 EdDSA key, the form `gpg --quick-gen-key ... ed25519` produces and that apt/gpgv/sqv on Debian bookworm and trixie and Ubuntu noble verify. It signs InRelease, Release.gpg and repomd.xml.asc with SHA-512, and its fingerprint is the usual 40-hex-digit v4 fingerprint. RSA OpenPGP keys still sign with SHA-256 as before. The web UI's key-type select lives in artifact-keeper-web.
