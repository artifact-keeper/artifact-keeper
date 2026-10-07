---
section: Changed
issues: [#1326]
---
- **`POST /api/v1/signing/keys` now rejects `key_type = ed25519` (and `key_type = rsa` with `algorithm = ed25519`) with 400** (#1326). `key_type = ed25519` never produced an Ed25519 key: generation fell through to RSA and stored an RSA keypair labelled `ed25519`, which could not sign Debian or RPM metadata. The 400 points at the real option, `key_type = gpg` with `algorithm = ed25519`. Existing `ed25519` rows keep loading, and rotating one now produces the `rsa` key it really holds.
