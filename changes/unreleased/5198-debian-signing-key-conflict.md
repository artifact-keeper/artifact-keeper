---
section: Fixed
issues: [#5198]
---
- **A Debian repository whose signing key cannot produce OpenPGP now answers 409 instead of failing or serving the wrong key** (#5198). With a `key_type=rsa` key, the default, `InRelease` and `Release.gpg` returned 500 and logged an ERROR on every anonymous request, and `gpg-key.asc` returned 200 with an X.509 PEM labelled `application/pgp-keys`. All of them now return 409 with a WARN and a message naming `key_type='gpg'`, as RPM does. This also covers a Virtual repository that signs its own `Release`; a Remote or Virtual repository serving an upstream's release files is unchanged.

  `POST /api/v1/signing/repositories/{id}/config` now returns 400 when it is asked to bind such a key to a Debian, RPM or pacman repository, or to turn metadata signing on with one already bound, and 404 for an unknown key. Key creation already refused this for a repository-scoped key, but a global key or an older one could still be bound. An existing binding keeps working as before until it is changed: signing can still be turned off, and `SIGNING_AUTO_MIGRATE_LEGACY_KEYS=true` still replaces the key.
