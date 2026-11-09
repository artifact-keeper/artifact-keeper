# FIPS 140-3 mode

Artifact Keeper can run every security function on a single FIPS 140-3
validated cryptographic module and refuse configurations that fall outside
the approved set. This is **opt-in**: the default build and the default
`FIPS_MODE=off` behave exactly as before, write no new storage formats, and
can be downgraded freely.

This document is the one reference for the design (for contributors) and the
operating procedure (for deployments). Issue tracker: #5577 (epic).

## What "FIPS mode" means here

* **One provider.** The backend links exactly one cryptographic library,
  AWS-LC, through `aws-lc-rs`. There is no `ring`, no OpenSSL and no
  `native-tls` anywhere in the dependency graph, and
  `scripts/ci/check-crypto-provider.sh` fails CI if one comes back. Every TLS
  client (outbound HTTP, Postgres, Redis, LDAP, SMTP, OpenSearch) is rustls on
  that provider, using the operating system trust store plus any configured
  private CA.
* **One facade.** All security cryptography goes through `backend/src/crypto/`
  (digest, hmac, aead, kdf, password, rng, signature, token). Clippy
  `disallowed-methods` / `disallowed-types` in `.clippy.toml` refuse direct use
  of the RustCrypto hashers, `bcrypt`, `ed25519-dalek`, `rsa` and the `rand`
  entropy sources outside it. A legitimate non-security use carries
  `#[allow(clippy::disallowed_methods)] // NON-SECURITY: <reason>`.
* **A validated build.** `cargo build --features fips` links the AWS-LC FIPS
  module (`aws-lc-fips-sys`) instead of AWS-LC. The `-fips` image and binary
  tags are that build. `cmake` and Go are needed to compile it.
* **A gate.** `FIPS_MODE` decides what the binary does with the policy checks
  below.

| `FIPS_MODE` | checks run | violations            | storage formats written | build required |
|-------------|------------|-----------------------|-------------------------|----------------|
| `off`       | no         | –                     | legacy (today's)        | any            |
| `warn`      | yes        | logged, in `/health`  | legacy                  | any            |
| `strict`    | yes        | refuse to start       | module-backed (v2)      | `fips`         |

Use `warn` on an existing deployment first: it tells you everything `strict`
would refuse without changing anything.

## Policy checks (`strict` refuses, `warn` reports)

| code                          | what                                                        | fix |
|-------------------------------|-------------------------------------------------------------|-----|
| `non-fips-build`              | binary not built with `--features fips`                     | run the `-fips` tag |
| `module-self-test`            | AWS-LC FIPS module failed its power-on self-tests           | reinstall the release artifact |
| `rustls-provider`             | the installed rustls provider is not the FIPS one           | run the `-fips` tag |
| `jwt-secret-length`           | `JWT_SECRET` shorter than 32 bytes                          | regenerate (`openssl rand -base64 48`) |
| `smtp-tls-skip-verify`        | `SMTP_TLS_SKIP_VERIFY=true`                                 | use `SMTP_TLS_CA_CERT` |
| `ldap-insecure-tls`           | `LDAP_INSECURE_TLS=true`                                    | use `LDAP_CA_CERT_PATH` |
| `data-encryption-key-missing` | no `DATA_ENCRYPTION_KEY`                                    | set it, then run `reencrypt-secrets` |
| `oidc-legacy-rsa-keys`        | an SSO provider allows RSA keys under 2048 bits             | disable `allow_legacy_rsa_keys`, rotate the IdP key |
| `policy-check-failed`         | the database could not be inspected                         | check connectivity and migrations |

At run time in `strict` mode the backend also refuses SAML responses signed
with SHA-1 or anything outside SHA-2 RSA / RSA-PSS / ECDSA (#5584), and SHA-1
repository signature generation (#5586).

## Storage formats

Every build reads both columns of this table. Only `strict` writes the right
column, so an upgrade followed by a downgrade never produces a row the older
binary cannot read.

| data                      | legacy (default)                    | module-backed (`strict`)                                   | migrates |
|---------------------------|-------------------------------------|------------------------------------------------------------|----------|
| user passwords            | bcrypt (`$2b$…`)                    | `$pbkdf2-sha512$i=N$salt$hash` (PBKDF2-HMAC-SHA512, 210k)   | on next login (`FIPS_LEGACY_HASH_MIGRATION`, default on) |
| API tokens, device codes  | bcrypt                              | `$hmac-sha256$<tag>` under a KBKDF subkey of the secret    | on first use |
| TOTP backup codes         | bcrypt                              | PBKDF2 (same as passwords)                                 | regenerate |
| TOTP seeds                | base32 plaintext                    | `enc:<base64 0x02‖nonce‖ct>` under the `totp-seed` subkey   | re-enrol |
| stored secrets (SSO, LDAP, upstream, migration, signing keys) | `nonce‖ct` under HMAC(JWT_SECRET, ctx) | `0x02‖nonce‖ct` under the `credential-aead` subkey of `DATA_ENCRYPTION_KEY` | `reencrypt-secrets` |

`$pbkdf2-sha256$` hashes produced by other components of a deployment are
verified too.

### Key hierarchy

`DATA_ENCRYPTION_KEY` (32 random bytes, base64 or hex; `_FILE` variant
supported) is the root. Subkeys are derived with SP 800-108 KBKDF (counter
mode, HMAC-SHA256): `credential-aead`, `totp-seed`, `token-hmac`. Without it,
the legacy derivation from `JWT_SECRET` stays in use and `strict` refuses to
start.

### `reencrypt-secrets`

```
DATA_ENCRYPTION_KEY=… artifact-keeper reencrypt-secrets
```

Rewrites every legacy ciphertext (`oidc_configs`, `ldap_configs`,
`remote_instances`, `signing_keys`, `source_connections`, upstream
credentials) under the data key. Idempotent and resumable: rows already in v2
form are skipped, each row is its own statement, and a row that cannot be
decrypted is logged by table and id and left untouched. Run it before
switching to `strict`; never automatic. A downgrade after running it is
unsupported (the older binary cannot read v2 rows), so take a database
backup first.

## Operating a FIPS deployment

1. **Host.** The product uses a validated module; the deployment is FIPS only
   when the host and the bundled services (database, search, ingress,
   scanners) also run in FIPS mode. On RHEL-family hosts: `fips-mode-setup
   --enable` and a reboot.
2. **Image.** Use the `<version>-fips` tag. `/health` shows
   `crypto.provider = "AWS-LC FIPS"`, `crypto.fips_build = true`,
   `crypto.fips_module_active = true`. The image labels name the module
   version (`AWS_LC_FIPS_SYS_VERSION`).
3. **Settings.** `FIPS_MODE=warn` first; fix every violation listed in
   `/health.crypto.violations`; set `DATA_ENCRYPTION_KEY`; run
   `reencrypt-secrets`; then `FIPS_MODE=strict`.
4. **Database TLS.** `PGSSLMODE=verify-full` and `PGSSLROOTCERT=<ca>` (or
   `sslrootcert` in `DATABASE_URL`); SCRAM-SHA-256 authentication.
5. **Watch.** `ak_fips_mode` (0/1/2), `ak_crypto_legacy_verifications_total`
   (bcrypt matches still happening) and `ak_crypto_hash_migrations_total`
   (rows migrated) in Prometheus.

## Non-security algorithm inventory

These are interoperability checksums defined by the package formats, not
security functions, and FIPS 140-3 permits them as such. No security decision
in the backend depends on them; integrity gates use SHA-2 through the facade.

| algorithm | where                                                                 |
|-----------|-----------------------------------------------------------------------|
| MD5       | Maven `.md5`, npm legacy `dist.shasum` neighbours, conda `md5`, Composer, PyPI legacy, Debian `MD5Sum`, Alpine index |
| SHA-1     | Maven `.sha1`, npm `shasum`, git object ids, apk `.SIGN.RSA.sha1`, Debian `SHA1`, Conan, CocoaPods |
| BLAKE2    | `blake2b` content fields some formats publish alongside SHA-2        |

One SHA-256 use stays on the RustCrypto implementation: the sigstore bundle
verifier (`sigstore-rs`) consumes its own hasher type for the subject digest.
It is verification-only and marked with an `allow` in
`backend/src/services/curation/attestation_verify*.rs`.

## Testing

| layer | what                                                                 | when |
|-------|----------------------------------------------------------------------|------|
| L0    | `scripts/ci/check-crypto-provider.sh`; clippy disallowed lists; module manifest vs lockfile | every PR |
| L1    | facade vectors (FIPS 180-4, RFC 4231, SP 800-38D, RFC 6070/7914, RFC 5869, SP 800-108, RFC 8032); one test per gate refusal; dual-format readers | every PR |
| L2    | the unit suite on the default build and on `--features fips` with `FIPS_MODE=strict` | every PR |
| L3    | upgrade / rollback: seeded database through off → warn → strict → downgrade | release candidates |
| L4    | `-fips` image in strict mode against native clients, private CA and TLS-inspecting proxy | release candidates |

Locally:

```
cargo nextest run -p artifact-keeper-backend --lib -E 'test(/^(crypto|fips)::/)'
cargo build --features fips && FIPS_MODE=strict ./target/debug/artifact-keeper
./scripts/ci/check-crypto-provider.sh --features fips
```
