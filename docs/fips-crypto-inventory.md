# Cryptographic inventory (FIPS 140-3 build)

This lists every place the backend uses cryptography, what it is for, which
algorithm and implementation run it, and what the opt-in `fips` build does
with it. It exists for deployments that require FIPS 140-3 validated
cryptography; how to build and run that mode is in [fips.md](fips.md).

The `fips` cargo feature (`cargo build --no-default-features --features fips`)
links the AWS-LC FIPS module (`aws-lc-fips-sys`) under every `aws-lc-rs` user
in the dependency graph, installs `rustls::crypto::default_fips_provider()` as
the process-wide rustls provider at startup and refuses to start unless it
reports FIPS, and drops `ring` from the build. The first PR covers TLS and
password/token hashing. Everything else below is listed with the plan for a
follow-up.

## How to read this

Two separate questions decide whether a use is acceptable in FIPS mode:

1. **Is the algorithm approved?** For example SHA-256 (FIPS 180-4), AES-GCM
   (FIPS 197 with SP 800-38D), HMAC (FIPS 198-1), RSA and ECDSA and EdDSA
   signatures (FIPS 186-5), PBKDF2 (SP 800-132), and DRBGs (SP 800-90A).
   MD5, BLAKE2, RIPEMD-160, bcrypt, Argon2 and ChaCha-based RNGs are not.
   SHA-1 is approved only for non-signature uses such as HMAC; SP 800-131A
   Rev. 2 disallows it for generating digital signatures.
2. **Does it run inside the validated module boundary?** An approved algorithm
   only counts if the validated module computes it. The RustCrypto crates
   (`sha2`, `hmac`, `aes-gcm`, `rsa`, `ed25519-dalek`, `p256`, ...) implement
   approved algorithms, but they are not validated modules. In this build the
   only validated module is AWS-LC, reached through `aws-lc-rs` and the
   rustls FIPS provider.

"Security-relevant" means a wrong or forged value would let someone
authenticate, read or alter data they should not, or get untrusted content
accepted. Checksums that a package format requires but that only detect
corruption are not security-relevant, provided trust comes from somewhere
else (a SHA-256 digest computed by the server, or a signature).

Paths are relative to `backend/src`. Function names are the stable reference;
line numbers are not given because they move.

## Validated module version and certificate

**What the `fips` build links today.** `aws-lc-rs` 1.18.1 with
`aws-lc-fips-sys` 0.14.2, which builds the module version "AWS-LC FIPS 4.2.0"
(the AWS-LC-FIPS 4.x line). According to `crypto/fipsmodule/FIPS.md` in
AWS-LC, AWS-LC-FIPS v4.0 (static and dynamic) has completed lab testing and is
on the CMVP Modules In Process list. It does not have a certificate number yet.

**The newest line with a FIPS 140-3 certificate is AWS-LC-FIPS v3.1:**

| Certificate | Module | Validated | Sunset |
|---|---|---|---|
| CMVP #5314 | AWS-LC 3 Cryptographic Module (static) | 2026-06-05 | 2031-06-04 |
| CMVP #5298 | AWS-LC 3 Cryptographic Module (dynamic) | 2026-06-03 | 2031-06-02 |

Both are Security Level 1, with the caveat "when operated in approved mode ...
configured as specified in Section 11.1 of the Security Policy".
`aws-lc-fips-sys` links the module statically, so #5314 is the one that
applies. Older certificates: v2.0 static #4816 and dynamic #5429; v1.0 #4631.

**Crate version to module version.** Each `aws-lc-fips-sys` release reports
its module version in its `service_indicator` test:

| `aws-lc-fips-sys` | Module version |
|---|---|
| 0.13.0 to 0.13.10 | AWS-LC FIPS 3.0.0 |
| 0.13.11 | AWS-LC FIPS 3.1.0 (the certified version) |
| 0.13.12 | AWS-LC FIPS 3.2.0 |
| 0.13.13 | AWS-LC FIPS 3.3.0 |
| 0.13.15, 0.13.16 | AWS-LC FIPS 3.4.0 |
| 0.13.17 | AWS-LC FIPS 3.6.0 |
| 0.14.2 | AWS-LC FIPS 4.2.0 |

`aws-lc-rs` 1.17.1 and earlier accept `aws-lc-fips-sys` `^0.13.1` (1.17.2 is
yanked; 1.17.3 needs `^0.13.16` and 1.17.4 needs `^0.13.17`). `aws-lc-rs` 1.18
and later need `^0.14`.

**Why this build does not pin to 3.1.0.** The current lockfile has rustls
0.23.46 and rustls-webpki 0.103.16, which require `aws-lc-rs` `^1.18`. Pinning
`aws-lc-fips-sys = "=0.13.11"` only resolves by downgrading the lockfile to
`aws-lc-rs` 1.17.1, `aws-lc-sys` 0.42.0, rustls 0.23.43 and rustls-webpki
0.103.13. `Cargo.lock` is shared, so that downgrade also changes the default
build. `cargo audit` on that lockfile reports:

- RUSTSEC-2026-0285, RUSTSEC-2026-0346, RUSTSEC-2026-0348 and
  RUSTSEC-2026-0349 (rustls)
- RUSTSEC-2026-0382 (rustls-webpki)
- RUSTSEC-2026-0042 and RUSTSEC-2026-0043 (`aws-lc-fips-sys` 0.13.11 itself)

The pin therefore conflicts both with the rustls version and with security
fixes. Whether to make that trade-off is left to operators and maintainers.
The options are:

1. **Wait for the 4.x certificate.** No code change; the build already links
   4.2.0.
2. **Keep a separate lockfile for the FIPS image.** It pins the 3.1.0 chain
   and is used only by the FIPS image build. This accepts the older
   rustls/webpki and the advisories above.
3. **Pin across the workspace.** Rejected: it changes the default build and
   brings back the advisories.

To check which module a build links:

```sh
cargo tree -p artifact-keeper-backend -e normal --no-default-features --features fips -i aws-lc-fips-sys
```

## TLS transport

Inbound TLS is not terminated by the backend: `api/serve.rs` serves plain
HTTP and gRPC. The ingress or load balancer in front of it must provide
FIPS-validated TLS itself.

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| Process-wide rustls provider | TLS 1.2/1.3 suites of the provider | `main.rs::run_server` installs `ring` (default) or `fips::install_fips_provider` (`fips`) | Yes: every rustls connection uses it | FIPS build: Yes (AWS-LC FIPS provider; `CryptoProvider::fips()` is checked) | Done in this PR. Startup fails if the module or the installed provider does not report FIPS. |
| Postgres TLS | TLS via rustls | sqlx `tls-rustls-ring-webpki` (default) / `tls-rustls-aws-lc-rs` (`fips`) | Yes | FIPS build: Yes | Done in this PR. |
| Postgres password authentication | SCRAM-SHA-256 (HMAC-SHA-256, SHA-256, PBKDF2-style `Hi()`); MD5 password auth if the server asks for it | sqlx-postgres `connection/sasl.rs` (RustCrypto `hmac`, `sha2`), `connection/establish.rs` (`md-5`) | Yes: proves the DB password | SCRAM: approved primitives, outside the module. MD5 auth: No | Operators must set `password_encryption = scram-sha-256` and `scram-sha-256` in `pg_hba.conf`, and run it over TLS (or use client certificates). Follow-up: refuse `Md5Password` in the FIPS build, if sqlx can be configured to. SCRAM stays outside the module until sqlx offers a hook. |
| Outbound HTTP clients we build (proxy upstreams, webhooks, SSO/IdP, internal services) | TLS via rustls | `services/http_client.rs` builders over `reqwest` | Yes | FIPS build: Yes | Done in this PR (rustls on the FIPS provider; no native-tls in the FIPS build). |
| S3 / GCS / Azure object storage | TLS via rustls | `object_store` (`storage/s3.rs`), `reqwest` (`storage/gcs.rs`, `storage/azure.rs`) | Yes | FIPS build: Yes | Done in this PR. |
| OpenSearch | TLS | `opensearch` crate, `native-tls` (default) / `rustls-tls` (`fips`) | Yes | FIPS build: Yes | Done in this PR. |
| Sigstore trust-root fetch, TUF | TLS via rustls | `sigstore`, `tough` | Yes | FIPS build: Yes | Done in this PR. |
| OTLP HTTP exporter | TLS via rustls | `opentelemetry-otlp` (blocking `reqwest`) | Low: telemetry | FIPS build: Yes | Done in this PR. |
| OTLP gRPC exporter | none | `opentelemetry-otlp` `grpc-tonic`; `tonic` is built without a TLS feature | Low: telemetry, sent in plaintext | n/a | Point it at a local collector, or use the HTTP exporter for remote endpoints. |
| Conda (`rattler`) networking | TLS via rustls | `rattler_networking` through `reqwest` | Yes | FIPS build: Yes | Done in this PR. |
| Redis (`rediss://`) | TLS via rustls | `redis` `tokio-rustls-comp`, process default provider | Yes: cache contents | FIPS build: Yes | Done in this PR (uses the installed process default). |
| LDAP (LDAPS / StartTLS) | TLS | `ldap3`, `services/ldap_service.rs` | Yes: carries bind credentials | Default build: OpenSSL via native-tls | FIPS build: rustls on the FIPS provider (see [fips.md](fips.md)). |
| SMTP (STARTTLS / implicit TLS) | TLS | `lettre`, `services/smtp_service.rs` | Yes: SMTP credentials and mail content | Default build: OpenSSL via native-tls | FIPS build: rustls on the FIPS provider (see [fips.md](fips.md)). |
| Plugin source checkout | libgit2, no HTTPS/SSH transport compiled in | `git2` (default features off), `services/wasm_plugin_service.rs::clone_repository` | See plugin signatures below | n/a | No change. Trust comes from the Ed25519 plugin signature, not the transport. |

## Password, token and secret hashing

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| User passwords | bcrypt (default); PBKDF2-HMAC-SHA256 (`fips`) | `services/auth_service.rs::hash_password` / `verify_password`; `services/fips_password.rs` | Yes | bcrypt: No. PBKDF2-HMAC-SHA256: Yes (SP 800-132), in the module (`aws_lc_rs::pbkdf2`) | Done in this PR. New hashes are `$pbkdf2-sha256$i=600000$...` with a 16-byte salt from the module DRBG. A stored bcrypt hash is verified and rehashed on the next successful login, or refused, depending on `FIPS_LEGACY_PASSWORD_HASHES`. |
| API tokens (stored hash) | bcrypt (default); PBKDF2-HMAC-SHA256 (`fips`) | `auth_service.rs::generate_api_token_with_policy`, `validate_api_token` | Yes | As above | Done in this PR, same scheme and legacy policy as passwords. |
| TOTP backup codes (stored hash) | bcrypt (default); PBKDF2-HMAC-SHA256 (`fips`) | `api/handlers/totp.rs::mint_backup_codes`, `find_backup_code_index` | Yes | As above | Done in this PR. |
| Timing pad for unknown users | bcrypt / PBKDF2 dummy hash | `auth_service.rs::dummy_bcrypt_hash` and the `fips` equivalent | Yes: hides whether a user exists | As above | Done in this PR. |
| API token cache key | SHA-256 of the raw token | `auth_service.rs::validate_api_token` (RustCrypto `sha2`) | Yes: in-memory index of a secret | Yes (FIPS 180-4), outside the module | Follow-up: `aws_lc_rs::digest::SHA256`. |
| Device-flow `device_code` / `user_code` | unsalted SHA-256, stored and looked up | `services/device_service.rs::code_digest` | Yes: bearer secrets at rest | Yes, outside the module | Follow-up: `aws_lc_rs::digest`. The codes are 256-bit random (device) and short-lived (user), so an unsalted hash is adequate. |
| MCP namespace / CI access tokens | SHA-256, stored and looked up | `services/mcp_namespaces.rs::token_digest` | Yes | Yes, outside the module | Follow-up: `aws_lc_rs::digest`. |
| LDAP Basic credential cache | HMAC-SHA256 tag over user and password, random per-process key | `services/ldap_basic_auth.rs::credential_tag_with_key`, `hmac_key` | Yes: a cache hit authenticates | Yes (FIPS 198-1), outside the module | Follow-up: `aws_lc_rs::hmac`. |
| Upstream credential cache key | length-prefixed SHA-256 of upstream username and password | `services/proxy_service.rs::credential_digest` | Yes: derived from a secret, kept in memory | Yes, outside the module | Follow-up: `aws_lc_rs::digest`; consider HMAC with a process key. |
| Upstream URL fingerprints (URLs may embed credentials) | truncated SHA-256 | `services/npm_attestation_cache.rs::upstream_hash`, `npm_packument_cache.rs::base_url_hash`, `age_gate_service.rs::upstream_fingerprint` | Low: cache partitioning | Yes, outside the module | Follow-up with the other `sha2` call sites; no behaviour change. |
| Webhook secrets created before encryption at rest | bcrypt (legacy rows only) | `services/webhook_secret_crypto.rs` | Yes | No | No change: such secrets cannot sign and must be rotated already. |
| Password strength estimate | zxcvbn (no cryptography) | `zxcvbn` | No | n/a | No change. |

## Tokens, JWT, sessions, CSRF and SSO state

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| Access, refresh, scan, TOTP-pending, enrolment and registry tokens | JWT HS256 (HMAC-SHA256) keyed by `JWT_SECRET` | `jsonwebtoken` (`aws_lc_rs` backend), `services/auth_service.rs` (`generate_*`, `Validation::new(Algorithm::HS256)`), `grpc/auth_interceptor.rs` | Yes | Yes (FIPS 198-1) | FIPS build: in the module, since `jsonwebtoken` already uses `aws-lc-rs`. No code change. Document a minimum `JWT_SECRET` length of 32 bytes (SP 800-107 key strength). |
| CI OIDC token exchange (GitHub, GitLab, ...) | RS256/384/512, PS256/384/512, ES256/384 via JWKS | `services/ci_oidc_service.rs` (`jsonwebtoken`, `decoding_key_from_jwk`) | Yes | Yes (FIPS 186-5) | FIPS build: in the module. No change. |
| SSO OIDC ID token, keys of 2048 bits or more | RS*, PS*, ES* via JWKS | `api/handlers/sso.rs::verify_id_token_strict` (`jsonwebtoken`) | Yes | Yes | FIPS build: in the module. No change. |
| SSO OIDC ID token, legacy RSA under 2048 bits (opt-in per provider via `allow_legacy_rsa_keys`) | RSA PKCS#1 v1.5 with SHA-256/384/512 | `api/handlers/sso.rs::verify_id_token_with_legacy_rsa` (RustCrypto `rsa`, then `jsonwebtoken` with signature checking disabled) | Yes | No: RSA under 2048 bits is not approved, and the check is outside the module | Follow-up: refuse `allow_legacy_rsa_keys` in the FIPS build (reject at save time and at login). |
| PKCE `code_challenge` | SHA-256 (S256) | `services/auth_config_service.rs::pkce_challenge_s256` | Yes | Yes, outside the module | Follow-up: `aws_lc_rs::digest`. |
| PKCE verifier | 48 bytes from the OS CSPRNG | `auth_config_service.rs::generate_pkce_verifier` (`rand::rngs::SysRng`) | Yes | OS RNG, not a module DRBG | See [Random number generation](#random-number-generation). |
| OIDC `state` / `nonce`, SAML RelayState, SSO exchange codes | UUIDv4 (122 random bits each; exchange codes join two) | `services/oidc_service.rs`, `auth_config_service.rs::create_exchange_code`, `services/saml_service.rs` | Yes | OS RNG (`getrandom`) | See [Random number generation](#random-number-generation). |
| CSRF protection | header and method contract, no tokens | `api/middleware/auth.rs::csrf_guard` | Yes | n/a (no cryptography) | No change. |
| MCP pagination cursors | AES-256-GCM, key = HMAC-SHA256(`jwt_secret`, label) | `formats/mcp.rs::CursorSeal` | Yes: tamper-proof cursors | Yes, outside the module | Follow-up: `aws_lc_rs::aead` and `aws_lc_rs::hmac`. |
| Session and token-family IDs, upload session IDs, OCI upload state tokens, Incus finalize tokens | UUIDv4 | many (`Uuid::new_v4`) | Mixed: some act as bearer capabilities | OS RNG | See [Random number generation](#random-number-generation). |
| Federated email identity | SHA-256 of the OIDC subject, truncated to 64 bits | `services/federated_email.rs::synthetic_email_for_subject` | Low: identity mapping, not authentication | Yes, outside the module | Follow-up with the other `sha2` call sites. |

## Encryption at rest of stored secrets

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| Stored credentials: SSO client secrets, LDAP bind password, upstream auth, remote instance and migration credentials, egress proxy credentials | AES-256-GCM, 96-bit random nonce | `services/encryption.rs::CredentialEncryption` (RustCrypto `aes-gcm`); callers in `auth_config_service.rs`, `upstream_auth.rs`, `remote_instance_service.rs`, `migration_service.rs`, `egress_proxy.rs`, `ldap_env_bootstrap.rs`, `api/handlers/migration.rs` | Yes | Yes (FIPS 197, SP 800-38D), outside the module | Follow-up: `aws_lc_rs::aead::AES_256_GCM`. The ciphertext layout (nonce \|\| ciphertext \|\| tag) stays the same, so stored data needs no migration. |
| Key derivation for the above | single-step KDF: HMAC-SHA256(passphrase, fixed label) | `encryption.rs::derive_key_hkdf` | Yes | Yes (SP 800-108-style single-step KDF; the passphrase must have full key strength), outside the module | Follow-up: `aws_lc_rs::hmac`. Same output, no migration. |
| Legacy key derivation (decrypt-only fallback) | raw SHA-256 of the passphrase used as the key | `encryption.rs::derive_key_legacy` | Yes | Not an approved KDF | Follow-up: disable the fallback in the FIPS build. Before switching, re-encrypt legacy rows with the default build. |
| Signing private keys (RSA PKCS#8 PEM, OpenPGP secret keys) | AES-256-GCM via `CredentialEncryption` | `services/signing_service.rs::load_rsa_private_key`, `load_openpgp_secret_key` | Yes | As above | Same follow-up as stored credentials. |
| Webhook HMAC secrets and the instance Ed25519 webhook key | AES-256-GCM, key from `AK_WEBHOOK_SECRET_KEY` | `services/webhook_secret_crypto.rs`, `services/webhook_signing_keys.rs` | Yes | As above | Same follow-up. |
| Zeroising key material in memory | n/a | `zeroize` | Yes (hygiene) | n/a | No change. |

## Signing

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| RSA repository key generation | RSA 2048 / 4096 | `services/signing_service.rs::generate_rsa_key` (RustCrypto `rsa`, `OsRng`) | Yes | Yes (FIPS 186-5), outside the module | Follow-up: generate with `aws_lc_rs::rsa::KeyPair::generate`; export PKCS#8 as today. |
| OpenPGP key generation (RSA or Ed25519) | RSA 2048/4096, EdDSA (Ed25519) | `signing_service.rs::generate_openpgp_key_blocking` (`pgp` 0.14) | Yes | RSA: Yes. Ed25519: Yes (FIPS 186-5 EdDSA). Outside the module either way | Follow-up: `pgp` has no pluggable backend. Options: accept it as a documented non-validated component, or have the FIPS build generate keys in aws-lc-rs and import them into `pgp`. |
| Debian `Release` / `InRelease`, RPM `repomd.xml.asc`, Pacman database, Terraform `SHA256SUMS`, trust-attestation challenge | OpenPGP signatures, SHA-256 (RSA) or SHA-512 (EdDSA) | `signing_service.rs::sign_openpgp_detached*`, `sign_openpgp_cleartext*`; callers in `api/handlers/{debian,rpm,pacman,terraform,signing}.rs`, `services/rpm_publish_service.rs` | Yes | Yes, outside the module | Same as OpenPGP key generation. |
| Conda repodata signature, legacy RPM raw signature | RSA PKCS#1 v1.5 with SHA-256 | `signing_service.rs::sign_data` / `sign_with_key` | Yes | Yes, outside the module | Follow-up: `aws_lc_rs::signature::RsaKeyPair` with `RSA_PKCS1_SHA256`. |
| Hex registry signature | RSA PKCS#1 v1.5 with SHA-512 (2048-bit key) | `signing_service.rs::sign_hex_registry` | Yes | Yes, outside the module | Follow-up: `aws_lc_rs` `RSA_PKCS1_SHA512`. |
| **Alpine APKINDEX signature (`.SIGN.RSA.`)** | **RSA PKCS#1 v1.5 with SHA-1** | `signing_service.rs::sign_apk_index` → `sign_with_key_digest(RsaDigest::Sha1)`; `api/handlers/alpine.rs` | Yes | **No**: SHA-1 signature generation is disallowed (SP 800-131A Rev. 2) | Follow-up: in the FIPS build, sign with SHA-256 under `.SIGN.RSA256.` (check which apk-tools versions accept it), or refuse to sign APK indexes. |
| **CloudFront signed URLs** | **RSA PKCS#1 v1.5 with SHA-1** (required by CloudFront's canned policy) | `storage/s3.rs::generate_cloudfront_signed_url` (RustCrypto `rsa`, `sha1`) | Yes: authorises downloads | **No** | Follow-up: refuse CloudFront signed-URL mode in the FIPS build; use S3 presigned URLs (SigV4) instead. |
| GCS service-account auth and V4 signed URLs | RSA PKCS#1 v1.5 with SHA-256 (`GOOG4-RSA-SHA256`) | `storage/gcs.rs::fetch_jwt_token`, `generate_signed_url` (RustCrypto `rsa`) | Yes | Yes, outside the module | Follow-up: `aws_lc_rs::signature::RsaKeyPair`. |
| Webhook `v2=` signatures and JWKS | Ed25519 | `services/webhook_signing_keys.rs` (`ed25519-dalek`); thumbprint SHA-256 (`jwk_thumbprint`) | Yes | Ed25519: Yes (FIPS 186-5), outside the module | Follow-up: `aws_lc_rs::signature::Ed25519KeyPair`. Check that the AWS-LC FIPS certificate in use lists EdDSA; if it does not, the FIPS build offers only `hmac` signing mode. |
| Key fingerprints, signer-set fingerprint | SHA-256 | `signing_service.rs::compute_fingerprint`, `signer_set_fingerprint` | Low: identifiers | Yes, outside the module | Follow-up with the other `sha2` call sites. |

## Signature and MAC verification

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| **SAML response / assertion XML-DSig** | Whatever the IdP uses. Accepted: RSA PKCS#1 v1.5 and PSS with SHA-1/SHA-2/SHA-3, ECDSA, DSA-SHA1/SHA256, Ed25519, ML-DSA, SLH-DSA. Because `bergshamra`'s default `legacy-algorithms` feature is on, also **RSA-MD5, HMAC-MD5, RIPEMD-160 signatures and MD5 reference digests** | `services/saml_service.rs` (`bergshamra` 0.5.1, RustCrypto backends; `trusted_keys_only` and `strict_verification` are on) | Yes: this decides who logs in | SHA-2 RSA/ECDSA: Yes, outside the module. SHA-1 for verification: legacy use only (SP 800-131A). MD5, RIPEMD-160, DSA: No | Follow-up, high priority: turn off `bergshamra`'s default features to drop `legacy-algorithms` (this affects the default build too), and in the FIPS build accept only RSA/ECDSA with SHA-256 or stronger in both `SignatureMethod` and `DigestMethod`. Then evaluate routing the `SignatureValue` check through aws-lc-rs via `DsigContext::hsm_verifier` (reference digests would still be computed by RustCrypto). |
| Upstream OpenPGP signatures during curation sync (Debian Release, RPM repomd, Pacman) | Whatever the upstream signs with | `signing_service.rs::verify_detached`; callers `services/scheduler_service.rs`, `formats/pacman.rs` | Yes: gates which upstream checksums are trusted | SHA-2 RSA/EdDSA: Yes, outside the module. `pgp` 0.14 does not appear to refuse SHA-1 or MD5 signatures by default; SHA-1 goes through `sha1-checked` collision detection | Follow-up: apply the existing `attestation_hash_is_allowed` allowlist (SHA-2 and SHA-3 only) in `verify_detached`, at least in the FIPS build. |
| Signing-key trust attestations | OpenPGP, SHA-2/SHA-3 only; RSA keys of 2048 bits or more | `signing_service.rs::reject_weak_attestation_signature`, `reject_untrusted_issuer_key` | Yes | Yes, outside the module | Same as OpenPGP signing. |
| Sigstore bundle verification (`publisher_trust match:attestation`), PyPI and npm attestations, CEP-27 | ECDSA P-256/P-384, RSA, Ed25519 (Fulcio leaf and DSSE); SHA-256 digests; Rekor SET and inclusion proofs | `services/curation/attestation_verify/*` (`sigstore` 0.14 `CosignVerificationKey`, RustCrypto `ecdsa`/`p256`/`p384`/`rsa`/`ed25519-dalek`); certificate chain via `rustls-webpki` `ALL_VERIFICATION_ALGS` | Yes | Approved algorithms. Chain building: in the module in the FIPS build (`rustls-webpki` on aws-lc-rs). Leaf and DSSE signatures, Rekor: outside the module | Follow-up: re-implement the leaf/DSSE and Rekor signature checks with `aws_lc_rs::signature` (the crate's verifier is not pluggable), or document sigstore as a non-validated component. |
| Vendored Sigstore trust root pin | SHA-256 | `attestation_verify/trust_root.rs::vendored` | Yes | Yes, outside the module | Follow-up: `aws_lc_rs::digest`. |
| MCPB bundle signatures (CMS / PKCS#7) | RSA with SHA-256 only (other digests refused); X.509 parsing | `services/mcpb.rs::verify_der_digests`, `verify_rsa` (`x509-cert`, RustCrypto `rsa`) | Yes | Yes, outside the module | Follow-up: `aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256`. |
| WASM plugin supply-chain signature | Ed25519 over the raw WASM bytes | `services/wasm_plugin_service.rs::verify_ed25519` (`ed25519-dalek`) | Yes | Yes (FIPS 186-5), outside the module | Follow-up: `aws_lc_rs::signature::ED25519` (subject to the EdDSA certificate check above). |
| Plugin pin to a git commit | SHA-1 object IDs (libgit2 `sha1dc`, collision-detecting) | `wasm_plugin_service.rs::checkout_ref` (`git2`) | Low: the Ed25519 signature is the trust anchor | No (SHA-1 used as an identifier) | No change. In FIPS mode, require a plugin signature. |
| OIDC/CI JWKS signature checks | see the JWT table | `jsonwebtoken` | Yes | Yes | In the module (FIPS build). |

## HMAC and request signing

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| Webhook `v1=` and legacy `X-Webhook-Signature` | HMAC-SHA256 | `services/webhook_signing.rs::compute_v1_signature`, `compute_legacy_signature` (RustCrypto `hmac`) | Yes | Yes (FIPS 198-1), outside the module | Follow-up: `aws_lc_rs::hmac`. Wire format unchanged. |
| S3 SigV4 request signing and presigned URLs | HMAC-SHA256, SHA-256 | `object_store` (`client/crypto.rs` selects `aws-lc-rs`), `storage/s3.rs` presigning | Yes | Yes, in the module in the FIPS build | No change. |
| ECR / CodeArtifact token minting (SigV4) | HMAC-SHA256 | `services/aws_upstream_auth.rs::signed_post` (via `object_store::aws::AwsAuthorizer`) | Yes | Yes, in the module in the FIPS build | No change. |
| S3 `DeleteObjects` `Content-MD5` | MD5 | `object_store` `aws/client.rs` | No: required by the S3 API as a transport check; the request is authenticated by SigV4 | No (non-security use) | No change. |
| S3 additional checksums | CRC64-NVME, SHA-256 | `object_store` (`crc-fast`) | No: integrity | n/a | No change. |
| Azure Shared Key and SAS tokens | HMAC-SHA256 | `storage/azure.rs::shared_key_auth`, `generate_sas_token_at`, `generate_container_sas_token` (RustCrypto `hmac`) | Yes | Yes, outside the module | Follow-up: `aws_lc_rs::hmac`. |
| TOTP codes | HMAC-SHA1, 6 digits, 30 s (RFC 6238) | `api/handlers/totp.rs::build_totp` (`totp-rs` → RustCrypto `hmac`, `sha1`) | Yes | Yes (HMAC-SHA1 is approved, FIPS 198-1 / SP 800-107), outside the module | Follow-up: compute HOTP/TOTP with `aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY` (or keep `totp-rs` only for URI and QR generation). The algorithm stays SHA-1 for authenticator-app compatibility. |

## Random number generation

| Use | Source | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| PBKDF2 salts (FIPS build) | AWS-LC DRBG | `fips_password.rs` (`aws_lc_rs::rand::SystemRandom`) | Yes | Yes (SP 800-90A CTR_DRBG), in the module | Done in this PR. |
| TLS randomness | provider RNG | rustls FIPS provider | Yes | Yes, in the module (FIPS build) | Done in this PR. |
| AES-GCM nonces (credential encryption, MCP cursors) | `rand::random` (ThreadRng: ChaCha12 seeded from the OS) | `services/encryption.rs::encrypt`, `formats/mcp.rs::CursorSeal::seal` | Yes | No (not an SP 800-90A DRBG) | Follow-up: with the AES-GCM move, `aws_lc_rs::rand`. |
| Webhook secrets, instance Ed25519 webhook seed, LDAP cache HMAC key, device codes, MCP namespace proofs | `rand::rng()` (ThreadRng) | `webhook_secret_crypto.rs`, `webhook_signing_keys.rs::generate`, `ldap_basic_auth.rs::hmac_key`, `device_service.rs`, `mcp_namespace_proofs.rs` | Yes | No | Follow-up: a small `crate::util::secure_random` helper that calls `aws_lc_rs::rand` in the FIPS build, used at every call site. |
| TOTP secret | `rand::rng()` inside `totp_rs::Secret::generate_secret` | `api/handlers/totp.rs` | Yes | No | Follow-up: generate the 20 bytes with the helper, then pass `Secret::Raw`. |
| TOTP backup codes, generated admin and user passwords, fallback `PEER_API_KEY` | `rand::rng()` / `rand::random` | `totp.rs::mint_backup_codes`, `main.rs::generate_random_password`, `api/handlers/users.rs::generate_password`, `config.rs` (`peer_api_key`) | Yes | No | Same helper. |
| PKCE verifier | OS CSPRNG (`rand::rngs::SysRng` → `getrandom`) | `auth_config_service.rs::generate_pkce_verifier` | Yes | No (OS RNG, outside the module) | Same helper. |
| RSA and OpenPGP key generation, OpenPGP v6 signature salts | `OsRng` (`rand_core` 0.6 via `rsa` and `pgp`) | `signing_service.rs` | Yes | No (OS RNG) | Moves with the key generation follow-up. |
| API tokens, OIDC state and nonce, SAML RelayState, SSO exchange codes, OCI and Incus upload state tokens | UUIDv4 (`uuid` `rng` feature → `getrandom`) | `auth_service.rs::generate_api_token_with_policy`, `oidc_service.rs`, `auth_config_service.rs`, `saml_service.rs`, `api/handlers/{oci_v2,incus}.rs` | Yes: bearer values | No (OS RNG) | Follow-up: mint secret values (API tokens, exchange codes, state) from the helper instead of UUIDs; keep UUIDs for identifiers. |
| Retry jitter, backoff, temp-file names, scheduler jitter | `rand::rng()` / `rand::random` | `db.rs`, `main.rs`, `scheduler_service.rs`, `scan_result_service.rs`, `rpm_publish_service.rs` | No | n/a | No change. |
| Metrics sampling | xoshiro | `metrics-util` (`rand_xoshiro`) | No | n/a | No change. |

## Package-format checksums and content addressing

The server computes SHA-256 of every stored artifact and keys storage on it
(`storage/*::put_stream`, `storage/verify.rs`, `services/storage_service.rs`,
`services/upload_service.rs`, OCI digests). That SHA-256, plus repository
signatures, is what trust rests on. MD5 and SHA-1 values exist because package
formats and clients require them.

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| Content addressing, dedupe, stored-byte verification, chunked upload assembly | SHA-256 | `storage/{s3,gcs,azure,filesystem}.rs::put_stream`, `storage/verify.rs`, `services/upload_service.rs`, `services/storage_service.rs` | Yes: integrity of stored content | Yes, outside the module | Follow-up: route `sha2::Sha256` through a `crate::util::digest` wrapper that uses `aws_lc_rs::digest` in the FIPS build. |
| Per-artifact checksum columns `checksum_sha256/sha1/md5` | SHA-256, SHA-1, MD5 (one pass) | `services/artifact_service.rs::MultiHasher`, `storage_reindex_service.rs`, `migration_worker.rs::compute_dual_checksums` | SHA-256: Yes. SHA-1/MD5: No, served for client compatibility only | SHA-256: Yes. SHA-1: approved as a hash but not for this kind of trust. MD5: No | SHA-256 moves to the wrapper. MD5/SHA-1 stay as non-security values. |
| Maven `.md5` / `.sha1` / `.sha256` / `.sha512` sidecars and `X-Checksum-*` headers | MD5, SHA-1, SHA-256, SHA-512 | `api/handlers/maven.rs::compute_checksum`, `serve_computed_checksum` | No: required by the format; clients use them for corruption checks | MD5: No. Others: Yes | No change (non-security). SHA-2 moves to the wrapper. |
| npm `integrity` (hosted) | SHA-256 SRI | `api/handlers/npm.rs::compute_npm_integrity` | Yes: clients verify the tarball against it | Yes, outside the module | Wrapper. |
| PyPI `#sha256=` links, client `sha256_digest` check | SHA-256 (client `md5_digest` is read and ignored) | `api/handlers/pypi.rs` | Yes | Yes, outside the module | Wrapper. |
| Debian `Packages` / `Release` | MD5Sum, SHA1, SHA256 | `api/handlers/debian.rs::push_packages_entry`, `render_release_document` | SHA-256: Yes (apt verifies it under the signed Release). MD5/SHA1: No (format compatibility) | MD5: No. SHA-1/SHA-256: Yes | No change for MD5/SHA-1. Consider omitting `MD5Sum`/`SHA1` in the FIPS build (modern apt needs only SHA256). |
| RPM repodata | SHA-256 | `api/handlers/rpm.rs::render_repodata_at` | Yes | Yes, outside the module | Wrapper. |
| Alpine APKINDEX `C:Q1…` | SHA-1 | `api/handlers/alpine.rs::apk_control_checksum` | No: package identity required by apk; the index signature and stored SHA-256 carry trust | SHA-1 as an identifier | No change (but see the APK index signature row). |
| Conda `md5` / `sha256`, CEP-16 shard addresses | MD5, SHA-256 | `api/handlers/conda.rs::store_conda_package`, `build_repodata_entry`, `shard_address`; `rattler_digest` | SHA-256: Yes. MD5: No (format compatibility) | MD5: No | No change for MD5. SHA-256 moves to the wrapper. |
| Conda JLAP hash chain | BLAKE2b-256, keyed with the previous (public) checksum | `api/handlers/conda.rs::blake2_256`, `blake2_256_keyed`; `conda/jlap_store.rs` | No: required by the JLAP format, and the key is public | No | No change (non-security). |
| Cargo `cksum`, NuGet `PackageHash`, Helm, RubyGems, Chef, Puppet, Swift, Conan, Hex, Terraform `SHA256SUMS`, Hugging Face, protobuf, MCP `fileSha256`, agent plugins, Pacman `%SHA256SUM%`, Go module zips | SHA-256 (NuGet v3 also SHA-512 where emitted) | respective `api/handlers/*.rs` and `formats/*.rs` | Yes: clients verify downloads | Yes, outside the module | Wrapper. |
| OCI manifest and blob digests | SHA-256 (`sha512:` rejected) | `api/handlers/oci_v2.rs`, `oci_digest.rs::compute_sha256` | Yes | Yes, outside the module | Wrapper. |
| CocoaPods CDN shard path | MD5 of the pod name | `formats/cocoapods.rs::cdn_shard_fragment` | No: path layout required by the protocol | No (non-security) | No change. |
| Composer `dist.shasum` (upstream) | SHA-1 string, used as a proxy-cache key | `api/handlers/composer.rs::composer_dist_cache_path` | Low: the value is not checked | n/a | No change. |
| Client-declared upload checksums (generic uploads, Maven sidecar uploads) | SHA-1, MD5 compared to server-computed values; a mismatch is refused | `artifact_service.rs::verify_checksums`, `verify_declared_digests`; `maven.rs::check_checksum_sidecar_upload` | No: a match grants nothing, since the server keys on its own SHA-256 | No (non-security use) | No change. |
| **Proxy cache integrity gate when upstream offers only SHA-1** | SHA-1 compared to upstream Maven `.sha1` or npm `sha1-` / `dist.shasum` (used only when no SHA-256/512 is available) | `services/proxy_service.rs::TeeDigestHasher::Sha1`, `tee_stream`; `maven.rs::maven_remote_stream`, `MavenScannedArchive::after_buffered_fetch`; `npm.rs::parse_npm_sri` | Yes: decides whether upstream bytes enter the cache (cache-poisoning defence) | SHA-1 is approved as a hash (FIPS 180-4), but its collision resistance is broken | Follow-up: in the FIPS build, compute the SHA-1 with `aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY`, and log that the entry is only SHA-1-verified. Prefer SHA-256/512 whenever upstream offers them (already the case). |
| **RPM curation chain of trust (`primary.xml` against signed `repomd.xml`)** | SHA-256, SHA-512, or SHA-1 (`type="sha"`/`sha1`); MD5 refused | `services/curation_sync.rs::repodata_hex_digest`, `repodata_checksum_matches` | Yes | SHA-1: approved hash, weak for this purpose | Follow-up: refuse `sha`/`sha1` repodata checksums in the FIPS build. |
| **Migration integrity check and duplicate detection** | SHA-256 when the source declares it, otherwise SHA-1 | `services/migration_worker.rs::verify_expected_checksums`, `decide_duplicate_match` | Yes: accepts or skips artifacts from the source system | As above | Follow-up: in the FIPS build, compute SHA-256 after transfer and record SHA-1-only matches as unverified; do not skip on a SHA-1 match. |
| Search by checksum | SHA-256, SHA-1, MD5 column lookup | `api/handlers/search.rs::resolve_checksum_column` | No: read-only lookup | n/a | No change. |

## Other uses

| Use | Algorithm | Crate / code location | Security-relevant? | FIPS-approved algorithm? | Plan for FIPS mode |
|---|---|---|---|---|---|
| HTTP `ETag`s | SHA-256 of the body or stored checksum; storage-backend MD5 ETags compared as strings | `api/handlers/cache_headers.rs::compute_etag`, `npm.rs::compute_packument_etag`, `conda.rs`, `formats/agent_plugins.rs::document_etag`; `proxy_service.rs::is_multipart_etag` | No: cache validation | n/a | Wrapper for SHA-256; no other change. |
| Cache keys, deterministic IDs (NuGet search, VS Code gallery, Debian signed-Release cache, conda merge keys, npm revisions, SBOM synthetic IDs, crash signatures, Hugging Face commit SHAs) | SHA-256 | `api/handlers/{nuget,vscode,debian,npm,huggingface,composer}.rs`, `conda/merge_gate.rs`, `services/{sbom_service,crash_reporting_service,package_analysis_service}.rs` | No | n/a | Wrapper (optional; no security impact). |
| sqlx migration checksums | SHA-384 | `migration_repair.rs` (`migration_sha384`), sqlx | No: detects edited migrations | n/a | No change. |
| UUIDs as identifiers | UUIDv4 | `uuid` | No (when only identifiers) | n/a | No change. |
| Render-lock striping, in-memory maps | SipHash (`DefaultHasher`), `ahash`, `fnv` | `services/repo_metadata_revision_cache.rs::render_lock`; dependencies | No | n/a | No change. |
| ZIP / archive CRCs, Redis key hashing | CRC-32, xxHash | `zip`, `flate2`, `redis` (`xxhash-rust`), test helpers | No | n/a | No change. |
| ZIP AES and legacy encryption support | AES (WinZip AE-x), PBKDF2-HMAC-SHA1, ZipCrypto | `zip` 9 (default features; reading encrypted archives is not used) | No | n/a | Follow-up (cleanup): build `zip` without its `aes-crypto` feature. |
| Algorithms only pulled in by dependencies | CAST5, IDEA, Twofish, Blowfish, 3DES, Camellia, DSA, X25519/X448, Ed448, secp256k1, Argon2, BLAKE2 (`pgp`); DES, AES-KW, ML-DSA, SLH-DSA, PKCS#11 (`bergshamra`, `kryptering`); scrypt, XSalsa20-Poly1305 (`sigstore`) | `cargo tree -e normal` | Only as reachable through the uses above | Mostly No | No change by itself. Each one is reachable only through the `pgp`, `bergshamra` and `sigstore` paths listed above, which have their own follow-ups. |
| Non-FIPS `aws-lc-sys` in the FIPS build | n/a | `object_store` enables `aws-lc-rs` default features, so `aws-lc-sys` is still compiled | No: when the `fips` feature is on, `aws-lc-rs` binds to `aws-lc-fips-sys` (`extern crate aws_lc_fips_sys as aws_lc`) and never calls it | n/a | Follow-up (build hygiene): drop it from the FIPS build if `object_store` allows `default-features = false` for `aws-lc-rs`. |

## Summary of gaps for follow-up PRs

In priority order: security-relevant uses with a non-approved algorithm first,
then security-relevant uses of approved algorithms outside the module, then
cleanup.

1. **SAML XML-DSig accepts MD5, RIPEMD-160 and SHA-1.** Turn off
   `bergshamra`'s default `legacy-algorithms` feature (all builds). In the FIPS
   build accept only SHA-256 or stronger RSA/ECDSA `SignatureMethod` and
   `DigestMethod`.
2. **SHA-1 signature generation**: the Alpine `.SIGN.RSA.` index
   (`sign_apk_index`) and CloudFront signed URLs
   (`generate_cloudfront_signed_url`). In the FIPS build, switch APK to
   `.SIGN.RSA256.` or refuse it; refuse CloudFront signed-URL mode.
3. **Sub-2048-bit RSA ID tokens** (`allow_legacy_rsa_keys`,
   `verify_id_token_with_legacy_rsa`). Refuse in the FIPS build.
4. **Upstream OpenPGP verification without a hash allowlist**
   (`verify_detached`). Apply `attestation_hash_is_allowed`.
5. **Integrity decisions on SHA-1**: RPM `type="sha"` repodata in curation
   sync, migration checks and duplicate skips that fall back to SHA-1, and the
   proxy cache gate when upstream offers only SHA-1. Refuse, or mark as
   unverified, in the FIPS build; compute any remaining SHA-1 inside the module.
6. **Random number generation for secrets** outside the module DRBG
   (`rand::rng()`, `OsRng`, `SysRng`, UUIDv4 used as bearer tokens). Add a
   `secure_random` helper backed by `aws_lc_rs::rand` in the FIPS build and use
   it for every secret, nonce, key and token.
7. **Encryption at rest** (`services/encryption.rs`, `formats/mcp.rs`
   cursors). Move AES-256-GCM and the HMAC KDF to `aws_lc_rs`, and disable the
   raw-SHA-256 legacy key fallback in the FIPS build after re-encrypting legacy
   rows.
8. **Postgres authentication.** Require `scram-sha-256` (document it now) and
   refuse MD5 password auth in the FIPS build; SCRAM itself stays in RustCrypto
   until sqlx allows a different backend.
9. **HMAC and digests on secrets and authentication paths**: webhook `v1=`,
   Azure Shared Key/SAS, LDAP credential cache, TOTP, PKCE, and the device-code,
   MCP-token and API-token-cache digests. Move them to `aws_lc_rs::hmac` and
   `aws_lc_rs::digest`.
10. **Signing and verification outside the module**: RSA repository and
    Hex/Conda signatures, GCS service-account JWTs and signed URLs, Ed25519
    webhooks and plugin signatures, MCPB CMS checks, sigstore leaf/DSSE and
    Rekor checks, OpenPGP (`pgp`). Move to `aws_lc_rs::signature` where the
    crate allows it; for `pgp`, `sigstore` and `bergshamra`, decide between
    adapter code and documenting them as non-validated components. Confirm
    that the AWS-LC FIPS certificate in use covers EdDSA.
11. **Content addressing and format checksums on SHA-2.** Add a
    `crate::util::digest` wrapper (aws-lc-rs in the FIPS build) and replace the
    roughly 110 `sha2` call sites. MD5, SHA-1 and BLAKE2 values that formats
    require stay as non-security uses; optionally drop Debian `MD5Sum`/`SHA1`
    in the FIPS build.
12. **Build hygiene**: drop the unused non-FIPS `aws-lc-sys` and `zip`'s
    `aes-crypto` from the FIPS build; OTLP gRPC has no TLS, so document a
    local-collector or HTTP-exporter setup.
