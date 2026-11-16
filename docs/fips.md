# FIPS 140-3 build

The backend has an opt-in build for deployments that require FIPS 140-3
validated cryptography. It is a cargo feature, `fips`, and a separate image
variant built from the same Dockerfile. The default build and the default
image are unchanged: nothing in this document applies to them.

Every cryptographic use in the backend, with its FIPS status and the plan for
it, is listed in [fips-crypto-inventory.md](fips-crypto-inventory.md). That
document also records which AWS-LC FIPS module version the build links and
its certificate status.

## What the `fips` build changes

- **One validated module.** Every `aws-lc-rs` user in the dependency graph
  (rustls, jsonwebtoken, object_store, sigstore) is switched to the AWS-LC
  FIPS module (`aws-lc-fips-sys`). `ring` is not linked, and neither is
  OpenSSL (`native-tls`).
- **TLS on the FIPS provider.** At startup the backend installs
  `rustls::crypto::default_fips_provider()` as the process-wide rustls
  provider, before anything opens a connection. All outbound TLS goes through
  it:
  - Postgres (sqlx, `tls-rustls-aws-lc-rs` instead of `tls-rustls-ring-webpki`);
  - every reqwest client: the backend's own (`services/http_client.rs`),
    object_store (S3, and the AWS credential chain), OpenSearch, sigstore and
    TUF, the OTLP HTTP exporter and the conda (rattler) client. Without
    `native-tls` in the build, reqwest's only TLS backend is rustls, and it
    uses the installed process-default provider;
  - Redis (`rediss://`), which uses the process-default provider;
  - LDAP (LDAPS and StartTLS) and SMTP (STARTTLS and implicit TLS), which use
    native-tls (OpenSSL) in the default build and rustls in this one.
- **Refuses to start** unless the AWS-LC module reports FIPS mode (its
  power-on self tests passed) and the installed provider reports
  `CryptoProvider::fips()`. The failure is printed to stderr and the process
  exits non-zero. On success it logs, before configuration is read:

  ```
  FIPS 140-3 mode: TLS and approved-algorithm operations use the AWS-LC FIPS module
  ```

- **Passwords and API tokens** are hashed with PBKDF2-HMAC-SHA256 from the
  module instead of bcrypt. See [Password and token hashing](#password-and-token-hashing).

The backend does not terminate inbound TLS (it serves plain HTTP and gRPC).
The ingress, load balancer or service mesh in front of it must provide FIPS
140-3 validated TLS itself.

## Behaviour differences to expect

- **TLS versions and suites.** Only TLS 1.2 and 1.3 with FIPS-approved cipher
  suites and key exchange groups are offered. A peer (directory server, mail
  server, upstream registry, database) limited to TLS 1.0/1.1 or to
  non-approved suites fails to connect.
- **Trust store.** Unchanged in meaning: the system trust store plus the
  configured custom CAs (`CUSTOM_CA_CERT_PATH`, `LDAP_CA_CERT_PATH` or the
  per-provider PEM, `SMTP_TLS_CA_CERT`, `S3_CA_CERT_PATH`).
- **Skip-verify options** (`LDAP_INSECURE_TLS`, `SMTP_TLS_SKIP_VERIFY`,
  `S3_INSECURE_TLS`) still work as in the standard build: certificate and
  hostname checks are skipped, but handshake signatures are still verified
  with the provider's approved algorithms. They defeat the purpose of TLS and
  should not be set in a FIPS deployment.
- **Plaintext channels.** The gRPC server and the OTLP gRPC exporter have no
  TLS in either build, and the Prometheus endpoint is plain HTTP. Put TLS in
  front of them, or use the OTLP HTTP exporter (which goes through the FIPS
  provider) for a remote collector.
- **Postgres authentication.** sqlx performs SCRAM-SHA-256 with pure-Rust
  primitives outside the module, and will answer MD5 password authentication
  if the server asks for it. Configure the database for `scram-sha-256` only,
  over TLS.

## Building it

From source (needs a C toolchain, CMake and Go for `aws-lc-fips-sys`, in
addition to the usual `protoc`):

```bash
cargo build --release --no-default-features --features fips,jemalloc --bin artifact-keeper
```

`--no-default-features` is required. The default `default-tls` feature turns on
`ring` and native-tls; sqlx uses `ring` for Postgres whenever that feature is
on at all, so combining `fips` with `default-tls` is a compile error rather
than a build that quietly leaves Postgres outside the module.

The container image variant:

```bash
docker build -f docker/Dockerfile.backend --build-arg FIPS=1 \
  -t artifact-keeper-backend:<version>-fips .
```

`FIPS=1` installs CMake and Go in the build stage and builds the backend with
`--no-default-features --features fips` plus the image's usual
`CARGO_FEATURES` (`jemalloc`). The runtime image is otherwise identical. Only
`docker/Dockerfile.backend` (UBI 9) has the variant; the Alpine Dockerfile
does not.

`scripts/ci/check-fips-dependency-graph.sh` asserts, from the resolved
dependency graph, that the FIPS build links `aws-lc-fips-sys` and none of
`ring`, `native-tls` or `openssl-sys`, and that the default build still links
`ring` and not the FIPS module.

## Password and token hashing

bcrypt and Argon2 are not FIPS-approved. In the `fips` build, new password
hashes, API token hashes and TOTP backup code hashes use PBKDF2-HMAC-SHA256
(SP 800-132) computed by `aws_lc_rs::pbkdf2`:

- **Format.** `$pbkdf2-sha256$i=600000$<salt>$<key>`: 600,000 iterations
  (the OWASP 2023 recommendation for PBKDF2-HMAC-SHA256), a 16-byte salt from
  the module's DRBG and a 32-byte derived key, both standard base64 without
  padding. Verification reads the iteration count from the stored string and
  compares in constant time (`aws_lc_rs::pbkdf2::verify`). The lib unit tests
  use 1,000 iterations, the same way they use a cheap bcrypt cost.
- **Existing bcrypt hashes** (written by a standard build) are handled
  according to `FIPS_LEGACY_PASSWORD_HASHES`:

  | Value | Behaviour |
  |---|---|
  | `rehash` (default, also when unset) | The bcrypt hash is checked once with bcrypt, logged at WARN as a non-approved legacy verification. On a successful password login (including HTTP Basic) or API-token use, the stored hash is replaced with a PBKDF2 hash. |
  | `refuse` | A bcrypt hash never verifies (logged at WARN). Affected users need a password reset by an administrator, API tokens must be reissued, TOTP backup codes regenerated. |

  Any other value stops the server at startup. `rehash` is a transition aid:
  it still runs bcrypt, a non-approved algorithm, until every account has
  logged in once. Deployments that must not run a non-approved algorithm at
  all use `refuse`.
- **What is not rehashed.** TOTP backup codes are single-use: a legacy code is
  checked under the policy and then consumed, and newly generated codes are
  PBKDF2. Entries in the password history cannot be rehashed; under `refuse`
  legacy entries no longer block password reuse. A password change always
  writes PBKDF2.
- **Timing.** The unknown-user timing pad is a PBKDF2 hash at the same
  iteration count, so a login for a non-existent user costs the same.
- **The rewrite is one way.** The standard build verifies bcrypt only, so
  moving a database from a FIPS deployment back to a standard build leaves
  every account and API token that was rehashed (or created) under FIPS
  unable to authenticate until an administrator resets it. Reading PBKDF2
  hashes in the standard build would avoid that; it is left out of this first
  change because the standard build's behaviour is deliberately unchanged.

## CI

- `🔐 FIPS Build (<shard>)` (`.github/workflows/ci.yml`, job
  `test-backend-fips`) builds and runs the lib and bin unit tests with
  `--no-default-features --features fips` on the same five shards as the
  default unit tests, runs clippy on that build, and runs
  `check-fips-dependency-graph.sh`. CMake and Go come preinstalled on the
  `ubuntu-24.04` runners. It is not a required check and is not instrumented
  for coverage.
- `🐳 Build Backend Image (FIPS)` (job `build-backend-image-fips`) builds the
  image with `FIPS=1` on the same triggers as the default image build, and
  checks that the container gets past the provider check and logs FIPS mode.
  It does not push.

The release workflows are unchanged: they do not build or publish a `-fips`
tag yet. Publishing one means adding the variant to `docker-publish.yml`
(build, scan, sign, attest, verify), which is a follow-up.

## Not covered yet

The first PR covers TLS and password/token hashing. The rest of the backend's
cryptography (content checksums, signing keys, signature verification, HMACs,
encryption of stored secrets, random numbers) still uses RustCrypto, `pgp` and
`rand`, which implement mostly approved algorithms but are outside the
validated module boundary, and a few non-approved or SHA-1-signature uses.
[fips-crypto-inventory.md](fips-crypto-inventory.md) lists each one with its
plan; its last section is the prioritised follow-up list.
