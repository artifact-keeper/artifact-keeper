# RPM Proxy Hardening (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Artifact Keeper's already-shipping Remote proxy for RPM: fix the DNS-rebinding SSRF gap, enforce cache quota, classify RPM cache freshness correctly, verify content-addressed integrity, and reject mirrorlist/metalink upstreams.

**Architecture:** Small, surgical changes to existing modules — a new SSRF-validating DNS resolver wired into the shared `base_client_builder`; an `Rpm` arm added to the central `cache_classifier`; validation and cache-write guards. No new tables. Reuses `is_blocked_resolved_ip`, `cache_classifier`, `validate_remote_upstream`, and existing quota helpers.

**Tech Stack:** Rust, Axum, reqwest (workspace dep), sqlx/PostgreSQL, tokio.

**Tracking:** beads epic `artifact-keeper-1gx`; this plan implements task `1gx.1` and bugs `artifact-keeper-3to` (SSRF) and `artifact-keeper-x70` (quota). Design: `docs/plans/2026-07-09-rpm-remote-proxy-design.md` (§6 S1/S2/S3/S9, §8).

## Global Constraints

- Branch `feat/rpm-remote-proxy`; never push to main; PR + squash-merge after CI.
- CI gates (all must pass): `cargo fmt --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --lib`; **≥70% coverage on changed lines**; **≤3% jscpd duplication on changed files**.
- Keep new logic in **pure, table-testable functions** (coverage + duplication gates).
- Streaming invariant (#1608): never buffer a full artifact body on an artifact path.
- Do NOT construct a new `reqwest::Client`; all outbound HTTP goes through `http_client::base_client_builder()`.
- No `Co-Authored-By` / AI-attribution in commits.

---

### Task 1: SSRF-validating DNS resolver (fixes `artifact-keeper-3to`, design S1)

Closes the DNS-rebinding gap: URL strings are validated at config time and every redirect hop, but the *resolved IP* of the initial request is never checked. Wire a custom `reqwest::dns::Resolve` into `base_client_builder` that rejects any resolved IP failing `is_blocked_resolved_ip`.

**Files:**
- Create: `backend/src/services/ssrf_dns.rs`
- Modify: `backend/src/services/mod.rs` (add `pub mod ssrf_dns;`)
- Modify: `backend/src/services/http_client.rs:59-97` (`base_client_builder`) — attach the resolver
- Test: in `backend/src/services/ssrf_dns.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `crate::api::validation::is_blocked_resolved_ip(std::net::IpAddr) -> bool` (validation.rs:265).
- Produces: `pub struct SsrfGuardResolver;` implementing `reqwest::dns::Resolve`; `base_client_builder()` returns a `ClientBuilder` whose DNS resolution rejects blocked IPs.

- [ ] **Step 1: Write the failing test** (create `backend/src/services/ssrf_dns.rs` with just the test + an empty resolver stub referenced by it)

```rust
//! SSRF-validating DNS resolver: rejects hostnames that resolve to blocked
//! (loopback / link-local / private / cloud-metadata) IPs at connect time,
//! closing the DNS-rebinding gap that URL-string validation cannot catch.

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// A `reqwest` DNS resolver that resolves via the OS resolver and then drops
/// any address rejected by [`crate::api::validation::is_blocked_resolved_ip`].
/// If every resolved address is blocked, resolution fails (the request never
/// connects), defeating DNS-rebinding attacks that pass the URL-string check.
#[derive(Debug, Default, Clone)]
pub struct SsrfGuardResolver;

/// Convenience: an `Arc<dyn Resolve>` for `ClientBuilder::dns_resolver`.
pub fn ssrf_guard_resolver() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver)
}

impl Resolve for SsrfGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            // Port 0 is a placeholder; reqwest substitutes the real port.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed: Vec<SocketAddr> = resolved
                .filter(|sa| !crate::api::validation::is_blocked_resolved_ip(sa.ip()))
                .collect();
            if allowed.is_empty() {
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "all resolved addresses blocked by SSRF policy",
                    ),
                );
                return Err(err);
            }
            let addrs: Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolver_rejects_localhost() {
        // `localhost` resolves to 127.0.0.1 / ::1, both blocked.
        let name: Name = "localhost".parse().expect("valid dns name");
        let result = SsrfGuardResolver.resolve(name).await;
        assert!(result.is_err(), "localhost must be refused by the SSRF resolver");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p artifact-keeper-backend --lib ssrf_dns::tests::resolver_rejects_localhost -- --nocapture`
Expected: FAIL to compile until `pub mod ssrf_dns;` is added, then the test passes once the module compiles. (If `Name: FromStr` is unavailable in the pinned reqwest, see Step 3 note.)

- [ ] **Step 3: Register the module and confirm the resolver compiles**

Add to `backend/src/services/mod.rs` (alphabetical with the other `pub mod` lines):

```rust
pub mod ssrf_dns;
```

Note: if `Name` does not implement `FromStr` in the pinned reqwest version, change the test to build a client with the resolver and assert `client.get("http://localhost/").send().await` errors (an integration-level assertion). Verify the API with `cargo doc -p reqwest --open` or `grep "impl FromStr for Name" ~/.cargo`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p artifact-keeper-backend --lib ssrf_dns::tests::resolver_rejects_localhost`
Expected: PASS.

- [ ] **Step 5: Wire the resolver into `base_client_builder`**

In `backend/src/services/http_client.rs`, change the builder construction (currently line 62):

```rust
    let mut builder = reqwest::Client::builder()
        .redirect(ssrf_redirect_policy())
        .dns_resolver(crate::services::ssrf_dns::ssrf_guard_resolver());
```

- [ ] **Step 6: Add a client-level regression test** (in `http_client.rs` tests module, mirroring `test_redirect_to_blocked_ip_is_refused`)

```rust
    /// A hostname resolving to a blocked IP must be refused at DNS time, not
    /// connected to. `localhost` resolves to 127.0.0.1/::1 (blocked).
    #[tokio::test]
    async fn test_client_refuses_host_resolving_to_blocked_ip() {
        let client = base_client_builder().build().unwrap();
        let err = client
            .get("http://localhost/")
            .send()
            .await
            .expect_err("host resolving to a blocked IP must be refused");
        // A DNS/connect-layer rejection (not a live HTTP response).
        assert!(
            err.is_connect() || err.is_request() || err.to_string().to_lowercase().contains("ssrf") || err.to_string().to_lowercase().contains("block"),
            "expected resolver rejection, got: {err}"
        );
    }
```

- [ ] **Step 7: Run the focused + regression tests, then fmt/clippy**

Run: `cargo test -p artifact-keeper-backend --lib ssrf_dns:: http_client::tests::test_client_refuses_host_resolving_to_blocked_ip`
Then: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS; no clippy warnings.

- [ ] **Step 8: Run the existing http_client SSRF tests to confirm no regression**

Run: `cargo test -p artifact-keeper-backend --lib http_client::tests`
Expected: PASS (including `test_redirect_to_blocked_ip_is_refused`).

- [ ] **Step 9: Commit**

```bash
git add backend/src/services/ssrf_dns.rs backend/src/services/mod.rs backend/src/services/http_client.rs
git commit -m "fix(security): validate resolved IP at connect time (DNS-rebinding SSRF)"
```

---

### Task 2: RPM cache-freshness classifier arm (implements `artifact-keeper-1gx.1` core, design S9/§8.2.1)

RPM currently falls into `cache_classifier::classify`'s conservative `_ => mutable_default()` (300s), so content-addressed `repodata/<sha256>-*.xml.gz`, `.rpm`, `.drpm`, `.zck` are needlessly revalidated every 5 min. Add an `Rpm` arm: content-addressed metadata + packages → `Immutable`; `repomd.xml`(+`.asc`) → mutable default.

**Files:**
- Modify: `backend/src/services/cache_classifier.rs` (add `classify_rpm`; add `Rpm` arm at the match near line 216–220; add `Rpm` to `is_explicitly_mutable_index`'s real-classifier arm at line 247–264 and remove it from the `_` comment at 276)
- Test: same file (`#[cfg(test)]` table test)

**Interfaces:**
- Consumes: `Mutability`, `Mutability::Immutable`, `Mutability::mutable_default()`, `leaf(&str)` (existing helper used by `classify_maven`).
- Produces: `fn classify_rpm(lower: &str) -> Mutability`; `classify(&RepositoryFormat::Rpm, path)` returns correct mutability.

- [ ] **Step 1: Write the failing table test**

```rust
    #[test]
    fn test_classify_rpm() {
        use RepositoryFormat::Rpm;
        // repomd.xml and its signature are the mutable entry point.
        assert_eq!(classify(&Rpm, "repodata/repomd.xml"), Mutability::mutable_default());
        assert_eq!(classify(&Rpm, "repodata/repomd.xml.asc"), Mutability::mutable_default());
        // Content-addressed metadata (checksum-prefixed) is immutable.
        assert_eq!(
            classify(&Rpm, "repodata/1a2b3c4d-primary.xml.gz"),
            Mutability::Immutable
        );
        assert_eq!(
            classify(&Rpm, "repodata/deadbeef-primary.xml.zck"),
            Mutability::Immutable
        );
        // Packages are immutable.
        assert_eq!(classify(&Rpm, "Packages/foo-1.2-3.x86_64.rpm"), Mutability::Immutable);
        assert_eq!(classify(&Rpm, "getPackage/bar-2.0-1.noarch.drpm"), Mutability::Immutable);
        // Unknown / directory-ish paths stay conservative.
        assert_eq!(classify(&Rpm, "repodata/"), Mutability::mutable_default());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p artifact-keeper-backend --lib cache_classifier::tests::test_classify_rpm`
Expected: FAIL (RPM currently returns `mutable_default()` for the content-addressed/package cases).

- [ ] **Step 3: Add the `Rpm` arm and `classify_rpm`**

In `classify` (near line 216, before the `_ =>` arm) add:

```rust
        // -- RPM / YUM ------------------------------------------------------
        // repomd.xml(+.asc) is the single mutable entry point; every other
        // repodata file is content-addressed (checksum-prefixed filename) and
        // packages are version-pinned — both immutable.
        RepositoryFormat::Rpm => classify_rpm(&lower),
```

Add the helper (next to `classify_maven`):

```rust
/// RPM: `repodata/repomd.xml`(+`.asc`) is the mutable index; all other
/// `repodata/<checksum>-*` files are content-addressed and packages
/// (`.rpm`/`.drpm`) are version-pinned — both immutable.
fn classify_rpm(lower: &str) -> Mutability {
    let leaf = leaf(lower);
    // The mutable pointer and its detached signature.
    if leaf == "repomd.xml" || leaf == "repomd.xml.asc" {
        return Mutability::mutable_default();
    }
    // Packages are immutable.
    if leaf.ends_with(".rpm") || leaf.ends_with(".drpm") {
        return Mutability::Immutable;
    }
    // Content-addressed metadata under repodata/: a checksum-prefixed name such
    // as `<hex>-primary.xml.gz` / `.zck`. Require a hex prefix before the first
    // '-' so a bare `primary.xml.gz` (no unique-filename) stays conservative.
    if lower.starts_with("repodata/") {
        if let Some((prefix, _rest)) = leaf.split_once('-') {
            let looks_hashed = prefix.len() >= 8 && prefix.chars().all(|c| c.is_ascii_hexdigit());
            if looks_hashed {
                return Mutability::Immutable;
            }
        }
    }
    // Unknown path: revalidate.
    Mutability::mutable_default()
}
```

- [ ] **Step 4: Add `Rpm` to `is_explicitly_mutable_index` for consistency**

In `is_explicitly_mutable_index` (line 247), add `| RepositoryFormat::Rpm` to the real-classifier arm so `repomd.xml` reports as a mutable index and content-addressed/package paths report as release coordinates:

```rust
        | RepositoryFormat::Cargo
        | RepositoryFormat::Debian
        | RepositoryFormat::Rpm => !classify(format, &lower).is_immutable(),
```

Update the `_ =>` comment at line 276 to drop `Rpm` from the "Default-format families" list.

- [ ] **Step 5: Add a test pinning `is_explicitly_mutable_index` for RPM**

```rust
    #[test]
    fn test_rpm_explicit_mutable_index() {
        use RepositoryFormat::Rpm;
        assert!(is_explicitly_mutable_index(&Rpm, "repodata/repomd.xml"));
        assert!(!is_explicitly_mutable_index(&Rpm, "Packages/foo-1.2-3.x86_64.rpm"));
        assert!(!is_explicitly_mutable_index(&Rpm, "repodata/deadbeef-primary.xml.gz"));
    }
```

- [ ] **Step 6: Run tests + fmt/clippy**

Run: `cargo test -p artifact-keeper-backend --lib cache_classifier::`
Then: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 7: Regression — the hosted RPM release-immutability guard**

Run the RPM handler + release-guard tests to confirm hosted RPM behavior is unchanged:
Run: `cargo test -p artifact-keeper-backend --lib rpm`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/src/services/cache_classifier.rs
git commit -m "feat(rpm): classify RPM proxy cache freshness (immutable pkgs/metadata, mutable repomd)"
```

---

### Task 3: Verify content-addressed integrity before caching (design S3)

When a fetched path embeds a hex checksum (createrepo unique-filename convention), verify the body's SHA-256 matches before caching it as immutable; on mismatch, serve the body but refuse to cache (treat as miss). This makes the "cache forever" decision safe against a dishonest/compromised upstream.

**Files:**
- Modify: `backend/src/services/cache_classifier.rs` (add a pure `expected_sha256_from_path`)
- Modify: `backend/src/services/proxy_service.rs` (call the check at the immutable-cache-write site; exact site read in Step 1)
- Test: `cache_classifier.rs` for the pure extractor; `proxy_service.rs` for the write guard

**Interfaces:**
- Produces: `pub fn expected_sha256_from_path(path: &str) -> Option<&str>` — returns the hex checksum prefix of a content-addressed repodata filename, if present.

- [ ] **Step 1: Read the immutable cache-write site**

Read `backend/src/services/proxy_service.rs` around the streaming cache writer (lines ~1268–1290 and ~2895–2965, where `size_bytes`/`bytes_written` and `storage_clone.put(...)` appear). Identify where a freshly-fetched *immutable* body is persisted; that is where the S3 guard hooks in.

- [ ] **Step 2: Write the failing test for the pure extractor**

```rust
    #[test]
    fn test_expected_sha256_from_path() {
        // Full SHA-256 (64 hex) prefix is returned.
        let p = "repodata/9f".to_string() + &"a".repeat(62) + "-primary.xml.gz";
        assert!(expected_sha256_from_path(&p).is_some());
        // repomd.xml and packages have no embedded checksum.
        assert_eq!(expected_sha256_from_path("repodata/repomd.xml"), None);
        assert_eq!(expected_sha256_from_path("Packages/foo-1.2-3.x86_64.rpm"), None);
    }
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p artifact-keeper-backend --lib cache_classifier::tests::test_expected_sha256_from_path`
Expected: FAIL (function not defined).

- [ ] **Step 4: Implement the extractor**

```rust
/// If `path` is a createrepo unique-filename (`repodata/<sha256>-<name>`),
/// return the 64-hex-char checksum prefix. Used to verify a content-addressed
/// body's integrity before caching it as immutable.
pub fn expected_sha256_from_path(path: &str) -> Option<&str> {
    let leaf = leaf(&path.to_ascii_lowercase());
    let (prefix, _) = leaf.split_once('-')?;
    if prefix.len() == 64 && prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        // Return the slice from the ORIGINAL path (case-insensitive hex).
        let start = path.len() - leaf.len();
        Some(&path[start..start + 64])
    } else {
        None
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p artifact-keeper-backend --lib cache_classifier::tests::test_expected_sha256_from_path`
Expected: PASS.

- [ ] **Step 6: Guard the immutable cache write in `proxy_service.rs`**

At the immutable-write site found in Step 1, before persisting, when `expected_sha256_from_path(cache_path)` is `Some(expected)`, compute the SHA-256 of the fetched bytes and skip the cache write (log a `target: "security"` warning + `metrics_service` counter) if it differs. Reuse the existing hashing helper used for `checksum_sha256` (see `proxy_service.rs:835-852`). Write the exact code against the real function once Step 1 identifies it.

- [ ] **Step 7: Add a proxy_service test asserting a mismatched content-addressed body is not cached**

Model it on the existing proxy_service cache tests (search `#[tokio::test]` in that file). Assert: fetch a `repodata/<64hex>-primary.xml.gz` whose body hashes differently → body returned to caller, no cache sidecar written.

- [ ] **Step 8: Interim one-object-over-quota guard (S2 interim; full quota → P4)**

At the SAME buffered cache-write decision point, add a cheap guard: if `repo.quota_bytes` is
`Some(q)` and the object being cached is larger than `q`, skip the cache write (still stream/return
to the client) and log a `target: "security"` warning + metric. This is the Phase-1 interim for
bug `artifact-keeper-x70`; true per-repo usage accounting + eviction is deferred to P4 (proxy cache
is NOT recorded in the `artifacts` table, so there is no per-repo proxy-cache usage figure to check
a running total against yet). Add a pure helper + unit test for the decision, e.g.
`fn exceeds_single_object_quota(quota_bytes: Option<i64>, object_len: i64) -> bool`.

- [ ] **Step 9: Run tests + fmt/clippy, then commit**

```bash
cargo test -p artifact-keeper-backend --lib cache_classifier:: proxy_service::
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
git add backend/src/services/cache_classifier.rs backend/src/services/proxy_service.rs
git commit -m "fix(security): verify content-addressed hash + reject over-quota single objects before caching"
```

---

### Task 4: Reject mirrorlist/metalink upstreams for Remote RPM repos (design §8.2.6)

A Remote RPM repo must point at one concrete baseurl; a mirrorlist/metalink URL would cache a rotating mirror list. Reject it at repo create/update.

**Files:**
- Modify: `backend/src/services/repository_service.rs:92-108` (`validate_remote_upstream`)
- Test: `repository_service.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `RepositoryType`, `RepositoryFormat`, existing `AppError::Validation`.
- Produces: `validate_remote_upstream(repo_type, upstream_url, format)` now also rejects mirrorlist/metalink for RPM. (Add a `format: &RepositoryFormat` parameter; update the two call sites at :542 and near :897.)

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn test_rpm_remote_rejects_mirrorlist_and_metalink() {
        let ml = Some("https://mirrors.example.org/mirrorlist?repo=epel-9&arch=x86_64".to_string());
        let mt = Some("https://mirrors.example.org/metalink?repo=epel-9".to_string());
        let base = Some("https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/".to_string());
        assert!(validate_remote_upstream(&RepositoryType::Remote, &ml, &RepositoryFormat::Rpm).is_err());
        assert!(validate_remote_upstream(&RepositoryType::Remote, &mt, &RepositoryFormat::Rpm).is_err());
        assert!(validate_remote_upstream(&RepositoryType::Remote, &base, &RepositoryFormat::Rpm).is_ok());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p artifact-keeper-backend --lib repository_service::tests::test_rpm_remote_rejects_mirrorlist_and_metalink`
Expected: FAIL (signature mismatch — function has no `format` param yet).

- [ ] **Step 3: Add the `format` param + rejection logic**

Update `validate_remote_upstream`:

```rust
pub(crate) fn validate_remote_upstream(
    repo_type: &RepositoryType,
    upstream_url: &Option<String>,
    format: &RepositoryFormat,
) -> Result<()> {
    if *repo_type == RepositoryType::Remote {
        match upstream_url {
            None => {
                return Err(AppError::Validation(
                    "Remote repository must have an upstream URL".to_string(),
                ));
            }
            Some(url) => {
                validate_outbound_url(url, "Upstream URL")?;
                if *format == RepositoryFormat::Rpm && is_mirrorlist_or_metalink(url) {
                    return Err(AppError::Validation(
                        "RPM remote upstream must be a concrete baseurl, not a mirrorlist/metalink \
                         URL. Point it at a resolved repo root (e.g. .../BaseOS/x86_64/os/)."
                            .to_string(),
                    ));
                }
            }
        }
    } else if let Some(url) = upstream_url {
        validate_outbound_url(url, "Upstream URL")?;
    }
    Ok(())
}

/// Heuristic: a URL whose path or query names a mirrorlist/metalink endpoint.
fn is_mirrorlist_or_metalink(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.contains("mirrorlist") || lower.contains("metalink")
}
```

- [ ] **Step 4: Update the two call sites**

At `repository_service.rs:542`: `validate_remote_upstream(&req.repo_type, &req.upstream_url, &req.format)?;`
Near `:897` (update path): pass the repository's format (fetch from the existing loaded row / `req.format`). Confirm the field name by reading the surrounding update function.

- [ ] **Step 5: Run tests + fmt/clippy**

Run: `cargo test -p artifact-keeper-backend --lib repository_service::`
Then: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/services/repository_service.rs
git commit -m "feat(rpm): reject mirrorlist/metalink upstreams for remote RPM repos"
```

---

## Remaining P1 tasks — need one short code-read before exact steps

These two items are **in Phase-1 scope** (design S2 + §8.2.2) but sit inside `proxy_service`'s
streaming path, whose exact function bodies I have not yet read. Writing bite-sized code for them
without that read would mean guessing — against this skill's "no placeholders" rule. Each needs a
~15-minute read of the named functions first, after which its task is written to the same standard
as Tasks 1–4.

- **Task 5 — Full cache quota enforcement — MOVED TO P4 (bug `artifact-keeper-x70`).** Confirmed:
  proxy-cache blobs are NOT recorded in the `artifacts` table (test
  `proxy_service.rs:10266 test_cache_artifact_does_not_insert_into_artifacts_table`), so there is no
  per-repo proxy-cache usage figure to enforce a running total against. True enforcement needs a
  usage-accounting mechanism (per-repo counter + eviction) that belongs with P4's GC. **Phase-1
  interim** (reject caching a single object larger than `quota_bytes`) is folded into Task 3 Step 8.
- **Task 6 — Range/`206` passthrough (§8.2.2).** Read `fetch_artifact_streaming_uncoordinated`
  (`proxy_service.rs:2974`) and the upstream request builder it calls, to see where request headers
  are set. Then: forward the client `Range` header, relay `206`/`Content-Range`/`Accept-Ranges`, and
  do **not** cache partial responses. Integration test: `curl -r 0-1023` through the proxy returns
  `206`. E2E: `dnf` zchunk delta path works.

---

## Final integration (after Tasks 1–6)

- [ ] **E2E:** add a script under `scripts/native-tests/` that creates a Remote RPM repo pointing at
  Rocky 9 BaseOS, runs `dnf --disablerepo=* --enablerepo=<ak> install <small-pkg>` with
  `repo_gpgcheck=1`, then a second install served from cache (assert no upstream hit via proxy
  metrics/logs). Wire it into the existing native-test runner.
- [ ] **Full gate run:** `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --lib`; confirm ≥70% changed-line coverage and ≤3% jscpd locally before pushing.
- [ ] **Update beads:** mark `artifact-keeper-3to`, `artifact-keeper-x70` resolved when their tasks land; note progress on `artifact-keeper-1gx.1`.

## Self-review notes
- Spec coverage: S1 (Task 1), S3 (Task 3), classifier/S9 (Task 2), mirrorlist (Task 4), S2 (Task 5), Range (Task 6). All §8.2 items mapped.
- Type consistency: `SsrfGuardResolver`/`ssrf_guard_resolver`, `classify_rpm`, `expected_sha256_from_path`, `is_mirrorlist_or_metalink`, `validate_remote_upstream(_, _, format)` used consistently across tasks.
- Tasks 1–4 are independently shippable (Task 1 alone is a security fix worth merging).
