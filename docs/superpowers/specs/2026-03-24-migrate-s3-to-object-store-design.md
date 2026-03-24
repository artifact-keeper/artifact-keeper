# Migrate S3 Backend from rust-s3 to object_store

**Date:** 2026-03-24
**Issue:** #567 (S3 backend doesn't work with self-signed certificates)
**Scope:** Replace `rust-s3` crate with Apache `object_store` crate in `backend/src/storage/s3.rs`

## Problem

The `rust-s3` 0.37 crate uses `tokio-rustls-tls` which builds its internal reqwest client against `webpki-roots` (Mozilla's CA bundle). Self-signed or internal CA certificates in the system store are ignored. The crate's internal `ClientOptions` and `client()` function are `pub(crate)`, so there is no public API to add root certificates or configure TLS beyond `set_dangereous_config(true, true)` (skip all verification).

`rust-s3` is a single-maintainer project with declining engagement: 11 commits in the past year across two burst windows, 4 open PRs with zero review, known TLS bugs unaddressed since Nov 2025. Upstreaming a fix is not viable on any useful timeline.

## Decision

Replace `rust-s3` with `object_store` (Apache Arrow project). The `object_store` crate provides first-class TLS configuration through `ClientOptions`, including `with_root_certificate(Certificate)` for custom CAs and `with_allow_invalid_certificates(bool)` for skipping verification. It is actively maintained by a multi-contributor Apache project, used in production by crates.io.

## New Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `S3_CA_CERT_PATH` | String (file path) | unset | Path to a PEM file containing one or more CA certificates to trust for S3 connections. Supports bundles. |
| `S3_INSECURE_TLS` | Boolean | `false` | Disable all TLS certificate verification. Log a warning at startup when enabled. For dev/test only. |

Existing S3 env vars (`S3_BUCKET`, `S3_REGION`, `S3_ENDPOINT`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_PREFIX`, `S3_REDIRECT_DOWNLOADS`, `S3_PRESIGN_EXPIRY_SECS`, `S3_PRESIGN_ACCESS_KEY_ID`, `S3_PRESIGN_SECRET_ACCESS_KEY`) remain unchanged.

## Architecture

### What changes

**Single file rewrite:** `backend/src/storage/s3.rs` (1,932 lines today). The `StorageBackend` trait in `mod.rs` and all callers remain unchanged. The `S3Backend` struct continues to implement the same trait with the same public API.

**Dependency swap in `Cargo.toml`:**
- Remove: `rust-s3 = { version = "0.37", default-features = false, features = ["tokio-rustls-tls", "fail-on-err"] }`
- Add: `object_store = { version = "0.13", features = ["aws"] }`

### What stays the same

- `S3Config` struct and `from_env()` (adds two new fields: `ca_cert_path`, `insecure_tls`; adds `with_ca_cert_path()` and `with_insecure_tls()` builder methods for programmatic construction)
- `S3Backend` public API surface (`new`, `from_env`, `list`, `copy`, `size`, `redirect_enabled`, `default_presign_expiry`)
- `StorageBackend` trait implementation (put, get, exists, delete, supports_redirect, get_presigned_url, health_check)
- CloudFront signed URL generation (uses RSA/SHA1 directly, not rust-s3)
- `StoragePathFormat` and Artifactory fallback logic
- Prefix handling (`full_key`, `strip_prefix`)
- All env var names except the two new ones

### Internal type mapping

| Current (rust-s3) | New (object_store) |
|---|---|
| `s3::bucket::Bucket` | `object_store::aws::AmazonS3` |
| `s3::creds::Credentials` | `AmazonS3Builder::with_access_key_id()` / `.with_secret_access_key()` |
| `s3::region::Region` | `AmazonS3Builder::with_region()` / `.with_endpoint()` |
| `s3::error::S3Error` | `object_store::Error` |
| `s3::request::ResponseData` | `object_store::GetResult` / `object_store::PutResult` |
| `bucket.put_object(key, bytes)` | `store.put(&path, payload).await` |
| `bucket.get_object(key)` | `store.get(&path).await?.bytes().await` |
| `bucket.head_object(key)` | `store.head(&path).await` returning `ObjectMeta` |
| `bucket.delete_object(key)` | `store.delete(&path).await` |
| `bucket.list(prefix, None)` | `store.list(Some(&prefix))` (returns `BoxStream<Result<ObjectMeta>>`, collect with `StreamExt::try_collect()`) |
| `bucket.copy_object_internal(src, dest)` | `store.copy(&from, &to).await` |
| `bucket.presign_get(key, expiry, None)` | `store.signed_url(Method::GET, &path, duration).await` (`Signer` trait) |
| `bucket.with_path_style()` | Default behavior (path-style is default in object_store) |
| `S3Error::HttpFailWithBody(404, _)` | `object_store::Error::NotFound { .. }` |

### S3Backend struct (new)

```rust
pub struct S3Backend {
    store: AmazonS3,
    prefix: Option<String>,
    redirect_downloads: bool,
    presign_expiry: Duration,
    cloudfront: Option<CloudFrontConfig>,
    path_format: StoragePathFormat,
    /// Separate AmazonS3 instance with dedicated presign credentials
    signing_store: Option<AmazonS3>,
}
```

### Builder construction (new)

```rust
fn build_store(config: &S3Config) -> Result<AmazonS3> {
    let mut client_opts = ClientOptions::new();

    // Only allow HTTP when the endpoint explicitly uses it (MinIO dev setups)
    if config.endpoint.as_ref().is_some_and(|e| e.starts_with("http://")) {
        client_opts = client_opts.with_allow_http(true);
    }

    // Custom CA certificate
    if let Some(ca_path) = &config.ca_cert_path {
        let pem = std::fs::read(ca_path)
            .map_err(|e| AppError::Config(format!("Failed to read CA cert '{}': {}", ca_path, e)))?;
        let certs = Certificate::from_pem_bundle(&pem)
            .map_err(|e| AppError::Config(format!("Invalid CA cert PEM: {}", e)))?;
        for cert in certs {
            client_opts = client_opts.with_root_certificate(cert);
        }
        tracing::info!(path = %ca_path, "Loaded custom CA certificate(s) for S3");
    }

    // Insecure TLS (skip verification)
    if config.insecure_tls {
        client_opts = client_opts.with_allow_invalid_certificates(true);
        tracing::warn!("S3 TLS certificate verification is DISABLED (S3_INSECURE_TLS=true)");
    }

    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(&config.bucket)
        .with_region(&config.region)
        .with_client_options(client_opts);

    if let Some(endpoint) = &config.endpoint {
        builder = builder.with_endpoint(endpoint);
    }

    // Credentials: S3_ prefixed env vars take precedence, then AWS default chain
    if let (Ok(ak), Ok(sk)) = (
        std::env::var("S3_ACCESS_KEY_ID"),
        std::env::var("S3_SECRET_ACCESS_KEY"),
    ) {
        builder = builder
            .with_access_key_id(&ak)
            .with_secret_access_key(&sk);
    }
    // If S3_ vars not set, AmazonS3Builder falls through to AWS_ACCESS_KEY_ID,
    // instance metadata, IRSA, etc. automatically.

    builder.build().map_err(|e| AppError::Config(format!("Failed to build S3 client: {}", e)))
}
```

### Error handling (new)

The Artifactory fallback logic currently pattern-matches on HTTP status codes from `S3Error::HttpFailWithBody`. With object_store, errors are typed variants of `object_store::Error`:

**get:**
```rust
match store.get(&path).await {
    Ok(result) => Ok(result.bytes().await?),
    Err(object_store::Error::NotFound { .. }) => {
        // Try Artifactory fallback path
        self.try_fallback_get(key, "primary not found").await
    }
    Err(e) => Err(AppError::Storage(format!("Failed to get '{}': {}", key, e))),
}
```

**put:** `object_store::put()` returns `Result<PutResult>`. Non-2xx responses surface as `object_store::Error::Generic` with the status and body in the message. No special status classification needed since object_store already treats non-2xx as errors.

**delete:** S3-backed `delete()` returns `Ok(())` for both successful deletes and non-existent keys (native S3 DELETE behavior). This matches the current `classify_delete_status` which treats both 2xx and 404 as success. No special handling needed.

**exists (head):** `head()` returns `Err(object_store::Error::NotFound { .. })` for missing keys, replacing the current `classify_head_status` / `is_head_not_found_error` string matching. The Artifactory fallback in `exists()` becomes:

```rust
match self.store.head(&path).await {
    Ok(_) => return Ok(true),
    Err(object_store::Error::NotFound { .. }) => {
        // Try Artifactory fallback
        if let Some(fallback_key) = self.try_artifactory_fallback(key) {
            match self.store.head(&fallback_path).await {
                Ok(_) => return Ok(true),
                Err(object_store::Error::NotFound { .. }) => {},
                Err(e) => tracing::warn!(error = %e, "Fallback head failed"),
            }
        }
        Ok(false)
    }
    Err(e) => Err(AppError::Storage(format!("Failed to check existence of '{}': {}", key, e))),
}
```

This is cleaner than the current string-matching on error messages (`contains("404")`, `contains("NoSuchKey")`, `contains("Not Found")`).

### Presigned URLs

object_store's `AmazonS3` implements the `Signer` trait:

```rust
use object_store::signer::Signer;

let url = store.signed_url(http::Method::GET, &path, expires_in).await?;
```

For dedicated signing credentials (`S3_PRESIGN_ACCESS_KEY_ID`), build a second `AmazonS3` instance with those credentials (same as the current `signing_bucket` pattern).

object_store's credential provider auto-refreshes STS/IRSA tokens internally via `TokenCache` with a 5-minute min-TTL strategy. When a credential is requested and its remaining TTL is under 5 minutes, a fresh token is fetched before returning. This covers IRSA (`WebIdentityProvider`), ECS Task credentials, EKS Pod Identity, and EC2 IMDS. The manual "refresh credentials before signing" logic (current lines 716-748) is no longer needed, and the `region`, `bucket_name`, and `use_path_style` fields used only for that refresh path can be removed.

### List (stream collection)

`object_store::list()` returns a `BoxStream<'static, Result<ObjectMeta>>` instead of a collected `Vec`. The `list()` implementation collects the stream into a `Vec` using `futures::StreamExt::try_collect()`. The `futures` crate is already in the workspace dependency tree (transitive through tokio/object_store), but may need an explicit `use futures::TryStreamExt;` import.

### Prefix handling

object_store has a built-in `PrefixStore` wrapper, but it has a known bug (#664: head doesn't strip prefix from returned meta). Instead, keep the existing `full_key()` / `strip_prefix()` helpers which work correctly.

### Health check

```rust
async fn health_check(&self) -> Result<()> {
    match self.store.head(&".health-probe".into()).await {
        Ok(_) => Ok(()),
        Err(object_store::Error::NotFound { .. }) => Ok(()), // Bucket reachable
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("403") || msg.contains("Access Denied") {
                Err(AppError::Storage(format!("S3 health check failed: access denied: {}", e)))
            } else {
                Err(AppError::Storage(format!("S3 health check failed: {}", e)))
            }
        }
    }
}
```

## Testing

### Unit tests (no credentials needed)

All existing unit tests rewritten against object_store types:
- `S3Config` construction and env var parsing (add `ca_cert_path`, `insecure_tls`)
- `full_key` / `strip_prefix` / `try_artifactory_fallback` (unchanged logic)
- Error classification helpers (now match on `object_store::Error` variants)
- Presigned URL source types (unchanged)

### New unit tests

- `test_s3_config_ca_cert_path_from_env` - verify `S3_CA_CERT_PATH` is read
- `test_s3_config_insecure_tls_from_env` - verify `S3_INSECURE_TLS` is read
- `test_s3_config_insecure_tls_default_false` - verify default is secure

### Integration tests (require S3/MinIO)

Existing integration tests continue to work since the `StorageBackend` trait is unchanged.

### E2E tests

Existing `test-maven-s3.sh` in artifact-keeper-test covers S3 storage operations. No new E2E test needed for the migration itself. A separate E2E test for custom CA certs would require a TLS-enabled MinIO, which is out of scope for this change.

## Migration Checklist

1. Add `object_store = { version = "0.13", features = ["aws"] }` to workspace `Cargo.toml`
2. Remove `rust-s3` from workspace `Cargo.toml`
3. Rewrite `backend/src/storage/s3.rs`:
   - Update imports
   - Add `ca_cert_path` and `insecure_tls` to `S3Config`
   - Replace `S3Backend::new()` with `AmazonS3Builder` construction
   - Replace each `StorageBackend` trait method implementation
   - Replace `list()`, `copy()`, `size()` implementations
   - Replace presigned URL generation with `Signer::signed_url()`
   - Keep CloudFront signed URL generation unchanged
   - Keep Artifactory fallback logic, rewrite against `object_store::Error`
   - Rewrite all unit tests
4. Update `.env.example` with `S3_CA_CERT_PATH` and `S3_INSECURE_TLS`
5. Verify: `cargo test --workspace --lib` (all tests pass)
6. Verify: `cargo clippy --workspace` (no warnings)
7. Verify: `cargo fmt --check` (clean)

## Out of Scope

- Migrating GCS or Azure backends to object_store (future work, separate issue)
- Unifying all storage backends behind the object_store trait (future architectural decision)
- Streaming uploads/multipart (AK doesn't use these for S3 today)
- object_store 0.14.0 upgrade when it ships (will resolve reqwest 0.12/0.13 duplication)
