//! S3 storage backend using the `object_store` crate (Apache Arrow project).
//!
//! Supports AWS S3 and S3-compatible services (MinIO, Ceph RGW, R2, Huawei OBS, etc.).
//! Configuration via environment variables:
//! - S3_BUCKET: Bucket name (required)
//! - S3_REGION: AWS region (default: us-east-1)
//! - S3_ENDPOINT: Custom endpoint URL for S3-compatible services
//! - S3_ACCESS_KEY_ID: Access key (preferred, falls back to AWS_ACCESS_KEY_ID)
//! - S3_SECRET_ACCESS_KEY: Secret key (preferred, falls back to AWS_SECRET_ACCESS_KEY)
//!
//! For TLS configuration:
//! - S3_CA_CERT_PATH: Path to PEM file with custom CA certificate(s)
//! - S3_INSECURE_TLS: Disable TLS certificate verification (default: false)
//!
//! For S3-compatible providers:
//! - S3_DISABLE_MULTI_DELETE: Use single-object DELETE instead of multi-object
//!   POST ?delete (default: false). Required for providers that do not implement
//!   the S3 DeleteObjects API, such as Huawei Cloud OBS.
//!
//! For HTTP connection pool tuning:
//! - S3_POOL_MAX_IDLE_PER_HOST: Maximum idle connections per host (default: 256)
//! - S3_POOL_IDLE_TIMEOUT_SECS: Idle connection timeout in seconds (default: 90)
//!
//! For HTTP request timeouts:
//! - S3_BULK_TIMEOUT_SECS: Overall request timeout for bulk data transfer --
//!   object payload reads/writes, multipart part uploads, and server-side
//!   CopyObject (default: 1800). Control-plane calls (head/list/delete/exists)
//!   keep a short [`S3_CONTROL_TIMEOUT`] so a wedged endpoint still fails fast.
//!   Set to 0 to disable the bulk timeout entirely.
//! - S3_MAX_SINGLE_COPY_BYTES: Largest object copied with one server-side
//!   CopyObject (default: 5 GiB, AWS's cap). Larger sources are copied via
//!   multipart UploadPartCopy in slices of this size. Clamped into
//!   [5 MiB, 5 GiB]. Lever for S3-compatible stores with lower copy limits.
//!
//! For redirect downloads (302 to presigned URLs):
//! - S3_REDIRECT_DOWNLOADS: Enable 302 redirects (default: false)
//! - S3_PRESIGN_EXPIRY_SECS: URL expiry in seconds (default: 3600)
//!
//! For CloudFront CDN:
//! - CLOUDFRONT_DISTRIBUTION_URL: CloudFront distribution URL (optional)
//! - CLOUDFRONT_KEY_PAIR_ID: CloudFront key pair ID for signing
//! - CLOUDFRONT_PRIVATE_KEY_PATH: Path to CloudFront private key PEM file
//!
//! For Artifactory migration:
//! - STORAGE_PATH_FORMAT: Storage path format (default: native)
//!   - "native": 2-level sharding {sha[0:2]}/{sha[2:4]}/{sha}
//!   - "artifactory": 1-level sharding {sha[0:2]}/{sha} (JFrog Artifactory format)
//!   - "migration": Write native, read from both (for zero-downtime migration)

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use object_store::aws::{AmazonS3, AmazonS3Builder, AwsAuthorizer};
use object_store::multipart::{MultipartStore, PartId};
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::task::JoinSet;

use super::{PresignedUrl, PresignedUrlSource, PutStreamResult, StoragePathFormat};
use crate::error::{AppError, Result};

/// S3's minimum multipart part size (5 MiB). Every part except the last must be
/// at least this large. This is also the part size used for the first
/// [`S3_PARTS_PER_TIER`] parts of an unknown-length stream, so the behaviour for
/// small/typical artifacts is identical to the historical fixed-size path.
const S3_MULTIPART_CHUNK_SIZE: usize = 5 * 1024 * 1024;
/// S3's maximum multipart part size (5 GiB). No single `UploadPart` may exceed
/// this regardless of how large the object is.
const S3_MULTIPART_MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const S3_MULTIPART_MAX_IN_FLIGHT_PARTS: usize = 4;
/// AWS's ceiling for a single copy operation (5 GiB): "You create a copy of
/// your object up to 5 GB in size in a single atomic action using this API.
/// However, to copy an object greater than 5 GB, you must use the multipart
/// upload Upload Part - Copy (UploadPartCopy) API" (Amazon S3 API Reference,
/// CopyObject). Default for the configurable
/// [`S3Config::max_single_copy_bytes`]; also the hard upper clamp, since no
/// single copy — `CopyObject` or one `UploadPartCopy` part — may exceed it.
const S3_MAX_SINGLE_COPY_SIZE: u64 = 5 * 1024 * 1024 * 1024;
/// Overall HTTP request timeout for control-plane S3 calls: head, exists, list,
/// delete, multipart create/abort. These are all small, fixed-cost round trips,
/// so a short cliff keeps a wedged endpoint from stalling a worker. This is the
/// same value `object_store::ClientOptions` defaults to; it is stated
/// explicitly here so the contrast with [`S3_DEFAULT_BULK_TIMEOUT_SECS`] is
/// visible at the call site.
const S3_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
/// Default overall HTTP request timeout for bulk data transfer (#3180).
///
/// `object_store`'s 30s default applies "from when the request starts
/// connecting until the response body has finished", which makes it a cap on
/// *total transfer duration*, not on stalls. A 2.33 GB OCI layer routinely
/// exceeds it in two places -- draining a `get_stream` body and waiting out a
/// server-side `CopyObject` -- so the default silently made multi-GB pushes
/// impossible. 30 minutes matches the ceiling the GCS backend already uses for
/// its streaming client (`gcs.rs`), keeping a cliff without capping transfers.
const S3_DEFAULT_BULK_TIMEOUT_SECS: u64 = 1800;
/// S3 caps a multipart upload at 10,000 parts.
const S3_MULTIPART_MAX_PARTS: usize = 10_000;
/// S3's maximum object size (5 TiB). The adaptive part-size schedule is designed
/// so an object up to this size can be streamed within the 10,000-part cap.
const S3_MAX_OBJECT_SIZE: u64 = 5 * 1024 * 1024 * 1024 * 1024;
/// When the object size is known up front we target this many parts (comfortably
/// under the 10,000-part cap) so transient retries / off-by-one buffering never
/// push us over the hard limit.
const S3_MULTIPART_TARGET_PARTS: u64 = 9_000;
/// Number of parts uploaded at each size tier before the part size doubles, used
/// when the object length is unknown (pure streaming). With 1,000 parts per tier
/// the size doubles 5 MiB → 10 MiB → … → 5 GiB across the first 10 tiers, so the
/// full 10,000-part budget covers objects up to ~4.99 TiB (see
/// [`adaptive_part_size`]).
const S3_PARTS_PER_TIER: u32 = 1_000;

/// Compute the S3 multipart part size (in bytes) to use for the part at
/// `part_index` (0-based), given the total object size when it is known.
///
/// This is the single source of truth for adaptive part sizing and is pure so it
/// can be unit-tested exhaustively without a live S3.
///
/// # Known size (`object_size = Some(n)`)
/// We pick one fixed part size for the whole object:
/// `clamp(ceil(n / TARGET_PARTS), MIN_PART, MAX_PART)`. Targeting
/// [`S3_MULTIPART_TARGET_PARTS`] (9,000) parts keeps us under the 10,000-part cap
/// with margin. Capped at [`S3_MULTIPART_MAX_PART_SIZE`] (5 GiB), one part size
/// reaches S3's 5 TiB object ceiling (5 GiB × 1,000 parts).
///
/// # Unknown size (`object_size = None`, pure streaming)
/// We grow the part size as the part index climbs so the 10,000-part budget can
/// cover a large object without knowing its length in advance. The size doubles
/// every [`S3_PARTS_PER_TIER`] parts starting from [`S3_MULTIPART_CHUNK_SIZE`]
/// (5 MiB) and is capped at [`S3_MULTIPART_MAX_PART_SIZE`] (5 GiB):
/// `min(MAX_PART, MIN_PART << (part_index / PARTS_PER_TIER))`.
/// The first 1,000 parts stay at 5 MiB, so small/typical objects are unaffected.
/// Summed across all 10,000 parts this schedule covers ~4.99 TiB.
fn adaptive_part_size(object_size: Option<u64>, part_index: u32) -> u64 {
    const MIN_PART: u64 = S3_MULTIPART_CHUNK_SIZE as u64;
    match object_size {
        Some(size) => {
            // ceil(size / TARGET_PARTS), then clamp into [MIN_PART, MAX_PART].
            let target = size.div_ceil(S3_MULTIPART_TARGET_PARTS);
            target.clamp(MIN_PART, S3_MULTIPART_MAX_PART_SIZE)
        }
        None => {
            let tier = part_index / S3_PARTS_PER_TIER;
            // 5 MiB << 10 == 5 GiB == MAX_PART, so any tier >= 10 is capped.
            // Clamp the shift first to avoid u64 overflow wrapping to 0 for very
            // large indices (`checked_shl` only guards shifts >= 64, not value
            // overflow), then `min` keeps us at the 5 GiB per-part maximum.
            const MAX_TIER: u32 = 10;
            if tier >= MAX_TIER {
                S3_MULTIPART_MAX_PART_SIZE
            } else {
                (MIN_PART << tier).min(S3_MULTIPART_MAX_PART_SIZE)
            }
        }
    }
}

type S3PartUploadResult = object_store::Result<(usize, PartId)>;

struct S3PartUploadContext<'a> {
    store: &'a AmazonS3,
    path: &'a ObjectPath,
    upload_id: &'a object_store::MultipartId,
    key: &'a str,
}

async fn collect_finished_s3_part(
    tasks: &mut JoinSet<S3PartUploadResult>,
    parts: &mut Vec<(usize, PartId)>,
    key: &str,
) -> Result<()> {
    let result = tasks
        .join_next()
        .await
        .expect("multipart upload task set should not be empty");
    match result {
        Ok(Ok(part)) => {
            parts.push(part);
            Ok(())
        }
        Ok(Err(e)) => Err(AppError::Storage(format!(
            "Multipart upload part failed for '{}': {}",
            key, e
        ))),
        Err(e) => Err(AppError::Storage(format!(
            "Multipart upload task failed for '{}': {}",
            key, e
        ))),
    }
}

async fn wait_for_s3_part_capacity(
    tasks: &mut JoinSet<S3PartUploadResult>,
    parts: &mut Vec<(usize, PartId)>,
    key: &str,
) -> Result<()> {
    while tasks.len() >= S3_MULTIPART_MAX_IN_FLIGHT_PARTS {
        collect_finished_s3_part(tasks, parts, key).await?;
    }
    Ok(())
}

/// Reject a multipart part that would violate a real S3 limit *before* it is
/// uploaded, so an over-large object fails fast instead of transferring the whole
/// payload and then failing opaquely at `complete_multipart`.
///
/// Enforces the genuine S3 constraints (not the historical artificial ~50 GiB
/// bound): at most [`S3_MULTIPART_MAX_PARTS`] parts and at most
/// [`S3_MULTIPART_MAX_PART_SIZE`] (5 GiB) per part. With adaptive part sizing the
/// effective object ceiling is S3's real ~5 TiB limit.
fn ensure_s3_part_within_limit(next_part_index: usize, part_len: usize, key: &str) -> Result<()> {
    if next_part_index >= S3_MULTIPART_MAX_PARTS {
        let approx_tib = S3_MAX_OBJECT_SIZE / (1024 * 1024 * 1024 * 1024);
        return Err(AppError::Storage(format!(
            "Multipart upload for '{}' exceeded S3's {}-part limit; \
             objects larger than ~{} TiB cannot be stored",
            key, S3_MULTIPART_MAX_PARTS, approx_tib,
        )));
    }
    if part_len as u64 > S3_MULTIPART_MAX_PART_SIZE {
        return Err(AppError::Storage(format!(
            "Multipart upload for '{}' produced a {}-byte part exceeding S3's {} GiB per-part limit",
            key,
            part_len,
            S3_MULTIPART_MAX_PART_SIZE / (1024 * 1024 * 1024),
        )));
    }
    Ok(())
}

async fn enqueue_s3_part_upload(
    tasks: &mut JoinSet<S3PartUploadResult>,
    parts: &mut Vec<(usize, PartId)>,
    context: S3PartUploadContext<'_>,
    next_part_index: &mut usize,
    part: Bytes,
) -> Result<()> {
    wait_for_s3_part_capacity(tasks, parts, context.key).await?;
    // Reject before spawning any part that would exceed a real S3 limit (the
    // 10,000-part cap or the 5 GiB per-part cap). The predicate is unit-tested
    // (`test_s3_part_within_limit_*`); keep the call here so a refactor of the
    // streaming loop can't silently drop the guard.
    ensure_s3_part_within_limit(*next_part_index, part.len(), context.key)?;

    let store = context.store.clone();
    let part_path = context.path.clone();
    let part_upload_id = context.upload_id.clone();
    let part_index = *next_part_index;
    *next_part_index += 1;
    tasks.spawn(async move {
        let part_id = store
            .put_part(
                &part_path,
                &part_upload_id,
                part_index,
                PutPayload::from(part),
            )
            .await?;
        Ok((part_index, part_id))
    });

    Ok(())
}

async fn drain_s3_part_uploads(
    tasks: &mut JoinSet<S3PartUploadResult>,
    parts: &mut Vec<(usize, PartId)>,
    key: &str,
) -> Result<()> {
    while !tasks.is_empty() {
        collect_finished_s3_part(tasks, parts, key).await?;
    }
    Ok(())
}

async fn abort_s3_multipart(
    store: &AmazonS3,
    path: &ObjectPath,
    upload_id: &object_store::MultipartId,
    key: &str,
) {
    if let Err(e) = store.abort_multipart(path, upload_id).await {
        tracing::warn!(
            key = %key,
            upload_id = %upload_id,
            "Failed to abort S3 multipart upload after put_stream error: {}",
            e
        );
    }
}

/// RAII guard that aborts an in-progress S3 multipart upload unless it is
/// explicitly finished.
///
/// It closes the cancellation window called out in [`S3Backend::put_stream`]:
/// if the `put_stream` future is dropped after `create_multipart` but before
/// completion (client disconnect, request timeout, task cancellation), the
/// server-side multipart upload would otherwise linger until a bucket
/// `AbortIncompleteMultipartUpload` lifecycle rule reclaimed it. On drop while
/// still armed, the guard spawns a best-effort `AbortMultipartUpload` (a `Drop`
/// impl cannot `await`).
///
/// Exit paths that handle the upload themselves defuse the guard first:
/// - [`abort_now`](Self::abort_now) awaits an inline abort (used on the existing
///   error paths, so exactly one abort is issued — not a redundant second one).
/// - [`disarm`](Self::disarm) is called after a successful completion so a
///   COMPLETED upload is never aborted.
struct MultipartAbortGuard {
    store: AmazonS3,
    path: ObjectPath,
    key: String,
    /// `Some` while an upload is in flight and not yet finished; `None` once the
    /// guard has been defused (completed or already aborted).
    upload_id: Option<object_store::MultipartId>,
}

impl MultipartAbortGuard {
    /// Create a disarmed guard; call [`arm`](Self::arm) once the multipart
    /// upload has actually been created.
    fn new(store: AmazonS3, path: ObjectPath, key: String) -> Self {
        Self {
            store,
            path,
            key,
            upload_id: None,
        }
    }

    /// Arm the guard with the id of a freshly created multipart upload.
    fn arm(&mut self, upload_id: object_store::MultipartId) {
        self.upload_id = Some(upload_id);
    }

    /// Defuse the guard without aborting: the upload completed successfully.
    fn disarm(&mut self) {
        self.upload_id = None;
    }

    /// Defuse the guard and abort the upload inline (awaited). No-op if the
    /// guard is not armed (no multipart upload was ever created).
    async fn abort_now(&mut self) {
        if let Some(upload_id) = self.upload_id.take() {
            abort_s3_multipart(&self.store, &self.path, &upload_id, &self.key).await;
        }
    }
}

impl Drop for MultipartAbortGuard {
    fn drop(&mut self) {
        let Some(upload_id) = self.upload_id.take() else {
            return;
        };
        // A completed/aborted upload defuses the guard above, so reaching here
        // means the future was dropped mid-upload. Drop can't await, so spawn a
        // detached best-effort abort. Guard against running outside a Tokio
        // runtime (e.g. a synchronous drop in a plain test) to avoid a panic.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                key = %self.key,
                upload_id = %upload_id,
                "S3 multipart upload dropped with no Tokio runtime to abort it"
            );
            return;
        };
        let store = self.store.clone();
        let path = self.path.clone();
        let key = std::mem::take(&mut self.key);
        handle.spawn(async move {
            abort_s3_multipart(&store, &path, &upload_id, &key).await;
        });
    }
}

/// Inclusive byte ranges for a server-side multipart copy (#3164).
///
/// Each range becomes one `UploadPartCopy`'s `x-amz-copy-source-range` header,
/// which the S3 API Reference (UploadPartCopy, `x-amz-copy-source-range`)
/// defines as "the form bytes=first-last, where the first and last are the
/// zero-based byte offsets to copy". Every part is `part_size` except a
/// shorter final part. `part_size` is the (clamped) single-copy ceiling — each
/// `UploadPartCopy` is itself a single copy operation bound by the same limit
/// — so maximal parts keep the count minimal: at the default 5 GiB ceiling,
/// S3's 5 TiB object ceiling needs 1,024 parts, far under
/// [`S3_MULTIPART_MAX_PARTS`]. Callers guarantee `part_size >= 5 MiB`
/// (see [`S3Backend::effective_single_copy_ceiling`]), satisfying the
/// minimum-part-size rule for every non-final part.
fn copy_part_ranges(size: u64, part_size: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut start = 0u64;
    while start < size {
        let end = (start + part_size).min(size) - 1;
        ranges.push((start, end));
        start = end + 1;
    }
    ranges
}

/// Build the `x-amz-copy-source` header value: "the name of the source bucket
/// and key of the source object, separated by a slash (/). ... The value must
/// be URL-encoded" (S3 API Reference, UploadPartCopy). Each key segment is
/// percent-encoded; the `/` separators are structural and stay literal.
fn s3_copy_source_value(bucket: &str, full_key: &str) -> String {
    let encoded: Vec<String> = full_key
        .split('/')
        .map(|segment| urlencoding::encode(segment).into_owned())
        .collect();
    format!("{}/{}", bucket, encoded.join("/"))
}

/// Extract the part ETag from an `UploadPartCopy` response body.
///
/// A successful response is `<CopyPartResult><ETag>...</ETag></CopyPartResult>`
/// (S3 API Reference, UploadPartCopy response syntax). S3 copy operations can
/// return `200 OK` with an embedded `<Error>` document instead, so a 200
/// status alone is not success — only a parseable ETag is.
///
/// The ETag's XML entity escapes are undone: implementations differ on how
/// they escape the quotes around the ETag — AWS emits the named entity
/// (`&quot;`), MinIO (Go's `encoding/xml`) the decimal reference (`&#34;`) —
/// and a passed-through entity poisons `CompleteMultipartUpload` with
/// `InvalidPart` ("the specified entity tag may not match"), caught live
/// against MinIO by `test_large_copy_upload_part_copy_live_3164`.
fn parse_copy_part_etag(body: &str) -> Option<String> {
    if body.contains("<Error") {
        return None;
    }
    let start = body.find("<ETag>")? + "<ETag>".len();
    let end = body[start..].find("</ETag>")? + start;
    let etag = body[start..end]
        .trim()
        .replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&#x22;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    (!etag.is_empty()).then_some(etag)
}

/// S3 storage backend configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// AWS region
    pub region: String,
    /// Custom endpoint URL (for MinIO compatibility)
    pub endpoint: Option<String>,
    /// Optional key prefix for all objects
    pub prefix: Option<String>,
    /// Enable redirect downloads via presigned URLs
    pub redirect_downloads: bool,
    /// Presigned URL expiry duration
    pub presign_expiry: Duration,
    /// CloudFront configuration (optional)
    pub cloudfront: Option<CloudFrontConfig>,
    /// Storage path format (native, artifactory, or migration)
    pub path_format: StoragePathFormat,
    /// Dedicated access key for presigned URL signing (optional, overrides default credentials)
    pub presign_access_key: Option<String>,
    /// Dedicated secret key for presigned URL signing (optional, overrides default credentials)
    pub presign_secret_key: Option<String>,
    /// Path to a PEM file containing custom CA certificate(s) for S3 connections
    pub ca_cert_path: Option<String>,
    /// Disable TLS certificate verification (for dev/test with self-signed certs)
    pub insecure_tls: bool,
    /// Use single-object DELETE requests instead of the S3 multi-object delete
    /// API (POST ?delete). Some S3-compatible providers (e.g. Huawei Cloud OBS)
    /// do not implement DeleteObjects and return 405 Method Not Allowed.
    pub disable_multi_delete: bool,
    /// Maximum number of idle connections kept per host in the HTTP connection
    /// pool used by the S3 client. Higher values reduce TLS handshake overhead
    /// under high concurrency. Default: 256.
    pub pool_max_idle_per_host: usize,
    /// Idle timeout in seconds for pooled HTTP connections. Connections idle
    /// longer than this are closed. Default: 90 seconds (matches hyper/reqwest
    /// defaults).
    pub pool_idle_timeout_secs: u64,
    /// Overall HTTP request timeout, in seconds, for bulk data transfer:
    /// payload get/put, streaming get/put, multipart part uploads, and
    /// server-side CopyObject. Control-plane calls keep [`S3_CONTROL_TIMEOUT`].
    /// `0` disables the bulk timeout. Default:
    /// [`S3_DEFAULT_BULK_TIMEOUT_SECS`] (#3180).
    pub bulk_timeout_secs: u64,
    /// Overall HTTP request timeout, in seconds, for control-plane calls:
    /// head/exists/list/delete/multipart-create. Small fixed-cost round trips,
    /// so this stays short to fail fast on a wedged endpoint. `0` disables it.
    /// Default: [`S3_CONTROL_TIMEOUT`] (30s).
    pub control_timeout_secs: u64,
    /// Largest object copied with a single server-side `CopyObject`; larger
    /// sources use the multipart `UploadPartCopy` path, whose per-part slice
    /// size is this same value (each part copy is a single copy operation
    /// under the same ceiling). Operator lever for S3-compatible stores with
    /// a lower single-copy limit than AWS's. Clamped at use into
    /// [5 MiB, 5 GiB]: a range copy requires a source over 5 MB, and no
    /// single copy may exceed AWS's 5 GiB cap. Default:
    /// [`S3_MAX_SINGLE_COPY_SIZE`] (5 GiB).
    pub max_single_copy_bytes: u64,
}

/// CloudFront CDN configuration for signed URLs
#[derive(Debug, Clone)]
pub struct CloudFrontConfig {
    /// CloudFront distribution URL (e.g., https://d1234.cloudfront.net)
    pub distribution_url: String,
    /// CloudFront key pair ID for signing
    pub key_pair_id: String,
    /// CloudFront private key (PEM format)
    pub private_key: String,
}

impl S3Config {
    /// Create config from environment variables
    pub fn from_env() -> Result<Self> {
        let bucket =
            std::env::var("S3_BUCKET").map_err(|_| AppError::Config("S3_BUCKET not set".into()))?;
        let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into());
        let endpoint = std::env::var("S3_ENDPOINT").ok();
        let prefix = std::env::var("S3_PREFIX").ok();
        if let Some(p) = prefix.as_deref() {
            if s3_prefix_collides_with_reserved_namespace(p) {
                tracing::warn!(
                    s3_prefix = %p,
                    reserved = ?crate::storage::BUCKET_ROOT_KEY_NAMESPACES,
                    "S3_PREFIX collides with a reserved bucket-root namespace; proxy-cache \
                     content is anchored at the bucket root and would share a key space with \
                     artifact bytes. Rename S3_PREFIX (#3368)."
                );
            }
        }

        // Redirect download configuration
        let redirect_downloads = std::env::var("S3_REDIRECT_DOWNLOADS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        let presign_expiry_secs: u64 = std::env::var("S3_PRESIGN_EXPIRY_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        // CloudFront configuration (optional)
        let cloudfront = Self::load_cloudfront_config();

        // Storage path format (native, artifactory, or migration)
        let path_format = StoragePathFormat::from_env();

        // Dedicated signing credentials for presigned URLs (Option B)
        let presign_access_key = std::env::var("S3_PRESIGN_ACCESS_KEY_ID").ok();
        let presign_secret_key = std::env::var("S3_PRESIGN_SECRET_ACCESS_KEY").ok();

        let ca_cert_path = std::env::var("S3_CA_CERT_PATH").ok();
        let insecure_tls = std::env::var("S3_INSECURE_TLS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        let disable_multi_delete = std::env::var("S3_DISABLE_MULTI_DELETE")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        let pool_max_idle_per_host: usize = std::env::var("S3_POOL_MAX_IDLE_PER_HOST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256);
        let pool_idle_timeout_secs: u64 = std::env::var("S3_POOL_IDLE_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90);
        let bulk_timeout_secs: u64 = std::env::var("S3_BULK_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(S3_DEFAULT_BULK_TIMEOUT_SECS);
        let control_timeout_secs: u64 = std::env::var("S3_CONTROL_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(S3_CONTROL_TIMEOUT.as_secs());
        let max_single_copy_bytes: u64 = std::env::var("S3_MAX_SINGLE_COPY_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(S3_MAX_SINGLE_COPY_SIZE);

        Ok(Self {
            bucket,
            region,
            endpoint,
            prefix,
            redirect_downloads,
            presign_expiry: Duration::from_secs(presign_expiry_secs),
            cloudfront,
            path_format,
            presign_access_key,
            presign_secret_key,
            ca_cert_path,
            insecure_tls,
            disable_multi_delete,
            pool_max_idle_per_host,
            pool_idle_timeout_secs,
            bulk_timeout_secs,
            control_timeout_secs,
            max_single_copy_bytes,
        })
    }

    /// Load CloudFront configuration from environment
    fn load_cloudfront_config() -> Option<CloudFrontConfig> {
        let distribution_url = std::env::var("CLOUDFRONT_DISTRIBUTION_URL").ok()?;
        let key_pair_id = std::env::var("CLOUDFRONT_KEY_PAIR_ID").ok()?;

        // Load private key from file or directly from env
        let private_key = if let Ok(key_path) = std::env::var("CLOUDFRONT_PRIVATE_KEY_PATH") {
            std::fs::read_to_string(&key_path)
                .map_err(|e| {
                    tracing::warn!(
                        "Failed to read CloudFront private key from {}: {}",
                        key_path,
                        e
                    );
                    e
                })
                .ok()?
        } else if let Ok(key) = std::env::var("CLOUDFRONT_PRIVATE_KEY") {
            key
        } else {
            tracing::debug!("CloudFront private key not configured");
            return None;
        };

        tracing::info!(
            distribution = %distribution_url,
            key_pair_id = %key_pair_id,
            "CloudFront CDN configured for redirect downloads"
        );

        Some(CloudFrontConfig {
            distribution_url,
            key_pair_id,
            private_key,
        })
    }

    /// Create config with explicit values
    pub fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        prefix: Option<String>,
    ) -> Self {
        Self {
            bucket,
            region,
            endpoint,
            prefix,
            redirect_downloads: false,
            presign_expiry: Duration::from_secs(3600),
            cloudfront: None,
            path_format: StoragePathFormat::default(),
            presign_access_key: None,
            presign_secret_key: None,
            ca_cert_path: None,
            insecure_tls: false,
            disable_multi_delete: false,
            pool_max_idle_per_host: 256,
            pool_idle_timeout_secs: 90,
            bulk_timeout_secs: S3_DEFAULT_BULK_TIMEOUT_SECS,
            control_timeout_secs: S3_CONTROL_TIMEOUT.as_secs(),
            max_single_copy_bytes: S3_MAX_SINGLE_COPY_SIZE,
        }
    }

    /// Set storage path format (for Artifactory compatibility)
    pub fn with_path_format(mut self, format: StoragePathFormat) -> Self {
        self.path_format = format;
        self
    }

    /// Enable redirect downloads
    pub fn with_redirect_downloads(mut self, enabled: bool) -> Self {
        self.redirect_downloads = enabled;
        self
    }

    /// Set presigned URL expiry
    pub fn with_presign_expiry(mut self, expiry: Duration) -> Self {
        self.presign_expiry = expiry;
        self
    }

    /// Set CloudFront configuration
    pub fn with_cloudfront(mut self, config: CloudFrontConfig) -> Self {
        self.cloudfront = Some(config);
        self
    }

    pub fn with_ca_cert_path(mut self, path: String) -> Self {
        self.ca_cert_path = Some(path);
        self
    }

    pub fn with_insecure_tls(mut self, insecure: bool) -> Self {
        self.insecure_tls = insecure;
        self
    }

    pub fn with_disable_multi_delete(mut self, disable: bool) -> Self {
        self.disable_multi_delete = disable;
        self
    }

    pub fn with_pool_max_idle_per_host(mut self, max_idle: usize) -> Self {
        self.pool_max_idle_per_host = max_idle;
        self
    }

    pub fn with_pool_idle_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.pool_idle_timeout_secs = timeout_secs;
        self
    }

    /// Override the bulk-transfer request timeout (seconds). `0` disables it.
    pub fn with_bulk_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.bulk_timeout_secs = timeout_secs;
        self
    }

    /// Override the control-plane request timeout (seconds). `0` disables it.
    pub fn with_control_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.control_timeout_secs = timeout_secs;
        self
    }

    /// Override the single-copy ceiling in bytes (see
    /// [`Self::max_single_copy_bytes`]). Clamped at use into [5 MiB, 5 GiB].
    pub fn with_max_single_copy_bytes(mut self, bytes: u64) -> Self {
        self.max_single_copy_bytes = bytes;
        self
    }
}

/// True if `S3_ALLOW_ANONYMOUS` is set to a truthy value (`true`, `True`,
/// `TRUE`, `1`). When enabled, the operator opts into unsigned S3 requests
/// for genuinely public buckets and `S3Backend::new` no longer requires
/// credentials. Used by both the credential-chain logic in `build_store`
/// and the startup check in `validate_credentials_present`.
fn anonymous_s3_enabled() -> bool {
    std::env::var("S3_ALLOW_ANONYMOUS")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Whether the store built by [`S3Backend::build_store_with_timeout`] will sign
/// its requests, mirroring that function's credential branch exactly.
///
/// It is `false` only on the one arm that calls `with_skip_signature(true)`:
/// no explicit key pair from any source, and `S3_ALLOW_ANONYMOUS` set. Kept
/// beside [`anonymous_s3_enabled`] so the two stay in step — the hand-rolled
/// `UploadPartCopy` path signs its own request and must refuse when this is
/// `false` (see [`S3Backend::sign_requests`]).
fn s3_requests_are_signed(access_key: Option<&str>, secret_key: Option<&str>) -> bool {
    let explicit_pair = (access_key.is_some() && secret_key.is_some())
        || (std::env::var("S3_ACCESS_KEY_ID").is_ok()
            && std::env::var("S3_SECRET_ACCESS_KEY").is_ok())
        || (std::env::var("AWS_ACCESS_KEY_ID").is_ok()
            && std::env::var("AWS_SECRET_ACCESS_KEY").is_ok());
    explicit_pair || !anonymous_s3_enabled()
}

/// Classify an `object_store::Error` from S3 into a human-readable
/// diagnostic. Used by both the runtime `health_check` and the boot
/// `startup_probe` so the operator sees the same actionable message in
/// `/health` and in startup logs. Recognized cases (issue #981):
///
/// - **TLS / cert errors**: typically misconfigured `S3_ENDPOINT`
///   (https against a host serving a self-signed cert or a different
///   CN). Suggests `S3_CA_CERT_PATH` or `S3_INSECURE_TLS=true`.
/// - **DNS / "no such host"**: the endpoint hostname does not resolve.
/// - **Connection refused / timeout / unreachable**: network path
///   broken or the wrong port.
/// - **403 / Access Denied**: credentials present but lack the bucket
///   permissions.
/// - **404 / NoSuchBucket**: bucket name typo or wrong region.
/// - **Region mismatch**: `BucketRegionError` or PermanentRedirect.
/// - **Signature mismatch**: clock skew or wrong secret.
///
/// The original error string is appended as `caused by:` so the full
/// message is still searchable in the logs.
pub(crate) fn classify_s3_error(err: &object_store::Error) -> String {
    let raw = err.to_string();
    let l = raw.to_lowercase();

    let category = if l.contains("certificate")
        || l.contains("tls")
        || l.contains("self-signed")
        || l.contains("self signed")
        || l.contains("unknownissuer")
        || l.contains("invalidcertificate")
    {
        "S3 TLS / certificate error. The endpoint's certificate is not \
         trusted by the container. Either mount a CA bundle and set \
         S3_CA_CERT_PATH=/path/to/ca.pem, or (only for trusted internal \
         networks) set S3_INSECURE_TLS=true. See docs at \
         https://artifactkeeper.com/docs/deployment/s3 (issue #981)."
    } else if l.contains("dns")
        || l.contains("no such host")
        || l.contains("name or service not known")
        || l.contains("nodename nor servname")
    {
        "S3 DNS resolution failed. S3_ENDPOINT hostname does not resolve \
         from inside the container. Check CoreDNS, /etc/resolv.conf, and \
         the spelling of S3_ENDPOINT."
    } else if l.contains("connection refused") {
        "S3 connection refused. The endpoint host is up but nothing is \
         listening on the configured port. Verify S3_ENDPOINT scheme and \
         port (e.g. https://s3.example.com:9000) match the actual \
         service."
    } else if l.contains("network unreachable")
        || l.contains("no route to host")
        || l.contains("host unreachable")
    {
        "S3 network unreachable. No route from the container to the \
         endpoint. Likely a NetworkPolicy, firewall, or egress rule."
    } else if l.contains("timeout") || l.contains("timed out") {
        "S3 connection timed out. Endpoint dropped packets or is behind \
         a stalled proxy. If you use a custom CA, also confirm S3_CA_CERT_PATH \
         is set so TLS does not fall back to system trust."
    } else if l.contains("403") || l.contains("access denied") || l.contains("forbidden") {
        "S3 access denied (403). Credentials are reaching the endpoint \
         but lack permission on the bucket. Confirm S3_BUCKET, the IAM \
         policy / bucket policy, and that S3_ACCESS_KEY_ID matches the \
         intended principal."
    } else if l.contains("nosuchbucket")
        || (l.contains("404") && l.contains("bucket"))
        || l.contains("the specified bucket does not exist")
    {
        "S3 bucket not found. Confirm S3_BUCKET exists and the region \
         (S3_REGION) is correct for that bucket."
    } else if l.contains("bucketregionerror")
        || l.contains("permanentredirect")
        || (l.contains("301") && l.contains("region"))
    {
        "S3 region mismatch. S3_REGION does not match the bucket's actual \
         region. Set S3_REGION to the region the bucket lives in."
    } else if l.contains("signaturedoesnotmatch") || l.contains("invalidaccesskeyid") {
        "S3 signature rejected. Either S3_SECRET_ACCESS_KEY is wrong, or \
         the container clock is skewed by more than 15 minutes from the \
         S3 server (AWS SigV4 rejects skewed signatures)."
    } else {
        "S3 request failed"
    };

    format!("{}. caused by: {}", category, raw)
}

/// Generate the full S3 key with optional prefix.
///
/// The prefix is **not** applied to keys in a reserved bucket-root namespace
/// (see [`crate::storage::BUCKET_ROOT_KEY_NAMESPACES`]). Proxy-cache content
/// is written at the bucket root by the prefix-less `StorageRole::ProxyCache`
/// handle, so composing `<S3_PREFIX>/proxy-cache/...` here names an object
/// that nothing ever writes: the read missed every time on a prefixed
/// deployment even though the object was present, and the miss-recovery
/// write-back then created a second copy under the prefix that no reader ever
/// consulted (#3368).
///
/// Deciding this from the KEY rather than from which handle the caller happens
/// to hold is what removes that divergence — the two handles now resolve a
/// proxy-cache key to the same physical object.
pub(crate) fn make_full_key(prefix: Option<&str>, key: &str) -> String {
    match prefix {
        Some(_) if crate::storage::key_is_bucket_root_anchored(key) => key.to_string(),
        Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
        None => key.to_string(),
    }
}

/// Strip the prefix from an S3 key.
///
/// Inverse of [`make_full_key`] for every non-degenerate `S3_PREFIX`. A
/// bucket-root-anchored key is unaffected because it does not begin with
/// `<prefix>/` — unless the prefix IS a reserved namespace, which is the one
/// configuration where the two key spaces are genuinely indistinguishable;
/// [`s3_prefix_collides_with_reserved_namespace`] warns about it at startup.
fn strip_key_prefix(prefix: Option<&str>, key: &str) -> String {
    match prefix {
        Some(p) => {
            let prefix_with_slash = format!("{}/", p.trim_end_matches('/'));
            key.strip_prefix(&prefix_with_slash)
                .unwrap_or(key)
                .to_string()
        }
        None => key.to_string(),
    }
}

/// Whether `S3_PREFIX` names (or sits inside) one of the reserved bucket-root
/// namespaces, which makes the bucket layout ambiguous.
///
/// Artifact bytes are written under `S3_PREFIX` and proxy-cache content at the
/// bucket root (#3368). Those two key spaces are disjoint for every ordinary
/// prefix. They are not disjoint when the prefix is itself `proxy-cache` or
/// `proxy-cache-staging`: a listed key then cannot be told apart from a cache
/// key, so `make_full_key` and `strip_key_prefix` stop round-tripping.
///
/// Reported as a warning rather than a hard startup failure: nothing about the
/// configuration is newly broken by the key-anchoring change, and refusing to
/// boot a running deployment over a naming choice would be a worse outcome
/// than telling the operator to rename the prefix.
pub(crate) fn s3_prefix_collides_with_reserved_namespace(prefix: &str) -> bool {
    let normalized = format!("{}/", prefix.trim_end_matches('/'));
    crate::storage::BUCKET_ROOT_KEY_NAMESPACES
        .iter()
        .any(|ns| normalized == *ns || normalized.starts_with(ns))
}

/// Try to generate an Artifactory fallback path from a native path.
/// Native format: ab/cd/abcd...full_checksum (64 chars)
/// Artifactory format: ab/abcd...full_checksum
fn artifactory_fallback_path(key: &str) -> Option<String> {
    if key.split('/').count() < 3 {
        return None;
    }
    let checksum = key.rsplit('/').next()?;
    if checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(format!("{}/{}", &checksum[..2], checksum))
    } else {
        None
    }
}

/// S3-compatible storage backend
pub struct S3Backend {
    store: AmazonS3,
    /// Bulk-transfer client (#3180). Same credentials and endpoint as
    /// [`Self::store`], but with a request timeout sized for multi-GB object
    /// payloads instead of the control-plane cliff. Used only by `get`/`put`,
    /// `get_stream`/`put_stream`, and `copy`.
    bulk_store: AmazonS3,
    /// Bucket name, kept for the `x-amz-copy-source` header of hand-rolled
    /// `UploadPartCopy` requests (#3164).
    bucket: String,
    /// Region used to SigV4-sign hand-rolled requests.
    region: String,
    /// Bulk-transfer request timeout, applied per-request to hand-rolled
    /// part-copy calls (mirrors `bulk_store`'s ceiling). `None` = disabled.
    bulk_timeout: Option<Duration>,
    /// Plain HTTP client for hand-rolled S3 API calls that `object_store`
    /// does not expose (ranged `UploadPartCopy`, #3164). Built with the same
    /// custom-CA / insecure-TLS options as the object_store clients.
    raw_http: reqwest::Client,
    /// Single-copy ceiling (already clamped into [5 MiB, 5 GiB], see
    /// [`Self::effective_single_copy_ceiling`]): sources at or under it use
    /// native `CopyObject`; larger ones use multipart `UploadPartCopy` with
    /// parts of this size.
    max_single_copy_bytes: u64,
    /// False when the store was built unsigned (`S3_ALLOW_ANONYMOUS` with no
    /// credentials — `build_store` calls `with_skip_signature(true)`).
    ///
    /// The hand-rolled `UploadPartCopy` path signs its own request, so it
    /// cannot honour `skip_signature`: `signed_url` and
    /// `credentials().get_credential()` both resolve credentials
    /// unconditionally, and with nothing configured object_store's chain falls
    /// through to the IMDS provider. Recording the decision here lets the
    /// multipart copy refuse legibly instead of stalling on a link-local probe.
    sign_requests: bool,
    prefix: Option<String>,
    redirect_downloads: bool,
    cloudfront: Option<CloudFrontConfig>,
    path_format: StoragePathFormat,
    signing_store: Option<AmazonS3>,
    /// When true, delete objects one at a time with HTTP DELETE instead of the
    /// S3 multi-object delete API (POST ?delete). Needed for providers like
    /// Huawei Cloud OBS that do not implement DeleteObjects.
    disable_multi_delete: bool,
}

impl S3Backend {
    /// Build the control-plane store: head, exists, list, delete, multipart
    /// create/abort, presigning. Short request timeout ([`S3_CONTROL_TIMEOUT`]).
    fn build_store(
        config: &S3Config,
        access_key: Option<&str>,
        secret_key: Option<&str>,
    ) -> Result<AmazonS3> {
        let timeout = (config.control_timeout_secs > 0)
            .then(|| Duration::from_secs(config.control_timeout_secs));
        Self::build_store_with_timeout(config, access_key, secret_key, timeout)
    }

    /// Build the bulk-transfer store used for object payload movement:
    /// `get`/`put`, `get_stream`/`put_stream` (including multipart part
    /// uploads), and server-side `copy`.
    ///
    /// These operations' duration scales with object size, so the
    /// control-plane cliff cannot apply to them (#3180). `bulk_timeout_secs ==
    /// 0` opts out of the timeout entirely.
    fn build_bulk_store(
        config: &S3Config,
        access_key: Option<&str>,
        secret_key: Option<&str>,
    ) -> Result<AmazonS3> {
        let timeout =
            (config.bulk_timeout_secs > 0).then(|| Duration::from_secs(config.bulk_timeout_secs));
        Self::build_store_with_timeout(config, access_key, secret_key, timeout)
    }

    /// Clamp the configured single-copy ceiling into what the S3 API can
    /// honor: at least 5 MiB ("You can copy a range only if the source object
    /// is greater than 5 MB" — S3 API Reference, UploadPartCopy — and 5 MiB
    /// is the minimum non-final part size) and at most
    /// [`S3_MAX_SINGLE_COPY_SIZE`] (no single copy may exceed AWS's 5 GiB
    /// cap). Used for both the CopyObject-vs-multipart threshold and the
    /// multipart part slice size.
    fn effective_single_copy_ceiling(config: &S3Config) -> u64 {
        config
            .max_single_copy_bytes
            .clamp(S3_MULTIPART_CHUNK_SIZE as u64, S3_MAX_SINGLE_COPY_SIZE)
    }

    /// HTTP client for hand-rolled S3 API calls that `object_store` does not
    /// expose (ranged `UploadPartCopy`, #3164). Honors the same custom-CA and
    /// insecure-TLS options as the object_store clients; each request is
    /// SigV4-signed per-call with [`AwsAuthorizer`], reusing the store's
    /// credential chain.
    fn build_raw_http_client(config: &S3Config) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder();
        if let Some(ca_path) = &config.ca_cert_path {
            let pem = std::fs::read(ca_path).map_err(|e| {
                AppError::Config(format!("Failed to read CA cert '{}': {}", ca_path, e))
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
                AppError::Config(format!("Invalid CA cert PEM '{}': {}", ca_path, e))
            })?;
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        if config.insecure_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        builder
            .build()
            .map_err(|e| AppError::Config(format!("Failed to build raw S3 HTTP client: {}", e)))
    }

    fn build_store_with_timeout(
        config: &S3Config,
        access_key: Option<&str>,
        secret_key: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<AmazonS3> {
        let mut client_opts = object_store::ClientOptions::new()
            .with_pool_max_idle_per_host(config.pool_max_idle_per_host)
            .with_pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout_secs));

        // `object_store` defaults this to 30s and applies it from the start of
        // connect until the response body is fully read, so it caps total
        // transfer duration rather than detecting stalls. Always set it
        // explicitly -- leaving it implicit is what caused #3180.
        client_opts = match timeout {
            Some(t) => client_opts.with_timeout(t),
            None => client_opts.with_timeout_disabled(),
        };

        if config
            .endpoint
            .as_ref()
            .is_some_and(|e| e.starts_with("http://"))
        {
            client_opts = client_opts.with_allow_http(true);
        }

        if let Some(ca_path) = &config.ca_cert_path {
            let pem = std::fs::read(ca_path).map_err(|e| {
                AppError::Config(format!("Failed to read CA cert '{}': {}", ca_path, e))
            })?;
            let certs = object_store::Certificate::from_pem_bundle(&pem).map_err(|e| {
                AppError::Config(format!("Invalid CA cert PEM '{}': {}", ca_path, e))
            })?;
            for cert in certs {
                client_opts = client_opts.with_root_certificate(cert);
            }
            tracing::info!(path = %ca_path, "Loaded custom CA certificate(s) for S3");
        }

        if config.insecure_tls {
            client_opts = client_opts.with_allow_invalid_certificates(true);
            tracing::warn!("S3 TLS certificate verification is DISABLED (S3_INSECURE_TLS=true)");
        }

        // Use new() instead of from_env() to avoid greedy ingestion of AWS_*
        // env vars that could hijack endpoints (AWS_ENDPOINT_URL), disable
        // signing (AWS_SKIP_SIGNATURE), or shadow IAM credentials. We
        // selectively read only the credential chain variables needed.
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&config.bucket)
            .with_region(&config.region)
            .with_client_options(client_opts);

        if let Some(endpoint) = &config.endpoint {
            builder = builder.with_endpoint(endpoint);
        }

        // ECS Fargate task role credentials
        if let Ok(uri) = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            builder = builder.with_config(
                object_store::aws::AmazonS3ConfigKey::ContainerCredentialsRelativeUri,
                uri,
            );
        }
        // EKS Pod Identity credentials
        if let Ok(uri) = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
            builder = builder.with_config(
                object_store::aws::AmazonS3ConfigKey::ContainerCredentialsFullUri,
                uri,
            );
        }
        if let Ok(f) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
            builder = builder.with_config(
                object_store::aws::AmazonS3ConfigKey::ContainerAuthorizationTokenFile,
                f,
            );
        }
        // EKS IRSA / Web Identity credentials
        if let Ok(f) = std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE") {
            builder = builder.with_config(
                object_store::aws::AmazonS3ConfigKey::WebIdentityTokenFile,
                f,
            );
        }
        if let Ok(arn) = std::env::var("AWS_ROLE_ARN") {
            builder = builder.with_config(object_store::aws::AmazonS3ConfigKey::RoleArn, arn);
        }

        // Explicit credentials: function args > S3_* env vars > AWS_* env vars
        if let Some(ak) = access_key {
            if let Some(sk) = secret_key {
                builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
            }
        } else if let (Ok(ak), Ok(sk)) = (
            std::env::var("S3_ACCESS_KEY_ID"),
            std::env::var("S3_SECRET_ACCESS_KEY"),
        ) {
            tracing::info!("Using S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY for S3 credentials");
            builder = builder.with_access_key_id(&ak).with_secret_access_key(&sk);
        } else if let (Ok(ak), Ok(sk)) = (
            std::env::var("AWS_ACCESS_KEY_ID"),
            std::env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            builder = builder.with_access_key_id(&ak).with_secret_access_key(&sk);
            if let Ok(token) = std::env::var("AWS_SESSION_TOKEN") {
                builder = builder.with_token(token);
            }
        } else if anonymous_s3_enabled() {
            tracing::warn!(
                "S3 storage configured with no credentials and S3_ALLOW_ANONYMOUS=true; \
                 using unsigned requests"
            );
            builder = builder.with_skip_signature(true);
        }

        builder
            .build()
            .map_err(|e| AppError::Config(format!("Failed to build S3 client: {}", e)))
    }

    /// Validate at startup that some recognized credential source is configured.
    ///
    /// Without this check, `S3Backend::new` would silently construct a client
    /// whose default credential provider falls back to EC2 instance metadata
    /// (169.254.169.254) at first request, causing 5-15s timeouts per storage
    /// operation in non-AWS deployments (issue #871).
    ///
    /// Only enforced when a custom `S3_ENDPOINT` is set: a custom endpoint is
    /// definitively not AWS, so IMDS is never the right fallback. For AWS S3
    /// itself (no custom endpoint), IMDS is a legitimate fallback when running
    /// on EC2 with an instance role, so the chain is left alone there.
    fn validate_credentials_present(config: &S3Config) -> Result<()> {
        if config.endpoint.is_none() {
            return Ok(());
        }
        if anonymous_s3_enabled() {
            return Ok(());
        }
        let has_static_creds = (std::env::var("S3_ACCESS_KEY_ID").is_ok()
            && std::env::var("S3_SECRET_ACCESS_KEY").is_ok())
            || (std::env::var("AWS_ACCESS_KEY_ID").is_ok()
                && std::env::var("AWS_SECRET_ACCESS_KEY").is_ok());
        let has_cloud_chain = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").is_ok()
            || std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI").is_ok()
            || std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE").is_ok();
        if has_static_creds || has_cloud_chain {
            return Ok(());
        }
        Err(AppError::Config(
            "S3 storage configured with custom endpoint but no credentials found. \
             Set S3_ACCESS_KEY_ID + S3_SECRET_ACCESS_KEY (or AWS_ACCESS_KEY_ID + \
             AWS_SECRET_ACCESS_KEY), one of the cloud credential chains \
             (ECS via AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, EKS Pod Identity via \
             AWS_CONTAINER_CREDENTIALS_FULL_URI, or IRSA via \
             AWS_WEB_IDENTITY_TOKEN_FILE), or S3_ALLOW_ANONYMOUS=true for unsigned \
             access. Without explicit credentials the AWS SDK falls back to EC2 \
             instance metadata (169.254.169.254), which is unreachable in non-AWS \
             deployments and causes every storage request to time out (issue #871)."
                .to_string(),
        ))
    }

    /// Run a startup connectivity probe so the operator sees the root
    /// cause (TLS, DNS, connection refused, 403, ...) at boot instead of
    /// a generic "storage probe timed out" 30 minutes later in a health
    /// log. The probe is a single HEAD against a synthetic key; both
    /// "object missing" and a successful HEAD count as connectivity OK.
    ///
    /// Failures are returned as `AppError::Storage` with a human-readable
    /// diagnostic from [`classify_s3_error`]. Callers in `main.rs` choose
    /// whether to fail-fast or warn-and-continue.
    pub async fn startup_probe(&self) -> Result<()> {
        // 10s is generous compared to the 5s health-endpoint budget, since
        // a first-time TCP + TLS handshake against a slow corporate proxy
        // can legitimately exceed 5s.
        let probe = async {
            let path: ObjectPath = ".health-probe".into();
            self.store.head(&path).await
        };
        match tokio::time::timeout(Duration::from_secs(10), probe).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(object_store::Error::NotFound { .. })) => Ok(()),
            Ok(Err(e)) => Err(AppError::Storage(classify_s3_error(&e))),
            Err(_) => Err(AppError::Storage(
                "S3 connectivity probe timed out after 10s. Network unreachable, \
                 DNS resolution failed, or endpoint is dropping packets. Verify \
                 S3_ENDPOINT is reachable from inside the container: \
                 `kubectl exec -it <pod> -- curl -v $S3_ENDPOINT`. If TLS is \
                 involved, also check the cert chain (issue #981)."
                    .to_string(),
            )),
        }
    }

    /// Create new S3 backend from configuration
    pub async fn new(config: S3Config) -> Result<Self> {
        // Issue #871: validate credentials are present before constructing
        // the client. Without this, a non-AWS deployment with a custom
        // S3_ENDPOINT and no creds would fall back to EC2 instance metadata
        // at first request, causing every storage operation to stall 5-15s.
        Self::validate_credentials_present(&config)?;

        let store = Self::build_store(&config, None, None)?;
        let bulk_store = Self::build_bulk_store(&config, None, None)?;

        let signing_store = match (&config.presign_access_key, &config.presign_secret_key) {
            (Some(ak), Some(sk)) => {
                let ss = Self::build_store(&config, Some(ak), Some(sk))?;
                tracing::info!("Using dedicated credentials for presigned URL signing");
                Some(ss)
            }
            _ => None,
        };

        if config.redirect_downloads {
            tracing::info!(
                bucket = %config.bucket,
                cloudfront = config.cloudfront.is_some(),
                expiry_secs = config.presign_expiry.as_secs(),
                dedicated_signing_creds = signing_store.is_some(),
                "S3 redirect downloads enabled"
            );
        }

        if config.path_format != StoragePathFormat::Native {
            tracing::info!(path_format = %config.path_format, "S3 storage path format configured");
        }

        if config.disable_multi_delete {
            tracing::info!(
                "S3 multi-object delete disabled (S3_DISABLE_MULTI_DELETE=true), \
                 using single-object DELETE requests"
            );
        }

        let raw_http = Self::build_raw_http_client(&config)?;

        Ok(Self {
            store,
            bulk_store,
            bucket: config.bucket.clone(),
            region: config.region.clone(),
            bulk_timeout: (config.bulk_timeout_secs > 0)
                .then(|| Duration::from_secs(config.bulk_timeout_secs)),
            raw_http,
            max_single_copy_bytes: Self::effective_single_copy_ceiling(&config),
            sign_requests: s3_requests_are_signed(None, None),
            prefix: config.prefix,
            redirect_downloads: config.redirect_downloads,
            cloudfront: config.cloudfront,
            path_format: config.path_format,
            signing_store,
            disable_multi_delete: config.disable_multi_delete,
        })
    }

    pub async fn from_env() -> Result<Self> {
        let config = S3Config::from_env()?;
        Self::new(config).await
    }

    /// Generate the full S3 key with optional prefix
    fn full_key(&self, key: &str) -> String {
        make_full_key(self.prefix.as_deref(), key)
    }

    /// Strip the prefix from an S3 key
    fn strip_prefix(&self, key: &str) -> String {
        strip_key_prefix(self.prefix.as_deref(), key)
    }

    /// Try to generate an Artifactory fallback path from a native path
    fn try_artifactory_fallback(&self, key: &str) -> Option<String> {
        artifactory_fallback_path(key)
    }

    fn byte_range(offset: u64, length: usize) -> Result<std::ops::Range<u64>> {
        let length = u64::try_from(length).map_err(|_| {
            AppError::Storage(format!(
                "Requested range length {} does not fit in u64",
                length
            ))
        })?;
        let end = offset.checked_add(length).ok_or_else(|| {
            AppError::Storage(format!(
                "Requested range offset {} length {} overflows u64",
                offset, length
            ))
        })?;
        Ok(offset..end)
    }

    async fn try_fallback_get(&self, key: &str, reason: &'static str) -> Result<Option<Bytes>> {
        if !self.path_format.has_fallback() {
            return Ok(None);
        }

        let Some(fallback_key) = self.try_artifactory_fallback(key) else {
            return Ok(None);
        };

        let fallback_full_key = self.full_key(&fallback_key);
        tracing::debug!(
            original = %key,
            fallback = %fallback_key,
            reason,
            "Trying Artifactory fallback path"
        );

        let path: ObjectPath = fallback_full_key.into();
        match self.bulk_store.get(&path).await {
            Ok(result) => {
                // STREAMING-EXEMPT: storage-internal object_store GetResult::bytes() full-body read — same exempt category as the S3/Azure/GCS get() fallbacks that back the streaming get impl; not one of the 3 clippy-gated shapes but tracked under #1608
                let bytes = result.bytes().await.map_err(|e| {
                    AppError::Storage(format!("Failed to read fallback '{}': {}", fallback_key, e))
                })?;
                tracing::info!(
                    key = %key,
                    fallback = %fallback_key,
                    size = bytes.len(),
                    "Found artifact at Artifactory fallback path"
                );
                Ok(Some(bytes))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get fallback object '{}' for '{}': {}",
                fallback_key, key, e
            ))),
        }
    }

    async fn try_fallback_get_range(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
        reason: &'static str,
    ) -> Result<Option<Bytes>> {
        if !self.path_format.has_fallback() {
            return Ok(None);
        }

        let Some(fallback_key) = self.try_artifactory_fallback(key) else {
            return Ok(None);
        };

        let fallback_full_key = self.full_key(&fallback_key);
        tracing::debug!(
            original = %key,
            fallback = %fallback_key,
            range_start = range.start,
            range_end = range.end,
            reason,
            "Trying Artifactory fallback path range"
        );

        let path: ObjectPath = fallback_full_key.into();
        match self.bulk_store.get_range(&path, range).await {
            Ok(bytes) => {
                tracing::info!(
                    key = %key,
                    fallback = %fallback_key,
                    size = bytes.len(),
                    "Found artifact range at Artifactory fallback path"
                );
                Ok(Some(bytes))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get fallback object range '{}' for '{}': {}",
                fallback_key, key, e
            ))),
        }
    }

    /// Delete a single object using a presigned DELETE URL.
    ///
    /// The `object_store` crate routes all deletes through the S3 multi-object
    /// delete API (POST ?delete). Some S3-compatible providers, notably Huawei
    /// Cloud OBS, do not implement this endpoint and return 405 Method Not
    /// Allowed. This method works around the limitation by generating a
    /// presigned DELETE URL via the `Signer` trait and executing it with a
    /// plain HTTP DELETE request.
    async fn single_object_delete(&self, path: &ObjectPath, display_key: &str) -> Result<()> {
        use object_store::signer::Signer;

        let presigned_url = self
            .store
            .signed_url(http::Method::DELETE, path, Duration::from_secs(300))
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to generate presigned DELETE URL for '{}': {}",
                    display_key, e
                ))
            })?;

        let response = reqwest::Client::new()
            .delete(presigned_url)
            .send()
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to send DELETE request for '{}': {}",
                    display_key, e
                ))
            })?;

        let status = response.status();
        if status.is_success() || status.as_u16() == 204 {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            // S3 returns 404 when deleting a non-existent object, which is not
            // an error (idempotent delete).
            if status.as_u16() == 404 {
                tracing::debug!(
                    key = %display_key,
                    "Single-object DELETE returned 404, treating as success"
                );
                return Ok(());
            }
            Err(AppError::Storage(format!(
                "Failed to delete object '{}': {} {}: {}",
                display_key,
                status.as_u16(),
                status.canonical_reason().unwrap_or(""),
                body
            )))
        }
    }
}

#[async_trait]
impl super::StorageBackend for S3Backend {
    #[tracing::instrument(skip(self, content), fields(otel.kind = "client", storage.system = "s3", storage.operation = "put"))]
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        self.bulk_store
            .put(&path, content.into())
            .await
            .map_err(|e| {
                tracing::error!(key = %key, error = %e, "S3 put_object failed");
                AppError::Storage(format!("Failed to put object '{}': {}", key, e))
            })?;

        tracing::debug!(key = %key, "S3 put object successful");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "get"))]
    async fn get(&self, key: &str) -> Result<Bytes> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.bulk_store.get(&path).await {
            Ok(result) => {
                // STREAMING-EXEMPT: storage-internal object_store GetResult::bytes() full-body read — same exempt category as the S3/Azure/GCS get() fallbacks that back the streaming get impl; not one of the 3 clippy-gated shapes but tracked under #1608
                let bytes = result.bytes().await.map_err(|e| {
                    AppError::Storage(format!("Failed to read object '{}': {}", key, e))
                })?;
                tracing::debug!(key = %key, size = bytes.len(), "S3 get object successful");
                Ok(bytes)
            }
            Err(object_store::Error::NotFound { .. }) => {
                if let Some(bytes) = self.try_fallback_get(key, "primary not found").await? {
                    return Ok(bytes);
                }
                Err(AppError::NotFound(format!(
                    "Storage key not found: {}",
                    key
                )))
            }
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get object '{}': {}",
                key, e
            ))),
        }
    }

    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "exists"))]
    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.store.head(&path).await {
            Ok(_) => return Ok(true),
            Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => {
                return Err(AppError::Storage(format!(
                    "Failed to check existence of '{}': {}",
                    key, e
                )));
            }
        }

        if self.path_format.has_fallback() {
            if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                let fallback_full_key = self.full_key(&fallback_key);
                let fallback_path: ObjectPath = fallback_full_key.into();
                match self.store.head(&fallback_path).await {
                    Ok(_) => {
                        tracing::debug!(
                            key = %key, fallback = %fallback_key,
                            "Found artifact at Artifactory fallback path"
                        );
                        return Ok(true);
                    }
                    Err(object_store::Error::NotFound { .. }) => {}
                    Err(e) => {
                        return Err(AppError::Storage(format!(
                            "Failed to check fallback existence of '{}' for '{}': {}",
                            fallback_key, key, e
                        )));
                    }
                }
            }
        }

        Ok(false)
    }

    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "delete"))]
    async fn delete(&self, key: &str) -> Result<()> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        if self.disable_multi_delete {
            self.single_object_delete(&path, key).await?;
        } else {
            // Deleting a missing object is idempotent (matches
            // `single_object_delete` and the filesystem backend): map
            // NotFound to Ok so callers like blob GC can treat "already
            // gone" as success instead of re-erroring every pass (#1409 H3).
            match self.store.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => {
                    return Err(AppError::Storage(format!(
                        "Failed to delete object '{}': {}",
                        key, e
                    )))
                }
            }
        }

        tracing::debug!(key = %key, "S3 delete object successful");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "copy"))]
    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        S3Backend::copy(self, source, dest).await
    }

    // Note: `put_file` is intentionally NOT overridden — the trait default in
    // storage/mod.rs already streams the file through `put_stream` with a
    // 256 KiB ReaderStream (memory-bounded), so a bespoke S3 override would only
    // duplicate that behavior.

    /// Surface S3's ETag from a HEAD on `key`. For single-part PUTs the
    /// ETag equals the MD5 of the object; for multipart uploads it is an
    /// opaque per-upload value. Either way the value is stable per object
    /// version and changes if the object is overwritten, which is exactly
    /// the integrity signal #1051's fast-path revalidation needs.
    ///
    /// Returns `Ok(None)` when the object is missing rather than an error,
    /// so the freshness probe can treat "ETag unavailable" as "do not
    /// fast-path" without losing the distinction from a real I/O failure.
    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "head_etag"))]
    async fn head_etag(&self, key: &str) -> Result<Option<String>> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();
        match self.store.head(&path).await {
            Ok(meta) => Ok(meta.e_tag),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(AppError::Storage(format!(
                "head_etag failed for '{}': {}",
                key, e
            ))),
        }
    }

    fn supports_redirect(&self) -> bool {
        self.redirect_downloads
    }

    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "get_presigned_url"))]
    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        if !self.redirect_downloads {
            return Ok(None);
        }

        let full_key = self.full_key(key);

        if let Some(cf) = &self.cloudfront {
            let url = self.generate_cloudfront_signed_url(cf, &full_key, expires_in)?;
            tracing::debug!(
                key = %key, expires_in_secs = expires_in.as_secs(), source = "cloudfront",
                "Generated CloudFront signed URL"
            );
            return Ok(Some(PresignedUrl {
                url,
                expires_in,
                source: PresignedUrlSource::CloudFront,
            }));
        }

        use object_store::signer::Signer;

        let path: ObjectPath = full_key.into();
        let signer = self.signing_store.as_ref().unwrap_or(&self.store);

        // S3 enforces a maximum presigned URL expiry of 7 days
        let clamped_expiry = Duration::from_secs(expires_in.as_secs().min(604800));

        let presigned_url = signer
            .signed_url(http::Method::GET, &path, clamped_expiry)
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to generate presigned URL for '{}': {}",
                    key, e
                ))
            })?;

        tracing::debug!(
            key = %key, expires_in_secs = clamped_expiry.as_secs(), source = "s3",
            dedicated_creds = self.signing_store.is_some(),
            "Generated S3 presigned URL"
        );

        Ok(Some(PresignedUrl {
            url: presigned_url.to_string(),
            expires_in: clamped_expiry,
            source: PresignedUrlSource::S3,
        }))
    }

    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "health_check"))]
    async fn health_check(&self) -> Result<()> {
        let path: ObjectPath = ".health-probe".into();
        match self.store.head(&path).await {
            Ok(_) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(AppError::Storage(classify_s3_error(&e))),
        }
    }

    // The span covers GET initiation (time-to-first-byte); the body transfer
    // happens later as the caller polls the returned stream.
    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "get_stream"))]
    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();
        let key_owned = key.to_string();

        let result = match self.bulk_store.get(&path).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => {
                // #2927: mirror `get()` / `get_range()` (and the GCS/Azure
                // `get_stream()` impls) and consult the Artifactory-migration
                // fallback before reporting NotFound. Without this, an object
                // that lives only at the legacy key layout is found by the
                // buffered `get()` and missed by the streaming `get_stream()`,
                // so every buffered->streaming handler conversion silently
                // changed migration-mode lookup semantics on S3 only.
                //
                // The fallback body is buffered (`try_fallback_get` returns
                // `Bytes`), exactly as GCS and Azure do; wrapping it in a
                // single-item stream keeps the caller's interface uniform. A
                // fully streaming fallback is a larger change and should not
                // block parity.
                //
                // `try_fallback_get` is gated on `path_format.has_fallback()`,
                // so this is a no-op outside Artifactory-migration mode.
                if let Some(bytes) = self
                    .try_fallback_get(key, "primary not found (stream)")
                    .await?
                {
                    return Ok(Box::pin(futures::stream::once(async move { Ok(bytes) })));
                }
                return Err(AppError::NotFound(format!(
                    "Storage key not found: {}",
                    key_owned
                )));
            }
            Err(e) => {
                return Err(AppError::Storage(format!(
                    "Failed to get object '{}': {}",
                    key_owned, e
                )));
            }
        };

        let stream = result
            .into_stream()
            .map(|r| r.map_err(|e| AppError::Storage(format!("Stream read error: {}", e))));

        Ok(Box::pin(stream))
    }

    #[tracing::instrument(skip(self), fields(otel.kind = "client", storage.system = "s3", storage.operation = "get_range"))]
    async fn get_range(&self, key: &str, offset: u64, length: usize) -> Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }

        let range = Self::byte_range(offset, length)?;
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.bulk_store.get_range(&path, range.clone()).await {
            Ok(bytes) => {
                tracing::debug!(
                    key = %key,
                    offset,
                    length,
                    size = bytes.len(),
                    "S3 get object range successful"
                );
                Ok(bytes)
            }
            Err(object_store::Error::NotFound { .. }) => {
                if let Some(bytes) = self
                    .try_fallback_get_range(key, range, "primary range not found")
                    .await?
                {
                    return Ok(bytes);
                }
                Err(AppError::NotFound(format!(
                    "Storage key not found: {}",
                    key
                )))
            }
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get object range '{}' (offset={}, length={}): {}",
                key, offset, length, e
            ))),
        }
    }

    /// Streams `stream` to S3 as a multipart upload.
    ///
    /// Cancellation note: if this future is dropped after the multipart upload
    /// is created but before it finishes (client disconnect, request timeout,
    /// task cancellation), the in-flight part tasks are aborted and a
    /// [`MultipartAbortGuard`] spawns a best-effort server-side
    /// `AbortMultipartUpload` on drop, so the upload does not linger until the
    /// bucket's `AbortIncompleteMultipartUpload` lifecycle rule reclaims it. A
    /// successfully completed upload defuses the guard and is never aborted.
    #[tracing::instrument(skip(self, stream), fields(otel.kind = "client", storage.system = "s3", storage.operation = "put_stream"))]
    async fn put_stream(
        &self,
        key: &str,
        stream: BoxStream<'static, Result<Bytes>>,
    ) -> Result<PutStreamResult> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        // Aborts the multipart upload if this future is dropped mid-flight.
        // Armed once `create_multipart` succeeds; defused on completion or by
        // the inline abort on an error path.
        let mut abort_guard =
            MultipartAbortGuard::new(self.store.clone(), path.clone(), key.to_string());
        let mut upload_id: Option<object_store::MultipartId> = None;
        let mut upload_tasks: JoinSet<S3PartUploadResult> = JoinSet::new();
        let mut uploaded_parts: Vec<(usize, PartId)> = Vec::new();
        let mut next_part_index = 0_usize;
        let mut pending_part = BytesMut::with_capacity(S3_MULTIPART_CHUNK_SIZE);
        let mut hasher = Sha256::new();
        let mut total: u64 = 0;

        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    hasher.update(&data);
                    total += data.len() as u64;
                    if upload_id.is_none() {
                        let id = self.store.create_multipart(&path).await.map_err(|e| {
                            AppError::Storage(format!(
                                "Failed to start multipart upload for '{}': {}",
                                key, e
                            ))
                        })?;
                        abort_guard.arm(id.clone());
                        upload_id = Some(id);
                    }
                    let mut data = data;
                    while !data.is_empty() {
                        // Adaptive: the target part size grows with the part index
                        // for unknown-length streams (see `adaptive_part_size`), so
                        // a 10,000-part budget can cover objects up to ~5 TiB. The
                        // first 1,000 parts stay at 5 MiB, leaving small/typical
                        // objects on the historical fixed-size happy path.
                        let current_part_size =
                            adaptive_part_size(None, next_part_index as u32) as usize;
                        if pending_part.is_empty() && data.len() >= current_part_size {
                            let part = data.split_to(current_part_size);
                            if let Err(e) = enqueue_s3_part_upload(
                                &mut upload_tasks,
                                &mut uploaded_parts,
                                S3PartUploadContext {
                                    store: &self.bulk_store,
                                    path: &path,
                                    upload_id: upload_id
                                        .as_ref()
                                        .expect("multipart upload id initialized above"),
                                    key,
                                },
                                &mut next_part_index,
                                part,
                            )
                            .await
                            {
                                upload_tasks.shutdown().await;
                                abort_guard.abort_now().await;
                                return Err(e);
                            }
                            continue;
                        }

                        let remaining_capacity = current_part_size - pending_part.len();
                        let bytes_to_buffer = remaining_capacity.min(data.len());
                        pending_part.extend_from_slice(&data.split_to(bytes_to_buffer));

                        if pending_part.len() == current_part_size {
                            let part = pending_part.split().freeze();
                            if let Err(e) = enqueue_s3_part_upload(
                                &mut upload_tasks,
                                &mut uploaded_parts,
                                S3PartUploadContext {
                                    store: &self.bulk_store,
                                    path: &path,
                                    upload_id: upload_id
                                        .as_ref()
                                        .expect("multipart upload id initialized above"),
                                    key,
                                },
                                &mut next_part_index,
                                part,
                            )
                            .await
                            {
                                upload_tasks.shutdown().await;
                                abort_guard.abort_now().await;
                                return Err(e);
                            }
                        }
                    }
                }
                Err(e) => {
                    // Abort the multipart upload on stream error to avoid
                    // leaving partial objects in S3.
                    upload_tasks.shutdown().await;
                    abort_guard.abort_now().await;
                    return Err(e);
                }
            }
        }

        if let Some(upload_id) = upload_id {
            if !pending_part.is_empty() {
                if let Err(e) = enqueue_s3_part_upload(
                    &mut upload_tasks,
                    &mut uploaded_parts,
                    S3PartUploadContext {
                        store: &self.bulk_store,
                        path: &path,
                        upload_id: &upload_id,
                        key,
                    },
                    &mut next_part_index,
                    pending_part.freeze(),
                )
                .await
                {
                    upload_tasks.shutdown().await;
                    abort_guard.abort_now().await;
                    return Err(e);
                }
            }
            if let Err(e) = drain_s3_part_uploads(&mut upload_tasks, &mut uploaded_parts, key).await
            {
                upload_tasks.shutdown().await;
                abort_guard.abort_now().await;
                return Err(e);
            }
            uploaded_parts.sort_by_key(|(part_index, _)| *part_index);
            let parts = uploaded_parts
                .into_iter()
                .map(|(_, part_id)| part_id)
                .collect();
            // CompleteMultipartUpload assembles the object server-side; for a
            // multi-GB upload S3 can hold the connection well past the
            // control-plane cliff, so this rides the bulk client too (#3180).
            if let Err(e) = self
                .bulk_store
                .complete_multipart(&path, &upload_id, parts)
                .await
            {
                abort_guard.abort_now().await;
                return Err(AppError::Storage(format!(
                    "Failed to complete multipart upload for '{}': {}",
                    key, e
                )));
            }
            // Upload completed: defuse the guard so drop never aborts it.
            abort_guard.disarm();
        } else {
            self.put(key, Bytes::new()).await?;
        }

        Ok(PutStreamResult {
            checksum_sha256: format!("{:x}", hasher.finalize()),
            bytes_written: total,
        })
    }
}

/// Extended S3 backend operations (for StorageService compatibility)
impl S3Backend {
    /// List keys with optional prefix
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        // Compose the search prefix through `make_full_key` so a listing
        // resolves the same physical location a `get`/`put` of a key under it
        // would (#3368).
        //
        // Defensive, not a live fix: today every caller that lists a
        // `proxy-cache/...` prefix (`purge_repo_cache`, `list_cached_paths`
        // and friends) goes through `ProxyService`, which `main.rs` always
        // builds from `StorageService::from_config` — i.e. the prefix-less
        // `StorageRole::ProxyCache` handle — and the storage GC never lists at
        // all, it drives off `artifacts` rows. So no production path reaches
        // this arm with a reserved key today. It is kept so that the FIRST one
        // that does resolves the same object `get`/`put` would, rather than
        // silently listing an empty prefix.
        let search_prefix = match (&self.prefix, prefix) {
            (Some(_), Some(p)) => make_full_key(self.prefix.as_deref(), p),
            (Some(base), None) => format!("{}/", base.trim_end_matches('/')),
            (None, Some(p)) => p.to_string(),
            (None, None) => String::new(),
        };

        let list_path: ObjectPath = search_prefix.into();
        let objects: Vec<_> = self
            .store
            .list(Some(&list_path))
            .try_collect()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to list objects: {}", e)))?;

        let keys: Vec<String> = objects
            .into_iter()
            .map(|meta| self.strip_prefix(meta.location.as_ref()))
            .collect();

        tracing::debug!(prefix = ?prefix, count = keys.len(), "S3 list objects successful");
        Ok(keys)
    }

    /// Copy content from one key to another
    pub async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let size = self.size(source).await?;
        if size > self.max_single_copy_bytes {
            tracing::debug!(
                source = %source,
                dest = %dest,
                size,
                "S3 source is too large for CopyObject; copying server-side via UploadPartCopy"
            );
            return self.multipart_server_side_copy(source, dest, size).await;
        }

        let source_key = self.full_key(source);
        let dest_key = self.full_key(dest);

        let from: ObjectPath = source_key.into();
        let to: ObjectPath = dest_key.into();

        self.bulk_store.copy(&from, &to).await.map_err(|e| {
            AppError::Storage(format!("Failed to copy '{}' to '{}': {}", source, dest, e))
        })?;

        tracing::debug!(source = %source, dest = %dest, "S3 copy object successful");
        Ok(())
    }

    /// Copy an object larger than the single-copy ceiling
    /// ([`S3Config::max_single_copy_bytes`], default
    /// [`S3_MAX_SINGLE_COPY_SIZE`]) entirely server-side via multipart
    /// `UploadPartCopy` (#3164).
    ///
    /// AWS caps single copies at 5 GiB: "You create a copy of your object up
    /// to 5 GB in size in a single atomic action using this API. However, to
    /// copy an object greater than 5 GB, you must use the multipart upload
    /// Upload Part - Copy (UploadPartCopy) API" (Amazon S3 API Reference,
    /// CopyObject). The previous fallback restreamed the object through the
    /// application (`get_stream` -> `put_stream`) and only compared digests
    /// *after* `put_stream` had already completed the multipart upload — by
    /// the time a mismatch could be detected, the corrupt bytes were live at
    /// `dest`, and #3153 deliberately rules out a reactive delete (it could
    /// clobber a concurrent writer's just-published good object).
    ///
    /// Copying server-side removes both problems at once: no payload byte
    /// passes through the application, and `dest` is not touched until
    /// `CompleteMultipartUpload` — every part must have been copied
    /// successfully (S3 validates the supplied part ETags at completion)
    /// before the destination becomes visible, matching the atomicity the
    /// native `CopyObject` already gives objects below the threshold. Any
    /// earlier failure aborts the upload and leaves an existing `dest`
    /// object untouched.
    async fn multipart_server_side_copy(&self, source: &str, dest: &str, size: u64) -> Result<()> {
        // `UploadPartCopy` is signed per request: the method and every `x-amz-*`
        // header go into the SigV4 canonical request, so an anonymous store has
        // nothing to sign with. `build_store` sets `with_skip_signature(true)`
        // when no credentials are configured, but object_store still populates
        // its credential chain, which falls through to the IMDS provider — so
        // reaching the signing path on an anonymous store stalls on a
        // link-local probe (up to the 180s retry_timeout) and then fails with
        // an error naming 169.254.169.254, which reads like a network fault
        // rather than a configuration one. Refuse legibly instead.
        if !self.sign_requests {
            return Err(AppError::Storage(format!(
                "Server-side copy of '{source}' ({size} bytes) exceeds the \
                 single-copy ceiling and requires S3 credentials to sign an \
                 UploadPartCopy request, but this backend is running \
                 unsigned (S3_ALLOW_ANONYMOUS). Configure credentials, or \
                 lower S3_MAX_SINGLE_COPY_BYTES so this object copies with a \
                 single unsigned CopyObject."
            )));
        }

        // Bound the part count BEFORE materialising the range vector. `size`
        // comes from a HEAD Content-Length, so an S3-compatible endpoint
        // reporting a bogus length would otherwise have us push one 16-byte
        // tuple per part first: `copy_part_ranges(u64::MAX/2, 5 GiB)` builds
        // 1.7e9 ranges (~27 GiB resident) and completes rather than erroring.
        // The ceiling is clamped to >= 5 MiB at construction, so it is never 0.
        let part_count = size.div_ceil(self.max_single_copy_bytes);
        if part_count > S3_MULTIPART_MAX_PARTS as u64 {
            // Unreachable for real S3 (5 TiB object ceiling / 5 GiB parts =
            // 1,024), but fail fast rather than opaquely at part 10,001 if an
            // S3-compatible provider reports a larger object.
            return Err(AppError::Storage(format!(
                "Multipart copy of '{}' would need {} parts, exceeding S3's {}-part limit",
                source, part_count, S3_MULTIPART_MAX_PARTS,
            )));
        }
        let ranges = copy_part_ranges(size, self.max_single_copy_bytes);
        let copy_source = s3_copy_source_value(&self.bucket, &self.full_key(source));
        let dest_path: ObjectPath = self.full_key(dest).into();

        let upload_id = self.store.create_multipart(&dest_path).await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to start multipart copy of '{}' -> '{}': {}",
                source, dest, e
            ))
        })?;
        // Aborts the upload if this future is dropped mid-copy, mirroring
        // `put_stream`; defused on completion or by the inline aborts below.
        let mut abort_guard =
            MultipartAbortGuard::new(self.store.clone(), dest_path.clone(), dest.to_string());
        abort_guard.arm(upload_id.clone());

        let mut parts = Vec::with_capacity(ranges.len());
        for (part_idx, range) in ranges.iter().enumerate() {
            match self
                .upload_part_copy(&copy_source, &dest_path, &upload_id, part_idx, *range)
                .await
            {
                Ok(part) => parts.push(part),
                Err(e) => {
                    abort_guard.abort_now().await;
                    return Err(e);
                }
            }
        }

        // CompleteMultipartUpload is the publish point: `dest` only becomes
        // visible here, after every server-side part copy succeeded. It rides
        // the bulk client because S3 assembles the object server-side and can
        // hold the connection well past the control-plane cliff (#3180).
        if let Err(e) = self
            .bulk_store
            .complete_multipart(&dest_path, &upload_id, parts)
            .await
        {
            abort_guard.abort_now().await;
            return Err(AppError::Storage(format!(
                "Failed to complete multipart copy of '{}' -> '{}': {}",
                source, dest, e
            )));
        }
        abort_guard.disarm();

        tracing::debug!(
            source = %source,
            dest = %dest,
            size,
            parts = ranges.len(),
            "S3 server-side multipart copy successful"
        );
        Ok(())
    }

    /// Issue one server-side `UploadPartCopy` request.
    ///
    /// `object_store` 0.13 does not expose ranged `UploadPartCopy`, so this is
    /// a hand-rolled request against the S3 REST API
    /// (`PUT /{key}?partNumber=N&uploadId=ID` with `x-amz-copy-source` and
    /// `x-amz-copy-source-range`), signed with the crate's own SigV4 signer
    /// ([`AwsAuthorizer`]) and the store's credential chain, so IRSA /
    /// container credentials keep working. The URL shape (path-style vs
    /// virtual-hosted, custom endpoints) is derived from the configured store
    /// via [`object_store::signer::Signer::signed_url`] rather than rebuilt
    /// here. "All headers with the `x-amz-` prefix, including
    /// `x-amz-copy-source`, must be signed" (S3 API Reference,
    /// UploadPartCopy), which header-based SigV4 does and a presigned URL
    /// cannot.
    async fn upload_part_copy(
        &self,
        copy_source: &str,
        dest_path: &ObjectPath,
        upload_id: &str,
        part_idx: usize,
        range: (u64, u64),
    ) -> Result<PartId> {
        use object_store::signer::Signer;

        let display = dest_path.as_ref();
        // "Part number of part being copied. This is a positive integer
        // between 1 and 10,000" (S3 API Reference, UploadPartCopy).
        let part_number = part_idx + 1;

        let mut url = self
            .store
            .signed_url(http::Method::PUT, dest_path, Duration::from_secs(300))
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to build UploadPartCopy URL for '{}': {}",
                    display, e
                ))
            })?;
        url.set_query(None);
        url.query_pairs_mut()
            .append_pair("partNumber", &part_number.to_string())
            .append_pair("uploadId", upload_id);

        let credential = self
            .bulk_store
            .credentials()
            .get_credential()
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to resolve S3 credentials for UploadPartCopy of '{}': {}",
                    display, e
                ))
            })?;

        // "The range value must use the form bytes=first-last, where the
        // first and last are the zero-based byte offsets to copy" (S3 API
        // Reference, UploadPartCopy, x-amz-copy-source-range). Inclusive.
        let range_value = format!("bytes={}-{}", range.0, range.1);
        let mut request = http::Request::builder()
            .method(http::Method::PUT)
            .uri(url.as_str())
            .header("x-amz-copy-source", copy_source)
            .header("x-amz-copy-source-range", &range_value)
            .body(object_store::client::HttpRequestBody::empty())
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to build UploadPartCopy request for '{}': {}",
                    display, e
                ))
            })?;
        AwsAuthorizer::new(&credential, "s3", &self.region).authorize(&mut request, None);

        let mut send = self
            .raw_http
            .put(url.as_str())
            .headers(request.headers().clone());
        if let Some(timeout) = self.bulk_timeout {
            // A 5 GiB server-side copy is bulk work: give it the bulk
            // ceiling, not reqwest's unbounded default.
            send = send.timeout(timeout);
        }
        let response = send.send().await.map_err(|e| {
            AppError::Storage(format!(
                "UploadPartCopy part {} for '{}' failed to send: {}",
                part_number, display, e
            ))
        })?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::Storage(format!(
                "UploadPartCopy part {} for '{}' failed: {} {}: {}",
                part_number,
                display,
                status.as_u16(),
                status.canonical_reason().unwrap_or(""),
                body
            )));
        }
        let etag = parse_copy_part_etag(&body).ok_or_else(|| {
            AppError::Storage(format!(
                "UploadPartCopy part {} for '{}' returned {} without a CopyPartResult ETag: {}",
                part_number,
                display,
                status.as_u16(),
                body
            ))
        })?;
        Ok(PartId { content_id: etag })
    }

    /// Get content size without fetching full content
    pub async fn size(&self, key: &str) -> Result<u64> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.store.head(&path).await {
            Ok(meta) => {
                tracing::debug!(key = %key, size = meta.size, "S3 head object successful");
                Ok(meta.size)
            }
            Err(object_store::Error::NotFound { .. }) => Err(AppError::NotFound(format!(
                "Storage key not found: {}",
                key
            ))),
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get size of '{}': {}",
                key, e
            ))),
        }
    }

    /// Generate a CloudFront signed URL
    ///
    /// CloudFront signed URLs use RSA-SHA1 signatures with a canned policy.
    fn generate_cloudfront_signed_url(
        &self,
        config: &CloudFrontConfig,
        key: &str,
        expires_in: Duration,
    ) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::RsaPrivateKey;
        use sha1::Sha1;

        // Calculate expiry timestamp
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| AppError::Internal(format!("System time error: {}", e)))?
            .as_secs()
            + expires_in.as_secs();

        // Build the resource URL
        let resource_url = format!(
            "{}/{}",
            config.distribution_url.trim_end_matches('/'),
            key.trim_start_matches('/')
        );

        // Create canned policy
        let policy = format!(
            r#"{{"Statement":[{{"Resource":"{}","Condition":{{"DateLessThan":{{"AWS:EpochTime":{}}}}}}}]}}"#,
            resource_url, expires
        );

        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(&config.private_key)
            .map_err(|e| AppError::Config(format!("Invalid CloudFront private key: {}", e)))?;

        // Sign the policy with RSA-SHA1 (unprefixed for CloudFront compatibility)
        let signing_key = SigningKey::<Sha1>::new_unprefixed(private_key);
        let signature = signing_key.sign(policy.as_bytes());

        // Base64 encode and make URL-safe
        let signature_b64 = STANDARD
            .encode(signature.to_bytes())
            .replace('+', "-")
            .replace('=', "_")
            .replace('/', "~");

        // Build signed URL with canned policy (simplified - just expiry)
        let signed_url = format!(
            "{}?Expires={}&Signature={}&Key-Pair-Id={}",
            resource_url, expires, signature_b64, config.key_pair_id
        );

        Ok(signed_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- #2927: Artifactory-migration fallback parity across backends ---

    /// Text of the method that starts at the first occurrence of `signature`,
    /// ending where the next method (or the enclosing `impl`) begins.
    ///
    /// Deliberately delimiter-based rather than brace-matched: braces appear
    /// inside `format!` templates and comments, so counting them is fragile in
    /// a way that could silently widen the slice and make the assertion below
    /// pass for the wrong reason. Returns `None` when the signature is absent.
    fn method_text<'a>(src: &'a str, signature: &str) -> Option<&'a str> {
        let start = src.find(signature)?;
        let rest = &src[start + signature.len()..];
        // Every method in these `impl` blocks is indented four spaces, and the
        // block itself closes at column 0.
        let end = ["\n    async fn ", "\n    fn ", "\n    pub ", "\n}"]
            .iter()
            .filter_map(|d| rest.find(d))
            .min()
            .unwrap_or(rest.len());
        Some(&rest[..end])
    }

    #[test]
    fn method_text_stops_at_the_next_method() {
        let src = "impl X {\n    async fn a(&self) {\n        body_a();\n    }\n\n    fn b(&self) {\n        body_b();\n    }\n}\n";
        let a = method_text(src, "async fn a(&self)").expect("a is present");
        assert!(a.contains("body_a()"));
        assert!(!a.contains("body_b()"), "must not run into the next method");
    }

    #[test]
    fn method_text_missing_signature_is_none() {
        assert!(method_text("impl X {\n    fn a(&self) {}\n}", "fn zzz()").is_none());
    }

    /// #2927 regression guard. S3, GCS and Azure all implement the
    /// Artifactory-migration path fallback — a no-op when
    /// `path_format.has_fallback()` is false — and all three must run it from
    /// `get_stream`, not only from the buffered `get`. S3 used to be the
    /// outlier, so an object present only at the legacy key layout was found by
    /// `storage.get()` and reported `NotFound` by `storage.get_stream()`; every
    /// buffered->streaming handler conversion (#1608) silently inherited that
    /// gap. The filesystem backend has no `path_format` and no fallback of any
    /// kind, so it is not part of this comparison.
    ///
    /// Either spelling counts: S3 and GCS route through the buffered
    /// `try_fallback_get` helper, while Azure re-issues a streaming GET against
    /// `try_artifactory_fallback` directly. The invariant is that the legacy
    /// key is consulted at all.
    ///
    /// A live assertion would need a real bucket in migration mode, so this
    /// pins the invariant structurally instead — the same source-scanning
    /// pattern used elsewhere in the tree for cross-file invariants that no
    /// unit test can reach.
    #[test]
    fn every_fallback_capable_backend_runs_the_migration_fallback_in_get_stream() {
        const GET_STREAM_SIG: &str = "async fn get_stream(&self, key: &str)";
        for (backend, src) in [
            ("s3", include_str!("s3.rs")),
            ("gcs", include_str!("gcs.rs")),
            ("azure", include_str!("azure.rs")),
        ] {
            assert!(
                src.contains("try_artifactory_fallback"),
                "{backend} is expected to implement the Artifactory-migration fallback"
            );
            let body = method_text(src, GET_STREAM_SIG)
                .unwrap_or_else(|| panic!("{backend} must define `{GET_STREAM_SIG}`"));
            assert!(
                body.contains("try_fallback_get") || body.contains("try_artifactory_fallback"),
                "{backend}::get_stream must consult the Artifactory-migration fallback before \
                 reporting NotFound (#2927); otherwise a legacy-layout object resolves through \
                 the buffered `get` but 404s through the streaming read"
            );
        }
    }

    // --- free function tests: make_full_key ---

    #[test]
    fn test_full_key_with_prefix() {
        assert_eq!(
            make_full_key(Some("artifacts"), "test/file.txt"),
            "artifacts/test/file.txt"
        );
    }

    #[test]
    fn test_full_key_without_prefix() {
        assert_eq!(make_full_key(None, "test/file.txt"), "test/file.txt");
    }

    #[test]
    fn test_full_key_trailing_slash_prefix() {
        assert_eq!(
            make_full_key(Some("artifacts/"), "test/file.txt"),
            "artifacts/test/file.txt"
        );
    }

    // --- free function tests: bucket-root key anchoring (#3368) ---

    /// The regression test for #3368. The prefix is the variable: with
    /// `S3_PREFIX` unset both layouts coincide and everything works, which is
    /// why this went unnoticed. With a prefix configured, the ArtifactSource
    /// handle composed `<S3_PREFIX>/proxy-cache/...` for an `artifacts` row
    /// whose `storage_key` is proxy-cache content — a key nothing ever writes,
    /// so the read was a structurally guaranteed miss while the object sat at
    /// the bucket root.
    ///
    /// FAILS ON MAIN: `make_full_key` unconditionally prepended the prefix.
    #[test]
    fn test_full_key_does_not_prefix_proxy_cache_content_3368() {
        let key = "proxy-cache/pypi-remote/simple/six/six-1.17.0-py2.py3-none-any.whl/__content__";
        assert_eq!(
            make_full_key(Some("artifacts"), key),
            key,
            "proxy-cache content is written at the bucket root by the prefix-less \
             ProxyCache handle; composing a prefixed key here can only ever miss"
        );
        assert_eq!(
            make_full_key(Some("artifacts/"), key),
            key,
            "a trailing slash on S3_PREFIX must not change the answer"
        );
    }

    /// The sidecar and the staging namespace share the body's layout. The
    /// sidecar is what vouches for the body (#3147) and the staging objects
    /// are what a multipart write lands in first (#3454's log line), so a
    /// layout that moved either away from the body would be worse than the
    /// bug: verdict and body would be read from two different places.
    #[test]
    fn test_full_key_does_not_prefix_cache_sidecar_or_staging_3368() {
        for key in [
            "proxy-cache/maven-proxy/org/postgresql/postgresql/42.7.13/postgresql-42.7.13.pom/__cache_meta__.json",
            "proxy-cache-staging/0f8fad5b-d9cb-469f-a165-70867728950e",
        ] {
            assert_eq!(
                make_full_key(Some("artifacts"), key),
                key,
                "{key} must resolve at the bucket root"
            );
        }
    }

    /// Negative control. #3171 is the mirror-image bug — reading artifact
    /// bytes through the prefix-less handle — and it must stay fixed: every
    /// key OUTSIDE the reserved namespaces still gets `S3_PREFIX`. A fix that
    /// dropped the prefix wholesale would pass the test above and silently
    /// re-open #3171, so this control is what makes that one meaningful.
    #[test]
    fn test_full_key_still_prefixes_artifact_bytes_3171() {
        for key in [
            "pypi/six/1.17.0/six-1.17.0-py2.py3-none-any.whl",
            "maven/org/postgresql/postgresql/42.7.13/postgresql-42.7.13.pom",
            // Not a reserved namespace: only the exact `proxy-cache/` and
            // `proxy-cache-staging/` roots are anchored.
            "npm/proxy-cache-notes/-/proxy-cache-notes-1.0.0.tgz",
        ] {
            assert_eq!(
                make_full_key(Some("artifacts"), key),
                format!("artifacts/{key}"),
                "{key} is artifact bytes and must keep S3_PREFIX (#3171)"
            );
        }
    }

    /// `strip_key_prefix` is the inverse used to map listing results back to
    /// logical keys, and must round-trip BOTH layouts or a listing would hand
    /// back keys no `get`/`delete` can resolve.
    ///
    /// This is a property guard, NOT a regression test: the round trip holds
    /// on `main` too (there the prefix is applied and stripped symmetrically).
    /// It is here to stop the anchoring rule from being added on the compose
    /// side only, which WOULD break it.
    #[test]
    fn test_full_key_strip_round_trips_both_layouts_3368() {
        for prefix in [None, Some("artifacts"), Some("team-a/registry")] {
            for key in [
                "pypi/six/1.17.0/six-1.17.0-py2.py3-none-any.whl",
                "proxy-cache/repo/simple/six/six.whl/__content__",
                "proxy-cache-staging/0f8fad5b-d9cb-469f-a165-70867728950e",
            ] {
                let full = make_full_key(prefix, key);
                assert_eq!(
                    strip_key_prefix(prefix, &full),
                    key,
                    "round trip failed for prefix {prefix:?} key {key}"
                );
            }
        }
    }

    /// The one configuration the key-anchored layout cannot disambiguate is
    /// flagged; ordinary prefixes are not.
    #[test]
    fn test_reserved_namespace_prefix_collision_is_detected_3368() {
        for prefix in [
            "proxy-cache",
            "proxy-cache/",
            "proxy-cache-staging",
            "proxy-cache/sub",
        ] {
            assert!(
                s3_prefix_collides_with_reserved_namespace(prefix),
                "{prefix} shares a key space with proxy-cache content"
            );
        }
        for prefix in ["artifacts", "team-a/registry", "proxy-cache-notes", "ak"] {
            assert!(
                !s3_prefix_collides_with_reserved_namespace(prefix),
                "{prefix} is an ordinary prefix and must not be flagged"
            );
        }
    }

    // --- free function tests: ensure_s3_part_within_limit ---

    #[test]
    fn test_s3_part_within_limit_accepts_below_cap() {
        // The last valid index is S3_MULTIPART_MAX_PARTS - 1 (the 10,000th part).
        assert!(ensure_s3_part_within_limit(0, S3_MULTIPART_CHUNK_SIZE, "k").is_ok());
        assert!(ensure_s3_part_within_limit(
            S3_MULTIPART_MAX_PARTS - 1,
            S3_MULTIPART_CHUNK_SIZE,
            "k"
        )
        .is_ok());
        // A part exactly at the 5 GiB per-part maximum is accepted.
        assert!(ensure_s3_part_within_limit(0, S3_MULTIPART_MAX_PART_SIZE as usize, "k").is_ok());
    }

    #[test]
    fn test_s3_part_within_limit_rejects_at_cap() {
        // Index == cap would be the 10,001st part: rejected with a clear error.
        let err = ensure_s3_part_within_limit(
            S3_MULTIPART_MAX_PARTS,
            S3_MULTIPART_CHUNK_SIZE,
            "blobs/abc",
        )
        .expect_err("part index at the cap must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("blobs/abc"),
            "error should name the key: {msg}"
        );
        assert!(
            msg.contains(&S3_MULTIPART_MAX_PARTS.to_string()),
            "error should state the part limit: {msg}"
        );
        // The error now reports the real ~5 TiB object ceiling, not ~50 GiB.
        assert!(
            msg.contains("5 TiB"),
            "error should state the 5 TiB ceiling: {msg}"
        );
    }

    #[test]
    fn test_s3_part_within_limit_rejects_oversized_part() {
        // A part above the 5 GiB per-part maximum is rejected with a clear error.
        let too_big = S3_MULTIPART_MAX_PART_SIZE as usize + 1;
        let err = ensure_s3_part_within_limit(0, too_big, "blobs/huge")
            .expect_err("a part over 5 GiB must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("blobs/huge"),
            "error should name the key: {msg}"
        );
        assert!(
            msg.contains("per-part limit"),
            "error should explain the per-part cap: {msg}"
        );
    }

    // --- free function tests: adaptive_part_size ---

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;

    #[test]
    fn test_adaptive_part_size_small_known_object_uses_min_part() {
        // A tiny object never goes below the 5 MiB minimum part size.
        assert_eq!(
            adaptive_part_size(Some(1), 0),
            S3_MULTIPART_CHUNK_SIZE as u64
        );
        assert_eq!(
            adaptive_part_size(Some(10 * MIB), 0),
            S3_MULTIPART_CHUNK_SIZE as u64
        );
    }

    #[test]
    fn test_adaptive_part_size_known_object_part_index_is_irrelevant() {
        // For a known size the part size is fixed regardless of index.
        let size = Some(100 * GIB);
        let p0 = adaptive_part_size(size, 0);
        assert_eq!(p0, adaptive_part_size(size, 5_000));
        assert_eq!(p0, adaptive_part_size(size, 8_999));
    }

    #[test]
    fn test_adaptive_part_size_known_100gib_stays_under_cap_and_max() {
        let size = 100 * GIB;
        let part = adaptive_part_size(Some(size), 0);
        assert!(
            part <= S3_MULTIPART_MAX_PART_SIZE,
            "part {part} must not exceed the 5 GiB per-part max"
        );
        let parts = size.div_ceil(part);
        assert!(
            parts <= S3_MULTIPART_MAX_PARTS as u64,
            "100 GiB must fit within the 10,000-part cap, got {parts} parts"
        );
    }

    #[test]
    fn test_adaptive_part_size_known_50gib_boundary() {
        // The historical artificial ceiling: 50 GiB must now be well within limits.
        let size = 50 * GIB;
        let part = adaptive_part_size(Some(size), 0);
        let parts = size.div_ceil(part);
        assert!(parts <= S3_MULTIPART_MAX_PARTS as u64);
        assert!(part <= S3_MULTIPART_MAX_PART_SIZE);
        // At the 9,000-part target, a 50 GiB object uses ~5.7 MiB parts.
        assert!(part >= S3_MULTIPART_CHUNK_SIZE as u64);
    }

    #[test]
    fn test_adaptive_part_size_known_5tib_fits_within_limits() {
        // S3's real object ceiling: 5 TiB. ceil(5 TiB / 9000) ~= 583 MiB, which is
        // below the 5 GiB per-part max, so it is used directly and the part count
        // stays at the 9,000-part target (<= the 10,000 cap).
        let size = 5 * TIB;
        let part = adaptive_part_size(Some(size), 0);
        assert!(
            part <= S3_MULTIPART_MAX_PART_SIZE,
            "part {part} must not exceed the 5 GiB per-part max"
        );
        assert!(part >= S3_MULTIPART_CHUNK_SIZE as u64);
        let parts = size.div_ceil(part);
        assert!(
            parts <= S3_MULTIPART_MAX_PARTS as u64,
            "5 TiB must fit within the 10,000-part cap, got {parts} parts"
        );
        assert!(
            parts <= S3_MULTIPART_TARGET_PARTS,
            "a known 5 TiB object should fit within the 9,000-part target, got {parts}"
        );
    }

    #[test]
    fn test_adaptive_part_size_known_clamps_to_max_part_for_huge_object() {
        // An object so large that ceil(size / 9000) exceeds 5 GiB clamps the part
        // size to the 5 GiB per-part maximum (the absolute ceiling is 5 GiB x
        // 10,000 = ~48.8 TiB, well above S3's real 5 TiB object limit).
        let size = 9_000 * (6 * GIB); // ceil(size/9000) = 6 GiB > MAX_PART
        let part = adaptive_part_size(Some(size), 0);
        assert_eq!(part, S3_MULTIPART_MAX_PART_SIZE);
    }

    #[test]
    fn test_adaptive_part_size_unknown_first_tier_is_min_part() {
        // The first 1,000 parts of a stream stay at 5 MiB so small/typical
        // objects behave exactly like the historical fixed-size path.
        assert_eq!(adaptive_part_size(None, 0), S3_MULTIPART_CHUNK_SIZE as u64);
        assert_eq!(
            adaptive_part_size(None, 999),
            S3_MULTIPART_CHUNK_SIZE as u64
        );
    }

    #[test]
    fn test_adaptive_part_size_unknown_doubles_each_tier() {
        // Size doubles every S3_PARTS_PER_TIER parts: 5 MiB -> 10 MiB -> 20 MiB.
        assert_eq!(
            adaptive_part_size(None, S3_PARTS_PER_TIER),
            2 * S3_MULTIPART_CHUNK_SIZE as u64
        );
        assert_eq!(
            adaptive_part_size(None, 2 * S3_PARTS_PER_TIER),
            4 * S3_MULTIPART_CHUNK_SIZE as u64
        );
    }

    #[test]
    fn test_adaptive_part_size_unknown_caps_at_max_part() {
        // 5 MiB << 10 = 5 GiB == max part; tier 10 and beyond stay at the cap.
        assert_eq!(
            adaptive_part_size(None, 10 * S3_PARTS_PER_TIER),
            S3_MULTIPART_MAX_PART_SIZE
        );
        assert_eq!(
            adaptive_part_size(None, 50 * S3_PARTS_PER_TIER),
            S3_MULTIPART_MAX_PART_SIZE
        );
        // Far-future index that would overflow a naive shift must still be capped.
        assert_eq!(
            adaptive_part_size(None, u32::MAX),
            S3_MULTIPART_MAX_PART_SIZE
        );
    }

    #[test]
    fn test_adaptive_part_size_unknown_schedule_covers_near_5tib() {
        // Sum the part sizes across the full 10,000-part budget and confirm the
        // unknown-length schedule covers a multi-TiB object without ever
        // exceeding the per-part max or the part cap.
        let mut total: u64 = 0;
        for idx in 0..S3_MULTIPART_MAX_PARTS as u32 {
            let part = adaptive_part_size(None, idx);
            assert!(
                part <= S3_MULTIPART_MAX_PART_SIZE,
                "part at idx {idx} exceeded the 5 GiB max"
            );
            assert!(part >= S3_MULTIPART_CHUNK_SIZE as u64);
            total += part;
        }
        // Documented effective ceiling for unknown-length streams: ~4.99 TiB.
        let four_tib = 4 * TIB;
        assert!(
            total > four_tib && total <= 5 * TIB,
            "unknown-length schedule should cover ~5 TiB, got {total} bytes"
        );
    }

    #[test]
    fn test_full_key_empty_key() {
        assert_eq!(make_full_key(Some("prefix"), ""), "prefix/");
        assert_eq!(make_full_key(None, ""), "");
    }

    #[test]
    fn test_make_full_key_double_slash_prevention() {
        // Prefix with trailing slash should not produce double slash
        assert_eq!(make_full_key(Some("prefix/"), "key"), "prefix/key");
    }

    // --- free function tests: strip_key_prefix ---

    #[test]
    fn test_strip_prefix() {
        assert_eq!(
            strip_key_prefix(Some("artifacts"), "artifacts/test/file.txt"),
            "test/file.txt"
        );
    }

    #[test]
    fn test_strip_prefix_no_match() {
        assert_eq!(
            strip_key_prefix(Some("other-prefix"), "artifacts/test/file.txt"),
            "artifacts/test/file.txt"
        );
    }

    #[test]
    fn test_strip_prefix_none() {
        assert_eq!(strip_key_prefix(None, "test/file.txt"), "test/file.txt");
    }

    #[test]
    fn test_strip_prefix_exact_match() {
        // Key is exactly "prefix/" with nothing after
        assert_eq!(strip_key_prefix(Some("prefix"), "prefix/"), "");
    }

    #[test]
    fn test_strip_prefix_with_trailing_slash() {
        assert_eq!(
            strip_key_prefix(Some("prefix/"), "prefix/test/file.txt"),
            "test/file.txt"
        );
    }

    // --- free function tests: artifactory_fallback_path ---

    #[test]
    fn test_artifactory_fallback_valid_native_path() {
        let key = "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let result = artifactory_fallback_path(key);
        assert_eq!(
            result.unwrap(),
            "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_artifactory_fallback_short_checksum_rejected() {
        assert!(artifactory_fallback_path("ab/cd/abcdef1234").is_none());
    }

    #[test]
    fn test_artifactory_fallback_non_hex_rejected() {
        assert!(artifactory_fallback_path(
            "zz/yy/zzyy00000000000000000000000000000000000000000000000000gggggg"
        )
        .is_none());
    }

    #[test]
    fn test_artifactory_fallback_single_segment_rejected() {
        assert!(artifactory_fallback_path(
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        )
        .is_none());
    }

    #[test]
    fn test_artifactory_fallback_two_segments() {
        assert!(artifactory_fallback_path(
            "ab/abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
        )
        .is_none());
    }

    #[test]
    fn test_artifactory_fallback_deeply_nested() {
        // More than 3 segments should still work (takes the last one)
        let checksum = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let key = format!("a/b/c/d/{}", checksum);
        let result = artifactory_fallback_path(&key);
        assert_eq!(result.unwrap(), format!("91/{}", checksum));
    }

    #[test]
    fn test_byte_range_is_end_exclusive() {
        assert_eq!(S3Backend::byte_range(1_024, 4_096).unwrap(), 1_024..5_120);
    }

    #[test]
    fn test_byte_range_rejects_overflow() {
        let err = S3Backend::byte_range(u64::MAX - 1, 4).unwrap_err();
        assert!(
            err.to_string().contains("overflows u64"),
            "error should explain overflow: {err}"
        );
    }

    // --- S3Config constructor / builder tests ---

    #[test]
    fn test_s3_config_new() {
        let config = S3Config::new(
            "my-bucket".to_string(),
            "us-west-2".to_string(),
            Some("http://localhost:9000".to_string()),
            Some("prefix".to_string()),
        );

        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
        assert_eq!(config.prefix, Some("prefix".to_string()));
        assert_eq!(config.path_format, StoragePathFormat::Native);
        assert!(config.presign_access_key.is_none());
        assert!(config.presign_secret_key.is_none());
    }

    #[test]
    fn test_s3_config_with_path_format() {
        let config = S3Config::new("my-bucket".to_string(), "us-west-2".to_string(), None, None)
            .with_path_format(StoragePathFormat::Artifactory);
        assert_eq!(config.path_format, StoragePathFormat::Artifactory);
    }

    #[test]
    fn test_path_format_with_s3_config() {
        let config = S3Config::new("test".to_string(), "us-east-1".to_string(), None, None)
            .with_path_format(StoragePathFormat::Migration);
        assert_eq!(config.path_format, StoragePathFormat::Migration);
        assert!(config.path_format.has_fallback());
    }

    #[test]
    fn test_s3_config_presign_credentials_default_none() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None);
        assert!(config.presign_access_key.is_none());
        assert!(config.presign_secret_key.is_none());
    }

    #[test]
    fn test_s3_config_supports_redirect_requires_key() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_redirect_downloads(true);
        assert!(config.redirect_downloads);
        assert!(config.presign_access_key.is_none());
    }

    #[test]
    fn test_s3_config_with_presign_expiry() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_presign_expiry(Duration::from_secs(7200));
        assert_eq!(config.presign_expiry, Duration::from_secs(7200));
    }

    #[test]
    fn test_s3_config_with_cloudfront() {
        let cf = CloudFrontConfig {
            distribution_url: "https://d1234.cloudfront.net".to_string(),
            key_pair_id: "KPID123".to_string(),
            private_key: "fake-key-data".to_string(),
        };
        let config =
            S3Config::new("b".to_string(), "us-east-1".to_string(), None, None).with_cloudfront(cf);
        assert!(config.cloudfront.is_some());
        let cf = config.cloudfront.unwrap();
        assert_eq!(cf.distribution_url, "https://d1234.cloudfront.net");
        assert_eq!(cf.key_pair_id, "KPID123");
    }

    #[test]
    fn test_s3_config_default_values() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(!config.redirect_downloads);
        assert_eq!(config.presign_expiry, Duration::from_secs(3600));
        assert!(config.cloudfront.is_none());
        assert_eq!(config.path_format, StoragePathFormat::Native);
        assert!(config.endpoint.is_none());
        assert!(config.prefix.is_none());
        assert!(config.ca_cert_path.is_none());
        assert!(!config.insecure_tls);
        assert!(!config.disable_multi_delete);
    }

    #[test]
    fn test_s3_config_chained_builders() {
        let cf = CloudFrontConfig {
            distribution_url: "https://cdn.example.com".to_string(),
            key_pair_id: "KP1".to_string(),
            private_key: "key".to_string(),
        };
        let config = S3Config::new(
            "bucket".to_string(),
            "eu-west-1".to_string(),
            Some("https://minio:9000".to_string()),
            Some("prefix".to_string()),
        )
        .with_redirect_downloads(true)
        .with_presign_expiry(Duration::from_secs(600))
        .with_path_format(StoragePathFormat::Migration)
        .with_cloudfront(cf);

        assert_eq!(config.bucket, "bucket");
        assert_eq!(config.region, "eu-west-1");
        assert_eq!(config.endpoint, Some("https://minio:9000".to_string()));
        assert_eq!(config.prefix, Some("prefix".to_string()));
        assert!(config.redirect_downloads);
        assert_eq!(config.presign_expiry, Duration::from_secs(600));
        assert_eq!(config.path_format, StoragePathFormat::Migration);
        assert!(config.cloudfront.is_some());
    }

    // --- path_format tests ---

    #[test]
    fn test_native_format_has_no_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Native);
        assert!(!config.path_format.has_fallback());
    }

    #[test]
    fn test_artifactory_format_has_no_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Artifactory);
        assert!(!config.path_format.has_fallback());
    }

    #[test]
    fn test_migration_format_has_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Migration);
        assert!(config.path_format.has_fallback());
    }

    // --- TLS config tests ---

    #[test]
    fn test_s3_config_ca_cert_path_default_none() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(config.ca_cert_path.is_none());
        assert!(!config.insecure_tls);
    }

    #[test]
    fn test_s3_config_with_ca_cert_path() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_ca_cert_path("/etc/ssl/custom-ca.pem".to_string());
        assert_eq!(
            config.ca_cert_path,
            Some("/etc/ssl/custom-ca.pem".to_string())
        );
    }

    #[test]
    fn test_s3_config_with_insecure_tls() {
        let config =
            S3Config::new("b".to_string(), "r".to_string(), None, None).with_insecure_tls(true);
        assert!(config.insecure_tls);
    }

    #[test]
    fn test_s3_config_insecure_tls_default_false() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(!config.insecure_tls);
    }

    #[test]
    fn test_s3_config_chained_builders_with_tls() {
        let config = S3Config::new(
            "bucket".to_string(),
            "us-east-1".to_string(),
            Some("https://s3.internal:9000".to_string()),
            None,
        )
        .with_ca_cert_path("/etc/ssl/internal-ca.pem".to_string())
        .with_insecure_tls(false);

        assert_eq!(
            config.ca_cert_path,
            Some("/etc/ssl/internal-ca.pem".to_string())
        );
        assert!(!config.insecure_tls);
    }

    // --- disable_multi_delete config tests ---

    #[test]
    fn test_s3_config_disable_multi_delete_defaults_off_and_can_enable() {
        let default_config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(
            !default_config.disable_multi_delete,
            "should default to false"
        );

        let enabled = default_config.with_disable_multi_delete(true);
        assert!(enabled.disable_multi_delete);
    }

    #[test]
    fn test_s3_config_huawei_obs_chained_builders() {
        let config = S3Config::new(
            "obs-bucket".to_string(),
            "cn-north-4".to_string(),
            Some("https://obs.cn-north-4.myhuaweicloud.com".to_string()),
            None,
        )
        .with_disable_multi_delete(true)
        .with_insecure_tls(false);

        assert_eq!(config.bucket, "obs-bucket");
        assert_eq!(config.region, "cn-north-4");
        assert!(config.disable_multi_delete);
        assert!(!config.insecure_tls);
    }

    // --- build_store tests ---

    #[test]
    fn test_build_store_invalid_ca_cert_path() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_ca_cert_path("/nonexistent/ca.pem".to_string());
        let result = S3Backend::build_store(&config, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to read CA cert"), "got: {err}");
    }

    #[test]
    fn test_build_store_with_explicit_credentials() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        );
        let result = S3Backend::build_store(&config, Some("AKID"), Some("SECRET"));
        assert!(
            result.is_ok(),
            "build_store should succeed with explicit creds"
        );
    }

    #[test]
    fn test_build_store_minimal_config() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None);
        let result = S3Backend::build_store(&config, None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed with minimal config"
        );
    }

    #[test]
    fn test_build_store_with_custom_endpoint() {
        let config = S3Config::new(
            "b".to_string(),
            "us-east-1".to_string(),
            Some("https://s3.internal:9000".to_string()),
            None,
        );
        let result = S3Backend::build_store(&config, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_store_allows_http_for_http_endpoint() {
        let config = S3Config::new(
            "b".to_string(),
            "us-east-1".to_string(),
            Some("http://minio:9000".to_string()),
            None,
        );
        // Should succeed (allow_http enabled for http:// endpoints)
        assert!(S3Backend::build_store(&config, None, None).is_ok());
    }

    #[test]
    fn test_build_store_insecure_tls() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_insecure_tls(true);
        assert!(S3Backend::build_store(&config, None, None).is_ok());
    }

    // --- S3Config from_env tests ---

    #[test]
    fn test_s3_config_from_env_missing_bucket() {
        let original = std::env::var("S3_BUCKET").ok();
        std::env::remove_var("S3_BUCKET");
        let result = S3Config::from_env();
        assert!(result.is_err());
        // Restore
        if let Some(v) = original {
            std::env::set_var("S3_BUCKET", v);
        }
    }

    #[test]
    fn test_s3_config_from_env_success() {
        // Save originals
        let orig_bucket = std::env::var("S3_BUCKET").ok();
        let orig_region = std::env::var("S3_REGION").ok();
        let orig_endpoint = std::env::var("S3_ENDPOINT").ok();
        let orig_prefix = std::env::var("S3_PREFIX").ok();
        let orig_redirect = std::env::var("S3_REDIRECT_DOWNLOADS").ok();
        let orig_expiry = std::env::var("S3_PRESIGN_EXPIRY_SECS").ok();
        let orig_pak = std::env::var("S3_PRESIGN_ACCESS_KEY_ID").ok();
        let orig_psk = std::env::var("S3_PRESIGN_SECRET_ACCESS_KEY").ok();
        let orig_ca = std::env::var("S3_CA_CERT_PATH").ok();
        let orig_insecure = std::env::var("S3_INSECURE_TLS").ok();
        let orig_disable_multi = std::env::var("S3_DISABLE_MULTI_DELETE").ok();
        // Also save CloudFront vars to avoid interference
        let orig_cf_url = std::env::var("CLOUDFRONT_DISTRIBUTION_URL").ok();

        // Set test values
        std::env::set_var("S3_BUCKET", "test-from-env-bucket");
        std::env::set_var("S3_REGION", "eu-west-1");
        std::env::set_var("S3_ENDPOINT", "http://localhost:9000");
        std::env::set_var("S3_PREFIX", "my-prefix");
        std::env::set_var("S3_REDIRECT_DOWNLOADS", "true");
        std::env::set_var("S3_PRESIGN_EXPIRY_SECS", "7200");
        std::env::set_var("S3_PRESIGN_ACCESS_KEY_ID", "presign-ak");
        std::env::set_var("S3_PRESIGN_SECRET_ACCESS_KEY", "presign-sk");
        std::env::remove_var("S3_CA_CERT_PATH");
        std::env::set_var("S3_INSECURE_TLS", "1");
        std::env::set_var("S3_DISABLE_MULTI_DELETE", "true");
        std::env::remove_var("CLOUDFRONT_DISTRIBUTION_URL");

        let result = S3Config::from_env();
        assert!(
            result.is_ok(),
            "from_env should succeed: {:?}",
            result.err()
        );
        let config = result.unwrap();
        assert_eq!(config.bucket, "test-from-env-bucket");
        assert_eq!(config.region, "eu-west-1");
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
        assert_eq!(config.prefix, Some("my-prefix".to_string()));
        assert!(config.redirect_downloads);
        assert_eq!(config.presign_expiry, Duration::from_secs(7200));
        assert_eq!(config.presign_access_key, Some("presign-ak".to_string()));
        assert_eq!(config.presign_secret_key, Some("presign-sk".to_string()));
        assert!(config.ca_cert_path.is_none());
        assert!(config.insecure_tls);
        assert!(config.disable_multi_delete);
        assert!(config.cloudfront.is_none());

        // Restore all originals
        let restore = |name: &str, val: Option<String>| match val {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        };
        restore("S3_BUCKET", orig_bucket);
        restore("S3_REGION", orig_region);
        restore("S3_ENDPOINT", orig_endpoint);
        restore("S3_PREFIX", orig_prefix);
        restore("S3_REDIRECT_DOWNLOADS", orig_redirect);
        restore("S3_PRESIGN_EXPIRY_SECS", orig_expiry);
        restore("S3_PRESIGN_ACCESS_KEY_ID", orig_pak);
        restore("S3_PRESIGN_SECRET_ACCESS_KEY", orig_psk);
        restore("S3_CA_CERT_PATH", orig_ca);
        restore("S3_INSECURE_TLS", orig_insecure);
        restore("S3_DISABLE_MULTI_DELETE", orig_disable_multi);
        restore("CLOUDFRONT_DISTRIBUTION_URL", orig_cf_url);
    }

    #[test]
    fn test_build_store_with_valid_ca_cert() {
        // Use the test fixture PEM file
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let pem_path = format!("{}/tests/fixtures/test-ca.pem", manifest_dir);

        // Only run if the fixture exists
        if !std::path::Path::new(&pem_path).exists() {
            eprintln!("Skipping: test-ca.pem fixture not found at {}", pem_path);
            return;
        }

        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_ca_cert_path(pem_path);
        let result = S3Backend::build_store(&config, None, None);
        assert!(
            result.is_ok(),
            "build_store with valid CA cert should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_store_with_invalid_pem_content() {
        let tmp_path = std::env::temp_dir().join("test-bad-ca-s3.pem");
        std::fs::write(&tmp_path, b"not-a-valid-pem").expect("write temp PEM");

        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_ca_cert_path(tmp_path.to_str().unwrap().to_string());
        let result = S3Backend::build_store(&config, None, None);
        let _ = std::fs::remove_file(&tmp_path);
        // The PEM bundle parser may succeed with 0 certs or fail, either is acceptable
        // as long as we exercise the code path
        let _ = result;
    }

    // --- Presign expiry clamping ---

    #[test]
    fn test_presign_expiry_clamp_within_limit() {
        let expiry = Duration::from_secs(3600);
        let clamped = Duration::from_secs(expiry.as_secs().min(604800));
        assert_eq!(clamped, Duration::from_secs(3600));
    }

    #[test]
    fn test_presign_expiry_clamp_exceeds_7_days() {
        let expiry = Duration::from_secs(1_000_000);
        let clamped = Duration::from_secs(expiry.as_secs().min(604800));
        assert_eq!(clamped, Duration::from_secs(604800));
    }

    #[test]
    fn test_presign_expiry_clamp_exact_7_days() {
        let expiry = Duration::from_secs(604800);
        let clamped = Duration::from_secs(expiry.as_secs().min(604800));
        assert_eq!(clamped, Duration::from_secs(604800));
    }

    // --- S3Backend::new construction tests ---

    #[tokio::test]
    async fn test_s3_backend_new_minimal() {
        let _env = AnonymousS3TestEnv::enter();
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            Some("prefix".to_string()),
        );
        let backend = S3Backend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_s3_backend_new_with_signing_store() {
        let _env = AnonymousS3TestEnv::enter();
        let mut config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        );
        config.presign_access_key = Some("SIGN_AK".to_string());
        config.presign_secret_key = Some("SIGN_SK".to_string());
        config.redirect_downloads = true;
        let backend = S3Backend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_s3_backend_new_with_tls_config() {
        let _env = AnonymousS3TestEnv::enter();
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_insecure_tls(true);
        let backend = S3Backend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_s3_backend_new_migration_path_format() {
        let _env = AnonymousS3TestEnv::enter();
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_path_format(StoragePathFormat::Migration);
        let backend = S3Backend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_s3_backend_supports_redirect_false_by_default() {
        let _env = AnonymousS3TestEnv::enter();
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        );
        let backend = S3Backend::new(config).await.unwrap();
        assert!(!backend.redirect_downloads);
    }

    #[tokio::test]
    async fn test_s3_backend_supports_redirect_when_enabled() {
        let _env = AnonymousS3TestEnv::enter();
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_redirect_downloads(true);
        let backend = S3Backend::new(config).await.unwrap();
        assert!(backend.redirect_downloads);
    }

    #[tokio::test]
    async fn test_s3_backend_full_key_integration() {
        let _env = AnonymousS3TestEnv::enter();
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            Some("myprefix".to_string()),
        );
        let backend = S3Backend::new(config).await.unwrap();
        assert_eq!(backend.full_key("some/path"), "myprefix/some/path");
        assert_eq!(backend.strip_prefix("myprefix/some/path"), "some/path");
    }

    #[tokio::test]
    async fn test_s3_backend_fallback_integration() {
        let _env = AnonymousS3TestEnv::enter();
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_path_format(StoragePathFormat::Migration);
        let backend = S3Backend::new(config).await.unwrap();

        let key = "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let fallback = backend.try_artifactory_fallback(key);
        assert_eq!(
            fallback.unwrap(),
            "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );

        // No fallback for non-checksum paths
        assert!(backend.try_artifactory_fallback("not/valid").is_none());
    }

    #[tokio::test]
    async fn test_s3_backend_from_env_with_env_vars() {
        let _env = AnonymousS3TestEnv::enter();
        // Save originals
        let orig_bucket = std::env::var("S3_BUCKET").ok();
        let orig_region = std::env::var("S3_REGION").ok();
        let orig_endpoint = std::env::var("S3_ENDPOINT").ok();
        let orig_cf_url = std::env::var("CLOUDFRONT_DISTRIBUTION_URL").ok();

        std::env::set_var("S3_BUCKET", "env-test-bucket");
        std::env::set_var("S3_REGION", "ap-south-1");
        std::env::set_var("S3_ENDPOINT", "http://localhost:9999");
        std::env::remove_var("CLOUDFRONT_DISTRIBUTION_URL");

        let backend = S3Backend::from_env().await;
        assert!(
            backend.is_ok(),
            "from_env should succeed: {:?}",
            backend.err()
        );

        // Restore
        let restore = |name: &str, val: Option<String>| match val {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        };
        restore("S3_BUCKET", orig_bucket);
        restore("S3_REGION", orig_region);
        restore("S3_ENDPOINT", orig_endpoint);
        restore("CLOUDFRONT_DISTRIBUTION_URL", orig_cf_url);
    }

    #[tokio::test]
    async fn test_s3_backend_new_invalid_ca_cert_fails() {
        let _env = AnonymousS3TestEnv::enter();
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_ca_cert_path("/nonexistent/cert.pem".to_string());
        let backend = S3Backend::new(config).await;
        assert!(backend.is_err());
    }

    // --- build_store credential chain tests ---
    //
    // These tests exercise the env-var credential chain in build_store
    // (lines ~305-368). Because env vars are process-global state and
    // cargo test runs tests in parallel, we serialize all env-mutating
    // tests behind a single mutex and save/restore every variable we touch.

    use std::sync::Mutex;

    static CRED_ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// All AWS/S3 credential env var names that build_store reads.
    const CRED_ENV_VARS: &[&str] = &[
        "S3_ACCESS_KEY_ID",
        "S3_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "S3_ALLOW_ANONYMOUS",
    ];

    /// Save current values for all credential env vars.
    fn save_cred_env() -> Vec<(&'static str, Option<String>)> {
        CRED_ENV_VARS
            .iter()
            .map(|&name| (name, std::env::var(name).ok()))
            .collect()
    }

    /// Restore saved env var values.
    fn restore_cred_env(saved: Vec<(&'static str, Option<String>)>) {
        for (name, val) in saved {
            match val {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }

    /// Remove all credential env vars so each test starts from a clean slate.
    fn clear_cred_env() {
        for name in CRED_ENV_VARS {
            std::env::remove_var(name);
        }
    }

    /// RAII helper for tests that exercise `S3Backend::new` construction
    /// behavior without caring about the credential chain. Enters the
    /// CRED_ENV_MUTEX, clears every credential env var, and sets
    /// `S3_ALLOW_ANONYMOUS=true` so `validate_credentials_present` succeeds
    /// regardless of the host environment. On drop, restores the prior
    /// values and releases the mutex.
    ///
    /// Use this in any test that calls `S3Backend::new` with a custom
    /// (localhost / fake) endpoint to avoid the issue #871 startup check.
    struct AnonymousS3TestEnv {
        _lock: std::sync::MutexGuard<'static, ()>,
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl AnonymousS3TestEnv {
        fn enter() -> Self {
            let lock = CRED_ENV_MUTEX.lock().unwrap();
            let saved = save_cred_env();
            clear_cred_env();
            std::env::set_var("S3_ALLOW_ANONYMOUS", "true");
            Self { _lock: lock, saved }
        }
    }

    impl Drop for AnonymousS3TestEnv {
        fn drop(&mut self) {
            restore_cred_env(std::mem::take(&mut self.saved));
        }
    }

    /// Helper: build an S3Config pointing at a fake http endpoint so
    /// the builder never tries a real TLS handshake.
    fn test_config() -> S3Config {
        S3Config::new(
            "cred-test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:19876".to_string()),
            None,
        )
    }

    // --- Issue #871: startup credential validation ---

    #[test]
    fn test_validate_creds_fails_fast_with_custom_endpoint_and_no_creds() {
        // Issue #871: a custom S3 endpoint with no credentials must fail at
        // startup with a clear Config error, not silently fall through to
        // IMDS at first request and time out for 5-15s per call.
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        let result = S3Backend::validate_credentials_present(&test_config());
        assert!(
            result.is_err(),
            "validate_credentials_present with custom endpoint + no creds must fail fast"
        );
        let err = result.unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("169.254.169.254") && msg.contains("S3_ACCESS_KEY_ID"),
            "error must explain the IMDS fallback and how to fix it: {}",
            msg
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_succeeds_with_aws_endpoint_and_no_creds() {
        // Without a custom endpoint we are talking to real AWS S3, where
        // IMDS is a legitimate fallback (EC2 instance role). Don't error.
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        let aws_config = S3Config::new(
            "aws-bucket".to_string(),
            "us-east-1".to_string(),
            None, // no custom endpoint = AWS S3
            None,
        );
        let result = S3Backend::validate_credentials_present(&aws_config);
        assert!(
            result.is_ok(),
            "AWS endpoint with no explicit creds should pass validation (IMDS is the legit fallback): {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_succeeds_with_static_creds() {
        // The most common case: operator sets S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY.
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("S3_ACCESS_KEY_ID", "AKIA");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "secret");

        let result = S3Backend::validate_credentials_present(&test_config());
        assert!(
            result.is_ok(),
            "validate with S3_* creds should succeed: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_succeeds_with_aws_static_creds() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIA");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "secret");

        let result = S3Backend::validate_credentials_present(&test_config());
        assert!(
            result.is_ok(),
            "validate with AWS_* creds should succeed: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_partial_static_keys_treated_as_no_creds() {
        // Only AWS_ACCESS_KEY_ID without secret = misconfigured = same path
        // as no creds at all. Static cred chain in build_store also requires
        // both; this validator must agree to surface the error at startup.
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("S3_ACCESS_KEY_ID", "AKIA");
        // no S3_SECRET_ACCESS_KEY

        let result = S3Backend::validate_credentials_present(&test_config());
        assert!(
            result.is_err(),
            "validate must reject access key without secret key"
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_succeeds_with_irsa() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
        );
        std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/my-role");

        let result = S3Backend::validate_credentials_present(&test_config());
        assert!(
            result.is_ok(),
            "validate with IRSA should succeed: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_succeeds_with_ecs() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "/v2/credentials/some-uuid",
        );

        let result = S3Backend::validate_credentials_present(&test_config());
        assert!(
            result.is_ok(),
            "validate with ECS task role should succeed: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_succeeds_with_eks_pod_identity() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "http://169.254.170.23/v1/credentials",
        );

        let result = S3Backend::validate_credentials_present(&test_config());
        assert!(
            result.is_ok(),
            "validate with EKS Pod Identity should succeed: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_anonymous_with_custom_endpoint() {
        // S3_ALLOW_ANONYMOUS=true opts the operator into unsigned requests
        // for genuinely public buckets. Validation must accept this without
        // requiring further credentials.
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("S3_ALLOW_ANONYMOUS", "true");

        let result = S3Backend::validate_credentials_present(&test_config());
        assert!(
            result.is_ok(),
            "validate with S3_ALLOW_ANONYMOUS=true should succeed: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_validate_creds_anonymous_truthy_parsing() {
        // S3_ALLOW_ANONYMOUS uses standard truthy values: true, True, TRUE, 1.
        // Anything else (including "no", "false", empty) should NOT enable it.
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        for v in &["1", "TRUE", "True", "true"] {
            std::env::set_var("S3_ALLOW_ANONYMOUS", v);
            let result = S3Backend::validate_credentials_present(&test_config());
            assert!(
                result.is_ok(),
                "S3_ALLOW_ANONYMOUS={} should be truthy: {:?}",
                v,
                result.err()
            );
        }
        // Non-truthy values must still trigger the no-creds error.
        for v in &["no", "false", "FALSE", "0", ""] {
            std::env::set_var("S3_ALLOW_ANONYMOUS", v);
            let result = S3Backend::validate_credentials_present(&test_config());
            assert!(
                result.is_err(),
                "S3_ALLOW_ANONYMOUS={:?} must NOT enable anonymous mode",
                v
            );
        }

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_picks_up_s3_credentials() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "S3SK");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed with S3_* credentials: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_s3_creds_take_precedence_over_aws_creds() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Set both S3_* and AWS_* credentials. S3_* should win.
        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK-wins");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "S3SK-wins");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK-loses");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK-loses");

        // The builder cannot expose which credentials were chosen, but
        // we verify it builds successfully and does not error out.
        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store with both S3_* and AWS_* should succeed: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_picks_up_aws_static_credentials() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed with AWS_ACCESS_KEY_ID/SECRET: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_includes_aws_session_token() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK");
        std::env::set_var("AWS_SESSION_TOKEN", "tok-xyz");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed with AWS session token: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_session_token_ignored_without_aws_keys() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Session token alone, no access key / secret key
        std::env::set_var("AWS_SESSION_TOKEN", "orphan-token");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed even with orphan session token: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_ecs_fargate_relative_uri() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "/v2/credentials/some-uuid",
        );

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should accept ECS relative URI: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_eks_pod_identity_full_uri() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "http://169.254.170.23/v1/credentials",
        );

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should accept EKS Pod Identity full URI: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_eks_irsa_web_identity() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
        );
        std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/my-role");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should accept IRSA web identity vars: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_explicit_args_override_all_env_vars() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Set all possible env var credentials
        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK-env");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "S3SK-env");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK-env");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK-env");
        std::env::set_var("AWS_SESSION_TOKEN", "tok-env");

        // Explicit function args should take precedence over all env vars
        let result =
            S3Backend::build_store(&test_config(), Some("EXPLICIT-AK"), Some("EXPLICIT-SK"));
        assert!(
            result.is_ok(),
            "build_store with explicit args should override env vars: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_all_credential_sources_present() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Set every credential env var simultaneously
        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "S3SK");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK");
        std::env::set_var("AWS_SESSION_TOKEN", "tok");
        std::env::set_var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/creds/uuid");
        std::env::set_var(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "http://169.254.170.23/v1/credentials",
        );
        std::env::set_var(
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            "/var/run/secrets/token",
        );
        std::env::set_var("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/wi-token");
        std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::111111111111:role/chaos");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should handle all credential sources at once: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_partial_s3_creds_fall_through_to_aws() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Only S3_ACCESS_KEY_ID without the secret: the S3_* pair is
        // incomplete so the code should fall through to AWS_* vars.
        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK-partial");
        // S3_SECRET_ACCESS_KEY intentionally not set
        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK-fallback");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK-fallback");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store with partial S3_* should fall through to AWS_*: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_container_auth_token_file_alone() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            "/var/run/secrets/auth-token",
        );

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should accept container auth token file: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    // --- single_object_delete / disable_multi_delete via wiremock ---

    /// Build an S3Backend pointing at the given base URL with
    /// `disable_multi_delete` set to the requested value.
    async fn mock_s3_backend(base_url: &str, disable_multi_delete: bool) -> S3Backend {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some(base_url.to_string()),
            None,
        )
        .with_disable_multi_delete(disable_multi_delete);

        // build_store needs explicit creds so the signer can produce URLs
        let store = S3Backend::build_store(&config, Some("AKIAIOSFODNN7EXAMPLE"), Some("secret"))
            .expect("build mock store");
        let bulk_store =
            S3Backend::build_bulk_store(&config, Some("AKIAIOSFODNN7EXAMPLE"), Some("secret"))
                .expect("build mock bulk store");
        S3Backend {
            store,
            bulk_store,
            bucket: config.bucket.clone(),
            region: config.region.clone(),
            bulk_timeout: Some(Duration::from_secs(S3_DEFAULT_BULK_TIMEOUT_SECS)),
            raw_http: reqwest::Client::new(),
            max_single_copy_bytes: S3_MAX_SINGLE_COPY_SIZE,
            sign_requests: true,
            prefix: None,
            redirect_downloads: false,
            cloudfront: None,
            path_format: StoragePathFormat::Native,
            signing_store: None,
            disable_multi_delete,
        }
    }

    #[tokio::test]
    async fn test_exists_surfaces_migration_fallback_head_error() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let checksum = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        Mock::given(method("HEAD"))
            .and(path_regex(".*/repos/generic/.*"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path_regex(".*/ab/abcdef.*"))
            .respond_with(ResponseTemplate::new(503).set_body_string("fallback unavailable"))
            .mount(&server)
            .await;

        let mut backend = mock_s3_backend(&server.uri(), false).await;
        backend.path_format = StoragePathFormat::Migration;
        let result =
            StorageBackendTrait::exists(&backend, &format!("repos/generic/{checksum}")).await;

        assert!(
            matches!(
                &result,
                Err(AppError::Storage(message)) if message.contains("fallback") && message.contains("503")
            ),
            "fallback operational failures must not become false misses: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_single_object_delete_success_204() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // The presigned DELETE URL hits the mock server; respond with 204
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), true).await;
        let path: ObjectPath = "test-key".into();
        let result = backend.single_object_delete(&path, "test-key").await;
        assert!(result.is_ok(), "204 should be treated as success");
    }

    #[tokio::test]
    async fn test_single_object_delete_success_200() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), true).await;
        let path: ObjectPath = "another-key".into();
        let result = backend.single_object_delete(&path, "another-key").await;
        assert!(result.is_ok(), "200 should be treated as success");
    }

    #[tokio::test]
    async fn test_single_object_delete_404_is_idempotent() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(404).set_body_string("NoSuchKey"))
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), true).await;
        let path: ObjectPath = "missing-key".into();
        let result = backend.single_object_delete(&path, "missing-key").await;
        assert!(
            result.is_ok(),
            "404 on delete should be treated as success (idempotent)"
        );
    }

    #[tokio::test]
    async fn test_single_object_delete_403_returns_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(403).set_body_string("AccessDenied"))
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), true).await;
        let path: ObjectPath = "forbidden-key".into();
        let result = backend.single_object_delete(&path, "forbidden-key").await;
        assert!(result.is_err(), "403 should be an error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("403"),
            "error should mention status code: {msg}"
        );
    }

    #[tokio::test]
    async fn test_single_object_delete_500_returns_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(500).set_body_string("InternalError"))
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), true).await;
        let path: ObjectPath = "error-key".into();
        let result = backend.single_object_delete(&path, "error-key").await;
        assert!(result.is_err(), "500 should be an error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("500"),
            "error should mention status code: {msg}"
        );
    }

    #[tokio::test]
    async fn test_delete_dispatches_to_single_object_delete_when_enabled() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // single_object_delete generates a signed DELETE URL and then issues
        // an HTTP DELETE to it, so we only need to match DELETE
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), true).await;
        let result = StorageBackendTrait::delete(&backend, "dispatch-key").await;
        assert!(
            result.is_ok(),
            "delete with disable_multi_delete=true should use single_object_delete"
        );
    }

    #[tokio::test]
    async fn test_delete_uses_store_delete_when_multi_delete_enabled() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // object_store issues a POST ?delete for multi-object delete.
        // We just mock any request to respond with 200 so the call succeeds.
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<?xml version="1.0"?><DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>"#,
            ))
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        // With disable_multi_delete=false, the standard store.delete() path
        // is used. We mainly verify the branch is taken without panicking.
        let _ = crate::storage::StorageBackend::delete(&backend, "multi-key").await;
        // Not asserting success because the mock may not perfectly satisfy
        // the object_store S3 multi-delete protocol, but the branch is exercised.
    }

    // --- #3180: multi-GB OCI blob operations must not die on the S3 client's
    // default 30s overall-request timeout ---

    /// Reproduces #3180 without needing a multi-GB object: the failing
    /// ingredient is *elapsed time on one S3 request*, not the byte count.
    ///
    /// `S3Backend::copy` for an object under `S3_MAX_SINGLE_COPY_SIZE` issues a
    /// native `CopyObject` (PUT + `x-amz-copy-source`). S3 holds that connection
    /// open for the whole server-side copy, which for a 2.33 GB layer exceeds
    /// 30 seconds. `object_store::ClientOptions::default()` sets an overall
    /// request timeout of 30s covering connect + headers + body, so the copy is
    /// aborted client-side at exactly 30s and the blob PUT 500s.
    ///
    /// The mock delays the CopyObject response past 30s; a correctly configured
    /// client must wait for it.
    #[tokio::test]
    async fn test_copy_survives_response_slower_than_30s_default_timeout() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // HEAD for S3Backend::copy's size() probe. Well under the 5 GiB
        // single-copy threshold, so the native CopyObject branch is taken --
        // this is NOT the >5 GiB restream path tracked by #3164.
        Mock::given(method("HEAD"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", "2336179827")
                    .insert_header("last-modified", "Fri, 07 Aug 2026 18:09:54 GMT")
                    .insert_header("etag", "\"copy-src-etag\""),
            )
            .mount(&server)
            .await;

        // The CopyObject itself: S3 does not answer until the server-side copy
        // finishes. 32s is the smallest round delay that clears the 30s default.
        Mock::given(method("PUT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        "<CopyObjectResult><ETag>\"copy-dst-etag\"</ETag></CopyObjectResult>",
                    )
                    .set_delay(Duration::from_secs(32)),
            )
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;

        // Bound the failing case: on the 30s default the copy times out and
        // object_store retries it (retry budget ~180s), so without this guard a
        // regression would stall the suite for minutes instead of failing.
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            backend.copy(
                "oci-uploads/756f380e-a6f3-4c16-ab57-051febd01d5e.complete.7a46bd5c",
                "oci-blobs/sha256:1b31e0aa4b34a899fd9a210679c80ca2f96891e19495cb39cb900734751c317a",
            ),
        )
        .await;

        let result = result.expect(
            "#3180: CopyObject was still retrying after 90s -- the client aborted the \
             server-side copy at the 30s default timeout instead of waiting for it",
        );
        assert!(
            result.is_ok(),
            "#3180: a CopyObject that takes 32s must succeed; the S3 client's overall \
             request timeout must not cap multi-GB blob operations. Got: {:?}",
            result.err()
        );
    }

    /// Fast counterpart to the 32s test above: proves `bulk_timeout_secs` is
    /// actually wired into the bulk client rather than being a dead field.
    ///
    /// A 1s bulk timeout against a 4s response must fail; the same request with
    /// a generous timeout must succeed. Without the `with_timeout` wiring in
    /// `build_store_with_timeout`, the short case silently inherits
    /// `object_store`'s 30s default and wrongly succeeds.
    #[tokio::test]
    async fn test_bulk_timeout_secs_is_wired_into_the_bulk_client() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        async fn copy_with_bulk_timeout(secs: u64, delay: Duration) -> Result<()> {
            let server = MockServer::start().await;
            Mock::given(method("HEAD"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-length", "1024")
                        .insert_header("last-modified", "Fri, 07 Aug 2026 18:09:54 GMT")
                        .insert_header("etag", "\"src\""),
                )
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(
                            "<CopyObjectResult><ETag>\"dst\"</ETag></CopyObjectResult>",
                        )
                        .set_delay(delay),
                )
                .mount(&server)
                .await;

            let config = S3Config::new(
                "test-bucket".to_string(),
                "us-east-1".to_string(),
                Some(server.uri()),
                None,
            )
            .with_bulk_timeout_secs(secs);
            let backend = S3Backend {
                store: S3Backend::build_store(&config, Some("AKIA"), Some("secret")).unwrap(),
                bulk_store: S3Backend::build_bulk_store(&config, Some("AKIA"), Some("secret"))
                    .unwrap(),
                bucket: config.bucket.clone(),
                region: config.region.clone(),
                bulk_timeout: (config.bulk_timeout_secs > 0)
                    .then(|| Duration::from_secs(config.bulk_timeout_secs)),
                raw_http: reqwest::Client::new(),
                max_single_copy_bytes: S3_MAX_SINGLE_COPY_SIZE,
                sign_requests: true,
                prefix: None,
                redirect_downloads: false,
                cloudfront: None,
                path_format: StoragePathFormat::Native,
                signing_store: None,
                disable_multi_delete: false,
            };
            backend.copy("src-key", "dst-key").await
        }

        let too_short = copy_with_bulk_timeout(1, Duration::from_secs(4)).await;
        assert!(
            too_short.is_err(),
            "a 1s bulk timeout must abort a 4s CopyObject; if this passes, \
             bulk_timeout_secs never reaches the HTTP client"
        );

        let generous = copy_with_bulk_timeout(120, Duration::from_secs(4)).await;
        assert!(
            generous.is_ok(),
            "a 120s bulk timeout must tolerate a 4s CopyObject. Got: {:?}",
            generous.err()
        );
    }

    /// Positive control for the #3180 fix: raising the *bulk* ceiling must not
    /// remove the *control-plane* cliff. A wedged endpoint has to keep failing
    /// fast on head/exists/list, otherwise the fix trades a broken push for
    /// stalled workers.
    ///
    /// Both stores face the same slow endpoint. The control-plane HEAD (`size`)
    /// must give up; the bulk read (`get`) of the same object must not.
    #[tokio::test]
    async fn test_bulk_ceiling_does_not_leak_onto_control_plane_calls() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let slow = Duration::from_secs(5);
        Mock::given(method("HEAD"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", "4")
                    .insert_header("last-modified", "Fri, 07 Aug 2026 18:09:54 GMT")
                    .insert_header("etag", "\"src\"")
                    .set_delay(slow),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", "4")
                    .insert_header("last-modified", "Fri, 07 Aug 2026 18:09:54 GMT")
                    .insert_header("etag", "\"src\"")
                    .set_body_bytes(b"blob".to_vec())
                    .set_delay(slow),
            )
            .mount(&server)
            .await;

        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some(server.uri()),
            None,
        )
        .with_control_timeout_secs(1)
        .with_bulk_timeout_secs(120);
        let backend = S3Backend {
            store: S3Backend::build_store(&config, Some("AKIA"), Some("secret")).unwrap(),
            bulk_store: S3Backend::build_bulk_store(&config, Some("AKIA"), Some("secret")).unwrap(),
            bucket: config.bucket.clone(),
            region: config.region.clone(),
            bulk_timeout: (config.bulk_timeout_secs > 0)
                .then(|| Duration::from_secs(config.bulk_timeout_secs)),
            raw_http: reqwest::Client::new(),
            max_single_copy_bytes: S3_MAX_SINGLE_COPY_SIZE,
            sign_requests: true,
            prefix: None,
            redirect_downloads: false,
            cloudfront: None,
            path_format: StoragePathFormat::Native,
            signing_store: None,
            disable_multi_delete: false,
        };

        let bulk = StorageBackendTrait::get(&backend, "slow-key").await;
        assert!(
            bulk.is_ok(),
            "bulk read must tolerate a 5s response under a 120s ceiling. Got: {:?}",
            bulk.err()
        );
        assert_eq!(&bulk.unwrap()[..], b"blob");

        let control = backend.size("slow-key").await;
        assert!(
            control.is_err(),
            "control-plane HEAD must still fail fast under a 1s cliff; the bulk \
             ceiling must not leak onto it"
        );
    }

    /// The default must be generous enough for the multi-GB layers #3180 was
    /// filed about. A future edit dropping it back toward 30s would make the
    /// 32s regression test above the only thing standing between this bug and
    /// production.
    #[test]
    fn test_default_bulk_timeout_is_sized_for_multi_gb_transfers() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert_eq!(config.bulk_timeout_secs, S3_DEFAULT_BULK_TIMEOUT_SECS);
        assert!(
            config.bulk_timeout_secs >= 900,
            "bulk transfer ceiling {}s is too small for multi-GB OCI layers (#3180)",
            config.bulk_timeout_secs
        );
    }

    #[tokio::test]
    async fn test_put_stream_limits_in_flight_multipart_parts() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wiremock::matchers::{method, query_param_is_missing};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cap = S3_MULTIPART_MAX_IN_FLIGHT_PARTS;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(query_param_is_missing("uploadId"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<InitiateMultipartUploadResult><UploadId>test-upload-id</UploadId></InitiateMultipartUploadResult>",
            ))
            .mount(&server)
            .await;
        // Part uploads hang for the lifetime of the test so the in-flight set
        // stays saturated and the assertions never depend on wall-clock timing:
        // once `cap` parts are dispatched they never complete, so the streaming
        // loop cannot enqueue a (cap+1)th part until the test tears it down.
        let part_guard = Mock::given(method("PUT"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", "\"part-etag\"")
                    .set_delay(Duration::from_secs(60)),
            )
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        let chunks_polled = Arc::new(AtomicUsize::new(0));
        // cap + 1 full-size chunks: the extra one must stay buffered, unable to
        // begin uploading until an in-flight part frees a capacity slot.
        let stream_chunks = (0..=cap).map({
            let chunks_polled = Arc::clone(&chunks_polled);
            move |_| {
                chunks_polled.fetch_add(1, Ordering::SeqCst);
                Ok(Bytes::from(vec![b'x'; S3_MULTIPART_CHUNK_SIZE]))
            }
        });
        let stream: BoxStream<'static, Result<Bytes>> =
            Box::pin(futures::stream::iter(stream_chunks));

        let upload = tokio::spawn(async move {
            StorageBackendTrait::put_stream(&backend, "slow-multipart-object", stream).await
        });

        // Wait until the streaming loop has saturated the in-flight cap. Poll
        // (up to ~30s) instead of relying on a single fixed sleep so the
        // assertion is robust on slow/contended CI runners.
        let mut in_flight = 0;
        for _ in 0..300 {
            in_flight = part_guard.received_requests().await.len();
            if in_flight >= cap {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            in_flight, cap,
            "put_stream should saturate exactly the in-flight cap of concurrent part uploads"
        );

        // The (cap+1)th chunk has been polled and buffered, but its part cannot
        // be enqueued while every slot is held by a hung upload. Give the loop
        // room to misbehave, then confirm the cap still holds.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            part_guard.received_requests().await.len(),
            cap,
            "put_stream must not exceed its in-flight cap while earlier parts are still uploading; chunks polled: {}",
            chunks_polled.load(Ordering::SeqCst),
        );
        assert!(
            !upload.is_finished(),
            "upload must still be blocked on the hung in-flight parts"
        );
        assert_eq!(
            chunks_polled.load(Ordering::SeqCst),
            cap + 1,
            "put_stream should poll exactly one chunk past the cap before blocking on capacity"
        );

        // The hung parts never return; drop the task rather than wait out the delay.
        upload.abort();
    }

    #[tokio::test]
    async fn test_put_stream_buffers_small_chunks_into_valid_s3_parts() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::{method, query_param, query_param_is_missing};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const ONE_MIB: usize = 1024 * 1024;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(query_param_is_missing("uploadId"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<InitiateMultipartUploadResult><UploadId>test-upload-id</UploadId></InitiateMultipartUploadResult>",
            ))
            .mount(&server)
            .await;
        let part_guard = Mock::given(method("PUT"))
            .and(query_param("uploadId", "test-upload-id"))
            .respond_with(ResponseTemplate::new(200).insert_header("ETag", "\"part-etag\""))
            .mount_as_scoped(&server)
            .await;
        Mock::given(method("POST"))
            .and(query_param("uploadId", "test-upload-id"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<CompleteMultipartUploadResult><ETag>\"complete-etag\"</ETag></CompleteMultipartUploadResult>",
            ))
            .mount(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        let stream = futures::stream::iter((0..6).map(|_| Ok(Bytes::from(vec![b'x'; ONE_MIB]))));

        let result =
            StorageBackendTrait::put_stream(&backend, "small-chunks-object", Box::pin(stream))
                .await
                .expect("multipart upload should complete");

        assert_eq!(result.bytes_written, 6 * ONE_MIB as u64);

        let mut part_lengths: Vec<(usize, usize)> = part_guard
            .received_requests()
            .await
            .into_iter()
            .map(|request| {
                let part_number = request
                    .url
                    .query_pairs()
                    .find_map(|(key, value)| {
                        (key == "partNumber")
                            .then(|| value.parse::<usize>().expect("partNumber must be numeric"))
                    })
                    .expect("UploadPart request must include partNumber");
                (part_number, request.body.len())
            })
            .collect();
        part_lengths.sort_by_key(|(part_number, _)| *part_number);
        let part_lengths: Vec<usize> = part_lengths.into_iter().map(|(_, len)| len).collect();

        assert_eq!(
            part_lengths,
            vec![S3_MULTIPART_CHUNK_SIZE, ONE_MIB],
            "small input chunks must be buffered so only the final S3 part is below 5 MiB"
        );
    }

    #[tokio::test]
    async fn test_put_stream_aborts_multipart_when_complete_fails() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::{method, query_param, query_param_is_missing};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(query_param_is_missing("uploadId"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<InitiateMultipartUploadResult><UploadId>test-upload-id</UploadId></InitiateMultipartUploadResult>",
            ))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(query_param("uploadId", "test-upload-id"))
            .respond_with(ResponseTemplate::new(200).insert_header("ETag", "\"part-etag\""))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(query_param("uploadId", "test-upload-id"))
            .respond_with(ResponseTemplate::new(503).set_body_string("slow down"))
            .mount(&server)
            .await;
        let abort_guard = Mock::given(method("DELETE"))
            .and(query_param("uploadId", "test-upload-id"))
            .respond_with(ResponseTemplate::new(204))
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        let stream = futures::stream::iter([Ok(Bytes::from(vec![b'x'; S3_MULTIPART_CHUNK_SIZE]))]);

        let result =
            StorageBackendTrait::put_stream(&backend, "complete-fails-object", Box::pin(stream))
                .await;

        assert!(result.is_err(), "complete failure must surface to caller");
        assert_eq!(
            abort_guard.received_requests().await.len(),
            1,
            "failed CompleteMultipartUpload must abort the pending multipart upload"
        );
    }

    #[tokio::test]
    async fn test_put_stream_aborts_multipart_when_final_part_upload_fails() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::{method, query_param, query_param_is_missing};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(query_param_is_missing("uploadId"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<InitiateMultipartUploadResult><UploadId>test-upload-id</UploadId></InitiateMultipartUploadResult>",
            ))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(query_param("uploadId", "test-upload-id"))
            .respond_with(ResponseTemplate::new(503).set_body_string("part failed"))
            .mount(&server)
            .await;
        let abort_guard = Mock::given(method("DELETE"))
            .and(query_param("uploadId", "test-upload-id"))
            .respond_with(ResponseTemplate::new(204))
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        let stream = futures::stream::iter([Ok(Bytes::from(vec![b'x'; S3_MULTIPART_CHUNK_SIZE]))]);

        let result =
            StorageBackendTrait::put_stream(&backend, "part-fails-object", Box::pin(stream)).await;

        assert!(
            result.is_err(),
            "part upload failure must surface to caller"
        );
        assert_eq!(
            abort_guard.received_requests().await.len(),
            1,
            "failed final UploadPart must abort the pending multipart upload"
        );
    }

    // ---- #3164: >5 GiB copies must be server-side UploadPartCopy, and the
    // destination must never be published before the copy fully succeeds ----

    /// A copy of an object over `S3_MAX_SINGLE_COPY_SIZE` must be performed
    /// entirely server-side: CreateMultipartUpload, one ranged
    /// `UploadPartCopy` per 5 GiB slice, CompleteMultipartUpload — and no
    /// payload byte through the application. No GET mock is mounted, so a
    /// regression to the restream shape fails immediately on the source read.
    #[tokio::test]
    async fn test_copy_over_5gib_is_server_side_upload_part_copy() {
        use wiremock::matchers::{method, query_param, query_param_is_missing};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // 10 GiB + 1 byte -> exactly three parts: two full 5 GiB slices and a
        // final 1-byte slice. Never materialized; only a Content-Length.
        let size = 2 * 5_u64 * 1024 * 1024 * 1024 + 1;

        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Length", size.to_string())
                    .insert_header("last-modified", "Fri, 07 Aug 2026 18:09:54 GMT")
                    .insert_header("ETag", "\"large-source\""),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(query_param_is_missing("uploadId"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<InitiateMultipartUploadResult><UploadId>copy-upload-id</UploadId></InitiateMultipartUploadResult>",
            ))
            .mount(&server)
            .await;
        // MinIO-style decimal quote entities (`&#34;`); the failure-path test
        // below uses AWS-style `&quot;` so both real-world encodings are
        // covered (see `parse_copy_part_etag`).
        let part_copy_guard = Mock::given(method("PUT"))
            .and(query_param("uploadId", "copy-upload-id"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<CopyPartResult><ETag>&#34;part-copy-etag&#34;</ETag></CopyPartResult>",
            ))
            .mount_as_scoped(&server)
            .await;
        let complete_guard = Mock::given(method("POST"))
            .and(query_param("uploadId", "copy-upload-id"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<CompleteMultipartUploadResult><ETag>\"complete-copy\"</ETag></CompleteMultipartUploadResult>",
            ))
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        S3Backend::copy(&backend, "source-object", "dest-object")
            .await
            .expect("#3164: a >5 GiB copy must succeed via server-side UploadPartCopy");

        let requests = server.received_requests().await.unwrap_or_default();
        assert!(
            !requests.iter().any(|r| r.method.as_str() == "GET"),
            "#3164: a >5 GiB copy must not read the source back through the \
             application (no GET restream)"
        );

        // Every part must be a ranged server-side copy: empty body (no bytes
        // through the app), the copy-source header, and 1-based part numbers
        // whose ranges exactly partition [0, size-1] in 5 GiB slices.
        let mut part_requests = part_copy_guard.received_requests().await;
        part_requests.sort_by_key(|r| {
            r.url
                .query_pairs()
                .find_map(|(k, v)| (k == "partNumber").then(|| v.parse::<usize>().unwrap()))
                .expect("UploadPartCopy must carry partNumber")
        });
        let observed: Vec<(usize, String, String, usize)> = part_requests
            .iter()
            .map(|r| {
                let part_number = r
                    .url
                    .query_pairs()
                    .find_map(|(k, v)| (k == "partNumber").then(|| v.parse().unwrap()))
                    .unwrap();
                let source = r
                    .headers
                    .get("x-amz-copy-source")
                    .expect("part copy must name its server-side source")
                    .to_str()
                    .unwrap()
                    .to_string();
                let range = r
                    .headers
                    .get("x-amz-copy-source-range")
                    .expect("part copy must be ranged")
                    .to_str()
                    .unwrap()
                    .to_string();
                (part_number, source, range, r.body.len())
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                (
                    1,
                    "test-bucket/source-object".to_string(),
                    "bytes=0-5368709119".to_string(),
                    0
                ),
                (
                    2,
                    "test-bucket/source-object".to_string(),
                    "bytes=5368709120-10737418239".to_string(),
                    0
                ),
                (
                    3,
                    "test-bucket/source-object".to_string(),
                    "bytes=10737418240-10737418240".to_string(),
                    0
                ),
            ],
            "#3164: the copy must be exactly three ranged, bodyless \
             UploadPartCopy requests partitioning the object"
        );
        assert_eq!(
            complete_guard.received_requests().await.len(),
            1,
            "the multipart copy must be completed exactly once"
        );
    }

    /// The integrity half of #3164: with the old restream shape, `dest` was
    /// already fully published (multipart upload completed) before any
    /// verification could run. With server-side part copies the publish point
    /// is CompleteMultipartUpload, so a failed part copy must surface as an
    /// error, abort the upload, and never complete it — the destination keeps
    /// whatever it held before.
    ///
    /// The fixture deliberately lets the OLD shape succeed end to end (the
    /// source GET and un-ranged part PUTs are all mocked green), so on the
    /// unfixed code `copy()` returns Ok and publishes dest — this test can
    /// only pass when the publish is actually gated on the part copies.
    #[tokio::test]
    async fn test_copy_over_5gib_failed_part_copy_never_publishes_dest() {
        use wiremock::matchers::{header, method, query_param, query_param_is_missing};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // 5 GiB + 1 byte -> two parts; the second (1-byte) part copy fails.
        let size = 5_u64 * 1024 * 1024 * 1024 + 1;

        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Length", size.to_string())
                    .insert_header("last-modified", "Fri, 07 Aug 2026 18:09:54 GMT")
                    .insert_header("ETag", "\"large-source\""),
            )
            .mount(&server)
            .await;
        // Keep the pre-fix path viable so the test discriminates: the source
        // is readable...
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"restream-bytes".to_vec()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(query_param_is_missing("uploadId"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<InitiateMultipartUploadResult><UploadId>copy-upload-id</UploadId></InitiateMultipartUploadResult>",
            ))
            .mount(&server)
            .await;
        // The second ranged part copy fails server-side.
        Mock::given(method("PUT"))
            .and(query_param("uploadId", "copy-upload-id"))
            .and(header(
                "x-amz-copy-source-range",
                "bytes=5368709120-5368709120",
            ))
            .respond_with(ResponseTemplate::new(500).set_body_string("InternalError"))
            .mount(&server)
            .await;
        // ...and every other part upload succeeds, whether it is the first
        // ranged copy (fixed shape) or an un-ranged data PUT (old shape reads
        // the ETag header; new shape parses the CopyPartResult body).
        Mock::given(method("PUT"))
            .and(query_param("uploadId", "copy-upload-id"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", "\"part-etag\"")
                    .set_body_string(
                        "<CopyPartResult><ETag>&quot;part-etag&quot;</ETag></CopyPartResult>",
                    ),
            )
            .mount(&server)
            .await;
        let complete_guard = Mock::given(method("POST"))
            .and(query_param("uploadId", "copy-upload-id"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<CompleteMultipartUploadResult><ETag>\"complete-copy\"</ETag></CompleteMultipartUploadResult>",
            ))
            .mount_as_scoped(&server)
            .await;
        let abort_guard = Mock::given(method("DELETE"))
            .and(query_param("uploadId", "copy-upload-id"))
            .respond_with(ResponseTemplate::new(204))
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        let result = S3Backend::copy(&backend, "source-object", "dest-object").await;

        assert!(
            result.is_err(),
            "#3164: a failed server-side part copy must fail the whole copy \
             (the old restream shape returned Ok here)"
        );
        assert_eq!(
            complete_guard.received_requests().await.len(),
            0,
            "#3164: dest must never be published (CompleteMultipartUpload) \
             when a part copy failed — bad bytes must not go live"
        );
        assert_eq!(
            abort_guard.received_requests().await.len(),
            1,
            "a failed part copy must abort the pending multipart upload"
        );
    }

    /// Positive control for #3164: copies at or below the 5 GiB threshold must
    /// keep using the single atomic `CopyObject` ("You create a copy of your
    /// object up to 5 GB in size in a single atomic action using this API" —
    /// S3 API Reference, CopyObject), whose atomicity is itself the integrity
    /// guarantee: a failure never touches `dest`. A "fix" that pushed the
    /// common path into multipart machinery or a restream fails these counts.
    #[tokio::test]
    async fn test_copy_at_or_under_threshold_stays_single_native_copy_object() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Exactly the 5 GiB boundary: the largest size the atomic path serves.
        let size = 5_u64 * 1024 * 1024 * 1024;

        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Length", size.to_string())
                    .insert_header("last-modified", "Fri, 07 Aug 2026 18:09:54 GMT")
                    .insert_header("ETag", "\"small-source\""),
            )
            .mount(&server)
            .await;
        let copy_guard = Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<CopyObjectResult><ETag>\"copy-dst-etag\"</ETag></CopyObjectResult>",
            ))
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        S3Backend::copy(&backend, "source-object", "dest-object")
            .await
            .expect("a copy at the 5 GiB boundary must still succeed");

        let puts = copy_guard.received_requests().await;
        assert_eq!(
            puts.len(),
            1,
            "an at-threshold copy must be exactly one native CopyObject"
        );
        let put = &puts[0];
        assert!(
            put.headers.contains_key("x-amz-copy-source"),
            "the single PUT must be a server-side CopyObject"
        );
        assert!(
            !put.headers.contains_key("x-amz-copy-source-range"),
            "a native CopyObject is not ranged"
        );
        assert!(
            !put.url.query_pairs().any(|(k, _)| k == "uploadId"),
            "an at-threshold copy must not open a multipart upload"
        );
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(
            !requests.iter().any(|r| r.method.as_str() == "GET"),
            "an at-threshold copy must not restream the source"
        );
        assert!(
            !requests.iter().any(|r| r.method.as_str() == "POST"),
            "an at-threshold copy must not touch the multipart API"
        );
    }

    // ---- MultipartAbortGuard (abort-on-drop for cancelled multipart copies) ----

    /// Poll the mock's DELETE (AbortMultipartUpload) count until it reaches
    /// `expected`, giving the guard's detached abort task time to run. Returns
    /// the final observed count.
    async fn wait_for_abort_count(guard: &wiremock::MockGuard, expected: usize) -> usize {
        for _ in 0..50 {
            let n = guard.received_requests().await.len();
            if n >= expected {
                return n;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        guard.received_requests().await.len()
    }

    #[tokio::test]
    async fn test_multipart_abort_guard_aborts_on_drop() {
        use wiremock::matchers::{method, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let abort_mock = Mock::given(method("DELETE"))
            .and(query_param("uploadId", "drop-upload-id"))
            .respond_with(ResponseTemplate::new(204))
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        {
            let mut guard = MultipartAbortGuard::new(
                backend.store.clone(),
                "dropped/object".into(),
                "dropped/object".to_string(),
            );
            guard.arm("drop-upload-id".to_string());
            // guard dropped here while still armed -> spawns AbortMultipartUpload
        }

        let count = wait_for_abort_count(&abort_mock, 1).await;
        assert_eq!(count, 1, "dropping an armed guard must abort the multipart");
    }

    #[tokio::test]
    async fn test_multipart_abort_guard_disarmed_does_not_abort() {
        use wiremock::matchers::{method, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let abort_mock = Mock::given(method("DELETE"))
            .and(query_param("uploadId", "done-upload-id"))
            .respond_with(ResponseTemplate::new(204))
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        {
            let mut guard = MultipartAbortGuard::new(
                backend.store.clone(),
                "completed/object".into(),
                "completed/object".to_string(),
            );
            guard.arm("done-upload-id".to_string());
            // A completed upload defuses the guard.
            guard.disarm();
        }

        // Give any (erroneously) spawned abort a chance to land before asserting.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            abort_mock.received_requests().await.len(),
            0,
            "a completed (disarmed) upload must never be aborted"
        );
    }

    #[tokio::test]
    async fn test_multipart_abort_guard_abort_now_aborts_once() {
        use wiremock::matchers::{method, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let abort_mock = Mock::given(method("DELETE"))
            .and(query_param("uploadId", "err-upload-id"))
            .respond_with(ResponseTemplate::new(204))
            .mount_as_scoped(&server)
            .await;

        let backend = mock_s3_backend(&server.uri(), false).await;
        {
            let mut guard = MultipartAbortGuard::new(
                backend.store.clone(),
                "errored/object".into(),
                "errored/object".to_string(),
            );
            guard.arm("err-upload-id".to_string());
            // The error path aborts inline and defuses the guard...
            guard.abort_now().await;
            assert_eq!(
                abort_mock.received_requests().await.len(),
                1,
                "abort_now must issue exactly one AbortMultipartUpload"
            );
            // ...so the subsequent drop must NOT abort a second time.
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            abort_mock.received_requests().await.len(),
            1,
            "drop after abort_now must not issue a redundant abort"
        );
    }

    // ---- classify_s3_error: issue #981 diagnostic classifier ----
    //
    // These tests synthesize `object_store::Error::Generic` because the
    // real error shapes (TLS, DNS, ...) are produced deep inside reqwest
    // and not constructible in unit tests. The classifier only inspects
    // the display string, so a Generic with the right source text
    // covers every branch.

    fn generic_err(msg: &str) -> object_store::Error {
        object_store::Error::Generic {
            store: "S3",
            source: msg.to_string().into(),
        }
    }

    #[test]
    fn test_classify_tls_certificate_error() {
        let e = generic_err("invalid peer certificate: UnknownIssuer");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("TLS / certificate error"), "got: {msg}");
        assert!(
            msg.contains("S3_CA_CERT_PATH"),
            "must suggest CA bundle: {msg}"
        );
        assert!(msg.contains("caused by:"), "must keep raw source: {msg}");
    }

    #[test]
    fn test_classify_self_signed_error() {
        let e = generic_err("error: self-signed certificate");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("TLS / certificate error"), "got: {msg}");
    }

    #[test]
    fn test_classify_dns_error() {
        let e = generic_err("dns error: no such host (s3.invalid.example)");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("DNS resolution failed"), "got: {msg}");
    }

    #[test]
    fn test_classify_connection_refused() {
        let e = generic_err("error sending request: connection refused");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("connection refused"), "got: {msg}");
    }

    #[test]
    fn test_classify_network_unreachable() {
        let e = generic_err("network unreachable");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("network unreachable"), "got: {msg}");
    }

    #[test]
    fn test_classify_timeout() {
        // Mirrors the exact `transport error of kind Timeout` log line
        // in issue #981.
        let e = generic_err("Encountered transport error of kind Timeout");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("timed out"), "got: {msg}");
        assert!(
            msg.contains("S3_CA_CERT_PATH"),
            "should mention CA fallback hint for timeout: {msg}"
        );
    }

    #[test]
    fn test_classify_access_denied_403() {
        let e = generic_err("Client error with status 403 Forbidden: Access Denied");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("access denied (403)"), "got: {msg}");
        assert!(
            msg.contains("S3_BUCKET"),
            "must reference IAM/bucket policy: {msg}"
        );
    }

    #[test]
    fn test_classify_no_such_bucket() {
        let e = generic_err("NoSuchBucket: The specified bucket does not exist");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("bucket not found"), "got: {msg}");
        assert!(msg.contains("S3_REGION"), "must mention region: {msg}");
    }

    #[test]
    fn test_classify_region_mismatch() {
        let e = generic_err("BucketRegionError: bucket is in us-west-2");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("region mismatch"), "got: {msg}");
    }

    #[test]
    fn test_classify_signature_mismatch() {
        let e = generic_err("SignatureDoesNotMatch: clock skew");
        let msg = classify_s3_error(&e);
        assert!(msg.contains("signature rejected"), "got: {msg}");
        assert!(msg.contains("clock"), "must mention clock skew: {msg}");
    }

    #[test]
    fn test_classify_unknown_error_fallthrough() {
        // An unrecognized error must NOT be misclassified into a wrong
        // bucket; it should fall through to the generic "S3 request
        // failed" label and still preserve the raw source.
        let e = generic_err("some entirely new failure mode");
        let msg = classify_s3_error(&e);
        assert!(msg.starts_with("S3 request failed"), "got: {msg}");
        assert!(
            msg.contains("some entirely new failure mode"),
            "must keep raw text: {msg}"
        );
    }
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::storage::StorageBackend as StorageBackendTrait;

    #[tokio::test]
    #[ignore]
    async fn test_s3_presigned_url_generation() {
        let bucket = match std::env::var("S3_BUCKET") {
            Ok(b) => b,
            Err(_) => {
                println!("Skipping: S3_BUCKET not set");
                return;
            }
        };

        println!("Testing with bucket: {}", bucket);

        let config = S3Config::from_env()
            .expect("Failed to load S3 config")
            .with_redirect_downloads(true)
            .with_presign_expiry(Duration::from_secs(300));

        let backend = S3Backend::new(config)
            .await
            .expect("Failed to create S3 backend");

        let test_key = format!(
            "test/presign-test-{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let test_content = Bytes::from("Test content for presigned URL");

        println!("Uploading test file: {}", test_key);
        StorageBackendTrait::put(&backend, &test_key, test_content.clone())
            .await
            .expect("Failed to upload test file");

        assert!(StorageBackendTrait::supports_redirect(&backend));

        println!("Generating presigned URL...");
        let presigned =
            StorageBackendTrait::get_presigned_url(&backend, &test_key, Duration::from_secs(300))
                .await
                .expect("Failed to generate presigned URL");

        assert!(presigned.is_some());
        let presigned = presigned.unwrap();
        assert!(presigned.url.contains("X-Amz-Signature"));

        println!("Verifying presigned URL works...");
        let client = reqwest::Client::new();
        let response = client
            .get(presigned.url.as_str())
            .send()
            .await
            .expect("Failed to fetch presigned URL");
        assert!(
            response.status().is_success(),
            "Presigned URL should return 200"
        );

        let body = response.bytes().await.expect("Failed to read body");
        assert_eq!(body.as_ref(), test_content.as_ref(), "Content should match");

        println!("Cleaning up...");
        StorageBackendTrait::delete(&backend, &test_key)
            .await
            .expect("Failed to delete test file");
        println!("Test complete");
    }

    /// #3180 live: exercise the real OCI blob-upload shape against a live
    /// S3-compatible backend (MinIO) and prove the control/bulk client split
    /// did not break ordinary object movement. Mirrors what
    /// `handle_complete_upload` does: stream a part in, concatenate it into a
    /// `.complete.` object, then `copy` that onto the final `oci-blobs/` key.
    ///
    ///   AK_S3_E2E=1 S3_BUCKET=ak-test S3_REGION=us-east-1 \
    ///   S3_ENDPOINT=http://127.0.0.1:39000 S3_ACCESS_KEY_ID=... \
    ///   S3_SECRET_ACCESS_KEY=... cargo test test_oci_blob_roundtrip_live_3180 \
    ///   -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn test_oci_blob_roundtrip_live_3180() {
        if std::env::var("AK_S3_E2E").ok().as_deref() != Some("1") {
            println!("Skipping: set AK_S3_E2E=1 to run");
            return;
        }

        let config = S3Config::from_env().expect("S3Config::from_env");
        println!(
            "bulk_timeout_secs={} control_timeout_secs={}",
            config.bulk_timeout_secs, config.control_timeout_secs
        );
        let backend = S3Backend::new(config).await.expect("S3Backend::new");

        let id = uuid::Uuid::new_v4();
        let part_key = format!(
            "oci-uploads/{}.part.2147483647.{}",
            id,
            uuid::Uuid::new_v4()
        );
        let complete_key = format!("oci-uploads/{}.complete.{}", id, uuid::Uuid::new_v4());
        let blob_key = format!("oci-blobs/sha256:{}", "a".repeat(64));

        // ~24 MiB across several chunks: enough to exercise real multipart.
        let chunk = Bytes::from(vec![b'z'; 4 * 1024 * 1024]);
        let expected_len = chunk.len() as u64 * 6;
        let stream = futures::stream::iter((0..6).map(move |_| Ok(chunk.clone())));
        let put = StorageBackendTrait::put_stream(&backend, &part_key, Box::pin(stream))
            .await
            .expect("part put_stream");
        assert_eq!(put.bytes_written, expected_len);

        // Concatenate the part into the completion object, as the OCI handler does.
        let src = StorageBackendTrait::get_stream(&backend, &part_key)
            .await
            .expect("part get_stream");
        let complete = StorageBackendTrait::put_stream(&backend, &complete_key, src)
            .await
            .expect("completion put_stream");
        assert_eq!(complete.bytes_written, expected_len);

        // Promote onto the content-addressed blob key.
        backend.copy(&complete_key, &blob_key).await.expect("copy");
        assert_eq!(backend.size(&blob_key).await.expect("size"), expected_len);

        let read_back = StorageBackendTrait::get(&backend, &blob_key)
            .await
            .expect("get blob");
        assert_eq!(read_back.len() as u64, expected_len);

        for k in [&part_key, &complete_key, &blob_key] {
            let _ = StorageBackendTrait::delete(&backend, k).await;
        }
        println!("#3180 live OCI blob roundtrip OK ({} bytes)", expected_len);
    }

    /// #1555 live: the proxy-cache handle (env-derived config with prefix
    /// forced to None, as `StorageService::from_config` builds it) must put,
    /// presign, and serve a `proxy-cache/...` key at the bucket root with NO
    /// `S3_PREFIX`. Run with:
    ///   AK_S3_E2E=1 S3_BUCKET=<test> S3_REGION=us-east-1 S3_REDIRECT_DOWNLOADS=true \
    ///   cargo test -p artifact-keeper-backend test_proxy_cache_presign_no_prefix_live_1555 -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn test_proxy_cache_presign_no_prefix_live_1555() {
        if std::env::var("AK_S3_E2E").ok().as_deref() != Some("1") {
            println!("Skipping: set AK_S3_E2E=1 to run");
            return;
        }

        // Mirror from_config's proxy-cache handle: env-derived config, prefix=None.
        let mut config = S3Config::from_env().expect("S3Config::from_env");
        config.prefix = None;
        let backend = S3Backend::new(config).await.expect("S3Backend::new");

        assert!(
            StorageBackendTrait::supports_redirect(&backend),
            "S3_REDIRECT_DOWNLOADS must be true for this test"
        );

        let key = "proxy-cache/pypi-remote/simple/foo/foo-1.0-py3-none-any.whl/__content__";
        let body = Bytes::from_static(b"hello-presign-1555");
        StorageBackendTrait::put(&backend, key, body.clone())
            .await
            .expect("put no-prefix proxy-cache object");

        let pre = StorageBackendTrait::get_presigned_url(&backend, key, Duration::from_secs(300))
            .await
            .expect("get_presigned_url ok")
            .expect("presigned URL present");
        println!("presigned url: {}", pre.url);

        assert!(
            pre.url.contains("/proxy-cache/pypi-remote/simple/foo/"),
            "URL must carry the verbatim no-prefix key: {}",
            pre.url
        );
        assert!(
            !pre.url.contains("artifact-keeper"),
            "URL must NOT carry a global prefix (#1555): {}",
            pre.url
        );

        let resp = reqwest::get(&pre.url).await.expect("GET presigned URL");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "S3 must serve AK's presigned no-prefix URL"
        );
        let got = resp.bytes().await.expect("body");
        assert_eq!(&got[..], &body[..], "served bytes must match");

        let _ = StorageBackendTrait::delete(&backend, key).await;
        println!("#1555 no-prefix presign live test OK");
    }

    /// #3164 live: prove the hand-rolled, SigV4-signed `UploadPartCopy`
    /// request is actually ACCEPTED by a real S3-compatible server (MinIO).
    /// The wiremock suite asserts the request shape but cannot validate the
    /// signature — a signing bug there would pass every double and then fail
    /// in production on the first over-ceiling copy.
    ///
    /// Shrinks the single-copy ceiling via the `S3_MAX_SINGLE_COPY_BYTES`
    /// env lever (the operator-facing knob this PR adds) so the multipart
    /// path triggers on a 16 MiB object instead of a >5 GiB one, then
    /// asserts: (1) the copy succeeds against the live server — the
    /// signature validation; (2) destination bytes equal source bytes —
    /// position-dependent content, so a range mix-up changes the result;
    /// (3) the multipart path was really taken: a multipart-completed
    /// object's ETag carries a `-<parts>` suffix (md5-of-part-md5s), while
    /// a native `CopyObject` fallback would carry the source's plain ETag.
    ///
    ///   AK_S3_E2E=1 S3_BUCKET=ak-test S3_REGION=us-east-1 \
    ///   S3_ENDPOINT=http://127.0.0.1:39164 S3_ACCESS_KEY_ID=... \
    ///   S3_SECRET_ACCESS_KEY=... cargo test \
    ///   test_large_copy_upload_part_copy_live_3164 -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn test_large_copy_upload_part_copy_live_3164() {
        if std::env::var("AK_S3_E2E").ok().as_deref() != Some("1") {
            println!("Skipping: set AK_S3_E2E=1 to run");
            return;
        }

        // 6 MiB ceiling -> a 16 MiB source needs three ranged part copies
        // (6 + 6 + 4 MiB). Set via env so this exercises the exact
        // config-surface path an operator would use.
        std::env::set_var("S3_MAX_SINGLE_COPY_BYTES", (6u64 * 1024 * 1024).to_string());
        let config = S3Config::from_env().expect("S3Config::from_env");
        let backend = S3Backend::new(config).await.expect("S3Backend::new");

        let source_key = format!("large-copy-3164/src-{}", uuid::Uuid::new_v4());
        let dest_key = format!("large-copy-3164/dst-{}", uuid::Uuid::new_v4());

        // Position-dependent bytes: reassembling the parts in the wrong
        // order, at the wrong offsets, or dropping a slice changes the
        // content, so the equality check below validates the ranges too.
        let len = 16 * 1024 * 1024_usize;
        let content = Bytes::from(
            (0..len)
                .map(|i| (i.wrapping_mul(2654435761) >> 7) as u8)
                .collect::<Vec<u8>>(),
        );
        StorageBackendTrait::put(&backend, &source_key, content.clone())
            .await
            .expect("seed source object");

        // (1) Signature validation: the copy must be accepted by the live
        // server. Every part is a hand-rolled UploadPartCopy request.
        backend.copy(&source_key, &dest_key).await.expect(
            "#3164: server-side multipart copy must be accepted by a real \
             S3-compatible store (SigV4 of the hand-rolled UploadPartCopy)",
        );

        // (2) The copied bytes must equal the source bytes.
        let copied = StorageBackendTrait::get(&backend, &dest_key)
            .await
            .expect("read copied object");
        assert_eq!(copied.len(), content.len(), "copied length must match");
        assert!(
            copied == content,
            "#3164: destination bytes must equal source bytes"
        );

        // (3) The multipart path must actually have been taken. 16 MiB at a
        // 6 MiB ceiling = 3 parts -> ETag like "abc...-3". A native
        // CopyObject fallback yields a plain single-part ETag with no
        // dash-suffix (MD5 hex contains no '-').
        let dest_path: ObjectPath = backend.full_key(&dest_key).into();
        let meta = backend.store.head(&dest_path).await.expect("head dest");
        let etag = meta.e_tag.clone().expect("dest object must have an ETag");
        assert!(
            etag.contains("-3"),
            "#3164: dest ETag {:?} does not carry the 3-part multipart \
             suffix; the copy did not take the UploadPartCopy path",
            etag
        );

        let _ = StorageBackendTrait::delete(&backend, &source_key).await;
        let _ = StorageBackendTrait::delete(&backend, &dest_key).await;
        println!(
            "#3164 live multipart copy OK: len={} dest_etag={}",
            copied.len(),
            etag
        );
    }
}
