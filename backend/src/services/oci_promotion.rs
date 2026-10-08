//! Docker/OCI content for artifact promotion (#4578).
//!
//! An OCI manifest's `artifacts` row (`v2/<image>/manifests/<reference>`)
//! points at one object: the manifest itself, stored at
//! `oci-manifests/<digest>`. The registry does not serve pulls from that row.
//! It resolves a pull through `oci_tags`, the manifest reference tables and
//! `oci_blobs`, and reads the child manifests and the config and layer blobs
//! from their own objects. A promotion that copies only the row and the one
//! object leaves a tag the target repository cannot serve (`MANIFEST_UNKNOWN`).
//!
//! [`prepare`] walks the promoted manifest in the SOURCE repository (an image
//! index, its child manifests, and every config and layer blob they reference)
//! and copies the objects into the target storage. [`PreparedOciImage::register_in_tx`]
//! then records the image for the TARGET repository with the same helper a
//! manifest push uses ([`persist_tag_and_refs_in_tx`]), inside the caller's
//! transaction, so the promoted `artifacts` row and the rows that make it
//! pullable commit together or not at all.

use std::collections::{HashMap, HashSet, VecDeque};

use bytes::Bytes;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::handlers::oci_digest::compute_sha256;
use crate::api::handlers::oci_v2::{
    classify_manifest, extract_blob_refs, extract_child_digests, manifest_storage_key,
    manifest_total_size, persist_tag_and_refs_in_tx, resolve_manifest_content_type,
    upsert_manifest_artifact, ManifestClass,
};
use crate::error::{AppError, Result};
use crate::storage::StorageBackend;

/// Upper bound on the manifests walked for one promoted reference. A real
/// multi-platform index has a handful of children; the cap only stops a
/// pathological source from turning one promotion into an unbounded walk.
const MAX_PROMOTED_MANIFESTS: usize = 1024;

/// Split an OCI manifest artifact path `v2/<image>/manifests/<reference>`
/// into `(image, reference)`. The image name may itself contain `/`.
/// Returns `None` for any other path, which is how non-OCI artifacts opt out.
pub(crate) fn parse_manifest_artifact_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("v2/")?;
    let (image, reference) = rest.rsplit_once("/manifests/")?;
    if image.is_empty() || reference.is_empty() || reference.contains('/') {
        return None;
    }
    Some((image, reference))
}

/// One manifest of the promoted image, read from the source repository.
struct WalkedManifest {
    digest: String,
    content_type: String,
    class: ManifestClass,
    body: Bytes,
    /// `size_bytes` and `origin` of the source repository's `artifacts` row
    /// for this manifest, when it has one. Only used for child manifests: the
    /// root's row is the promoted artifact the caller inserts itself.
    source_row: Option<(i64, Option<serde_json::Value>)>,
}

/// One `oci_blobs` row of the source repository.
struct BlobRow {
    digest: String,
    size_bytes: i64,
    storage_key: String,
}

/// A promoted OCI reference whose objects are already in the target storage
/// and whose rows are ready to be recorded for the target repository.
pub(crate) struct PreparedOciImage {
    image: String,
    reference: String,
    /// Root manifest first, then its children in walk order.
    manifests: Vec<WalkedManifest>,
    blobs: Vec<BlobRow>,
}

/// Walk the OCI image behind `artifact_path` in `source_repo_id` and copy every
/// manifest and blob object it needs into `target`.
///
/// Returns `Ok(None)` when the artifact is not an OCI manifest of the source
/// repository (its path is not a manifest path, or no `oci_tags` row resolves
/// it), so callers can run this for every promoted artifact. Fails when the
/// source image is incomplete (a referenced manifest or blob is missing), so
/// a promotion never reports success for an image the target cannot serve.
pub(crate) async fn prepare(
    db: &PgPool,
    source: &dyn StorageBackend,
    target: &dyn StorageBackend,
    source_repo_id: Uuid,
    artifact_path: &str,
) -> Result<Option<PreparedOciImage>> {
    let Some((image, reference)) = parse_manifest_artifact_path(artifact_path) else {
        return Ok(None);
    };
    let root: Option<(String, String)> = sqlx::query_as(
        "SELECT manifest_digest, manifest_content_type FROM oci_tags \
         WHERE repository_id = $1 AND name = $2 AND tag = $3",
    )
    .bind(source_repo_id)
    .bind(image)
    .bind(reference)
    .fetch_optional(db)
    .await?;
    let Some((root_digest, root_content_type)) = root else {
        return Ok(None);
    };

    let mut manifests = Vec::new();
    let mut blob_digests: Vec<String> = Vec::new();
    let mut seen_blobs = HashSet::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::from([(root_digest.clone(), Some(root_content_type))]);

    while let Some((digest, stored_type)) = queue.pop_front() {
        if !visited.insert(digest.clone()) {
            continue;
        }
        if visited.len() > MAX_PROMOTED_MANIFESTS {
            return Err(AppError::Validation(format!(
                "OCI image {image}:{reference} references more than \
                 {MAX_PROMOTED_MANIFESTS} manifests"
            )));
        }
        let key = manifest_storage_key(&digest);
        let body = source.get(&key).await.map_err(|e| {
            AppError::Internal(format!(
                "Failed to read manifest {digest} of {image}:{reference}: {e}"
            ))
        })?;
        if compute_sha256(&body) != digest {
            return Err(AppError::Internal(format!(
                "Stored manifest {digest} of {image}:{reference} does not match its digest"
            )));
        }
        let class = classify_manifest(&body);
        match class {
            ManifestClass::Index => {
                for child in extract_child_digests(&body) {
                    queue.push_back((child, None));
                }
            }
            ManifestClass::Image => {
                for blob in extract_blob_refs(&body) {
                    if seen_blobs.insert(blob.digest.clone()) {
                        blob_digests.push(blob.digest);
                    }
                }
            }
            ManifestClass::Malformed => {
                return Err(AppError::Internal(format!(
                    "Stored manifest {digest} of {image}:{reference} is not a valid manifest"
                )));
            }
        }
        let stored_type = match stored_type {
            Some(t) => Some(t),
            None => {
                sqlx::query_scalar(
                    "SELECT manifest_content_type FROM oci_tags \
                 WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
                )
                .bind(source_repo_id)
                .bind(&digest)
                .fetch_optional(db)
                .await?
            }
        };
        let content_type = resolve_manifest_content_type(stored_type.as_deref(), &body);
        let source_row: Option<(i64, Option<serde_json::Value>)> = sqlx::query_as(
            "SELECT size_bytes, origin FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(source_repo_id)
        .bind(format!("v2/{image}/manifests/{digest}"))
        .fetch_optional(db)
        .await?;

        copy_object_if_missing(source, target, &key, Some(body.clone())).await?;
        manifests.push(WalkedManifest {
            digest,
            content_type,
            class,
            body,
            source_row,
        });
    }

    let rows: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT digest, size_bytes, storage_key FROM oci_blobs \
         WHERE repository_id = $1 AND digest = ANY($2)",
    )
    .bind(source_repo_id)
    .bind(&blob_digests)
    .fetch_all(db)
    .await?;
    let mut by_digest: HashMap<String, (i64, String)> = rows
        .into_iter()
        .map(|(digest, size, key)| (digest, (size, key)))
        .collect();
    let mut blobs = Vec::with_capacity(blob_digests.len());
    for digest in blob_digests {
        let Some((size_bytes, storage_key)) = by_digest.remove(&digest) else {
            return Err(AppError::Internal(format!(
                "Blob {digest} of {image}:{reference} is missing from the source repository"
            )));
        };
        copy_object_if_missing(source, target, &storage_key, None).await?;
        blobs.push(BlobRow {
            digest,
            size_bytes,
            storage_key,
        });
    }

    Ok(Some(PreparedOciImage {
        image: image.to_string(),
        reference: reference.to_string(),
        manifests,
        blobs,
    }))
}

/// Copy one content-addressed object unless the target already holds it. On a
/// shared cloud backend the source and target keys are the same object, so
/// the existence check also stops a read and a write of one key at once.
async fn copy_object_if_missing(
    source: &dyn StorageBackend,
    target: &dyn StorageBackend,
    key: &str,
    body: Option<Bytes>,
) -> Result<()> {
    if target.exists(key).await? {
        return Ok(());
    }
    let copied = match body {
        Some(body) => target.put(key, body).await,
        None => match source.get_stream(key).await {
            Ok(stream) => target.put_stream(key, stream).await.map(|_| ()),
            Err(e) => Err(e),
        },
    };
    copied.map_err(|e| AppError::Internal(format!("Failed to copy {key}: {e}")))
}

impl PreparedOciImage {
    /// Record the image for `target_repo_id` inside the caller's transaction:
    /// the `oci_blobs` rows, then every manifest through
    /// [`persist_tag_and_refs_in_tx`] (the same tag, reference and
    /// `oci_manifests` writes a push makes). Child manifests are recorded
    /// under their digest, with their own `artifacts` row, exactly as a
    /// by-digest push records them; the root is recorded under the promoted
    /// reference and its `artifacts` row is left to the caller.
    pub(crate) async fn register_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        target_repo_id: Uuid,
        uploaded_by: Uuid,
    ) -> std::result::Result<(), sqlx::Error> {
        if !self.blobs.is_empty() {
            let digests: Vec<&str> = self.blobs.iter().map(|b| b.digest.as_str()).collect();
            let sizes: Vec<i64> = self.blobs.iter().map(|b| b.size_bytes).collect();
            let keys: Vec<&str> = self.blobs.iter().map(|b| b.storage_key.as_str()).collect();
            sqlx::query(
                "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
                 SELECT $1, d, s, k FROM UNNEST($2::text[], $3::bigint[], $4::text[]) AS t(d, s, k) \
                 ON CONFLICT (repository_id, digest) DO UPDATE SET pending_delete_at = NULL",
            )
            .bind(target_repo_id)
            .bind(&digests)
            .bind(&sizes)
            .bind(&keys)
            .execute(&mut **tx)
            .await?;
        }

        // Children before the root, so every reference the root records
        // already resolves when its tag lands.
        for (i, m) in self.manifests.iter().enumerate().rev() {
            let is_root = i == 0;
            let tag = if is_root { &self.reference } else { &m.digest };
            persist_tag_and_refs_in_tx(
                tx,
                target_repo_id,
                &self.image,
                tag,
                &m.digest,
                &m.content_type,
                &m.class,
                &m.body,
            )
            .await?;
            if is_root {
                continue;
            }
            let (size, origin) = match &m.source_row {
                Some((size, origin)) => (*size, origin.clone()),
                None => (manifest_total_size(&m.body), None),
            };
            upsert_manifest_artifact(
                &mut **tx,
                target_repo_id,
                &self.image,
                &m.digest,
                &m.digest,
                &m.content_type,
                &manifest_storage_key(&m.digest),
                size,
                Some(uploaded_by),
                origin.as_ref(),
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::parse_manifest_artifact_path;

    #[test]
    fn parses_tag_and_digest_manifest_paths() {
        assert_eq!(
            parse_manifest_artifact_path("v2/probe/manifests/1"),
            Some(("probe", "1"))
        );
        assert_eq!(
            parse_manifest_artifact_path("v2/team/app/manifests/sha256:abc"),
            Some(("team/app", "sha256:abc"))
        );
    }

    #[test]
    fn rejects_non_manifest_paths() {
        for path in [
            "com/example/app-1.0.jar",
            "v2/probe/blobs/sha256:abc",
            "v2//manifests/1",
            "v2/probe/manifests/",
            "probe/manifests/1",
        ] {
            assert_eq!(parse_manifest_artifact_path(path), None, "{path}");
        }
    }
}
