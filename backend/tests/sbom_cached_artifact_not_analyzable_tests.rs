//! DB-gated invariant tests for #2227: SBOM/scan resolution of proxy-cached
//! (Remote) objects.
//!
//! Root cause of #2227: a Remote (proxy) repository lists a proxy-cached
//! object with a *synthetic* id derived from `SHA-256("proxy-cache/<key>/<path>")`
//! (see `cached_artifact_id` in `api::handlers::repositories`). That object has
//! **no row** in the `artifacts` table by design (#1280/#1278), so every
//! artifact-scoped analysis handler — SBOM generate (`generate_sbom`), CVE
//! history (`ensure_artifact_repo_access`) and the scan trigger
//! (`trigger_scan`) — resolves the id strictly against `artifacts.id` and
//! finds nothing, returning 404. Hosted (Local) npm/Docker artifacts have real
//! v4 ids and continue to resolve.
//!
//! These tests pin that invariant at the DB layer the three handlers share:
//! a hosted npm artifact and a hosted Docker manifest artifact both resolve,
//! while the synthetic cached id resolves to nothing.
//!
//! Requires a PostgreSQL database with migrations applied. Run:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test sbom_cached_artifact_not_analyzable_tests -- --ignored
//! ```

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Recompute the synthetic proxy-cache id exactly as
/// `api::handlers::repositories::cached_artifact_id` does: the first 16 bytes
/// of `SHA-256("proxy-cache/<repo_key>/<path>")`. Kept in sync manually because
/// the source helper is private to the handler module. If this drifts, the
/// listing and these tests disagree, which is itself the bug to catch.
fn synthetic_cached_id(repo_key: &str, path: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(format!("proxy-cache/{}/{}", repo_key, path).as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

async fn create_repo(pool: &PgPool, format: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("test-2227-{}-{}", format, id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', $5::repository_format)",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("2227-{}", id))
    .bind(format!("/tmp/test-artifacts/{}", id))
    .bind(format)
    .execute(pool)
    .await
    .expect("failed to create test repository");
    (id, key)
}

async fn insert_hosted_artifact(
    pool: &PgPool,
    repo_id: Uuid,
    name: &str,
    path: &str,
    content_type: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO artifacts (id, repository_id, name, path, size_bytes, checksum_sha256,
                               content_type, storage_key, is_deleted)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $4, false)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(name)
    .bind(path)
    .bind(2048_i64)
    .bind(format!("{:x}", Sha256::digest(path.as_bytes())))
    .bind(content_type)
    .execute(pool)
    .await
    .expect("failed to insert hosted artifact");
    id
}

/// The resolution the three analysis handlers share: `generate_sbom` selects
/// `(id, repository_id)`, `ensure_artifact_repo_access` selects
/// `repository_id ... AND NOT is_deleted`, and the `trigger_scan` pre-check
/// selects `id ... AND is_deleted = false`. All agree for these fixtures, so a
/// single existence probe models the honest-404-vs-resolves decision.
async fn artifact_resolves(pool: &PgPool, artifact_id: Uuid) -> bool {
    let row: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM artifacts WHERE id = $1 AND is_deleted = false")
            .bind(artifact_id)
            .fetch_optional(pool)
            .await
            .expect("resolution query failed");
    row.is_some()
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
}

#[tokio::test]
#[ignore] // Requires database
async fn hosted_npm_and_docker_artifacts_resolve_but_synthetic_cached_id_does_not() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    // Hosted npm artifact (real v4 id) -> analysis resolves. (Regression guard:
    // the fix must not break SBOM/scan for hosted artifacts.)
    let (npm_repo, npm_key) = create_repo(&pool, "npm").await;
    let npm_id = insert_hosted_artifact(
        &pool,
        npm_repo,
        "left-pad-1.3.0.tgz",
        "left-pad/1.3.0/left-pad-1.3.0.tgz",
        "application/octet-stream",
    )
    .await;
    assert!(
        artifact_resolves(&pool, npm_id).await,
        "hosted npm artifact must resolve so SBOM/scan still works"
    );

    // Hosted Docker/OCI manifest artifact (real v4 id) -> analysis resolves.
    let (docker_repo, docker_key) = create_repo(&pool, "docker").await;
    let docker_id = insert_hosted_artifact(
        &pool,
        docker_repo,
        "sha256:manifest",
        "library/postgres/manifests/16-alpine",
        "application/vnd.oci.image.manifest.v1+json",
    )
    .await;
    assert!(
        artifact_resolves(&pool, docker_id).await,
        "hosted Docker manifest artifact must resolve so SBOM/scan still works"
    );

    // Synthetic proxy-cache ids for a Remote npm and a Remote docker object:
    // no `artifacts` row exists, so resolution misses and the handlers return
    // the honest not-analyzable 404 instead of a silent success.
    let synth_npm = synthetic_cached_id("npm-remote", "left-pad/-/left-pad-1.3.0.tgz");
    let synth_docker = synthetic_cached_id("docker-remote", "library/postgres/manifests/16-alpine");
    assert!(
        !artifact_resolves(&pool, synth_npm).await,
        "synthetic proxy-cache npm id must not resolve (#1280/#1278 invariant)"
    );
    assert!(
        !artifact_resolves(&pool, synth_docker).await,
        "synthetic proxy-cache docker id must not resolve (#1280/#1278 invariant)"
    );

    // The synthetic id is deterministic and distinct from the hosted ids.
    assert_eq!(
        synth_npm,
        synthetic_cached_id("npm-remote", "left-pad/-/left-pad-1.3.0.tgz"),
        "synthetic id must be stable for the same repo_key + path"
    );
    assert_ne!(synth_npm, npm_id);
    assert_ne!(synth_docker, docker_id);

    // Silence unused-key warnings; keys document the Remote repos the synthetic
    // ids would have been listed under.
    let _ = (npm_key, docker_key);

    cleanup(&pool, npm_repo).await;
    cleanup(&pool, docker_repo).await;
}
