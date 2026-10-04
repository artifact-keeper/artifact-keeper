//! Per-artifact promotion state for artifact listings (#1758).
//!
//! Promotion is copy-not-move: the staging artifact stays where it is and the
//! event is recorded in `promotion_history`. This module derives the
//! "promoted -> <target>" signal the listings surface from that table, one
//! batched query per page.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::repositories::{member_grant_visibility, member_passes_token_scope};
use crate::api::middleware::auth::AuthExtension;
use crate::models::repository::RepositoryVisibility;
use crate::services::repository_service::RepositoryService;

/// The `promotion_history.status` value of a completed promotion. Rejected
/// and pending-approval rows are never reported as a promotion.
pub(crate) const PROMOTED_STATUS: &str = "promoted";

/// The most recent successful promotion of an artifact out of its repository
/// (#1758). Lets a client badge a staging artifact as "promoted -> target"
/// without cross-referencing the promotion-history view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct LastPromotion {
    /// Key of the repository the artifact was promoted into. `null` when the
    /// caller cannot read that repository: the promotion is still reported,
    /// but the listing does not disclose the name of a repository its viewer
    /// could not open.
    pub target_repo_key: Option<String>,
    /// When the promotion was recorded.
    pub promoted_at: DateTime<Utc>,
    /// The `promotion_history` status of the reported row. Always
    /// `promoted`; rejected and pending attempts are never reported here.
    pub status: String,
}

/// One `promotion_history` row: the latest `promoted` row per artifact.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct LastPromotionRow {
    pub artifact_id: Uuid,
    pub target_repo_id: Uuid,
    pub target_repo_key: String,
    pub target_visibility: RepositoryVisibility,
    pub promoted_at: DateTime<Utc>,
    pub status: String,
}

/// Turn the latest-promotion rows into the per-artifact map, redacting the
/// target key wherever `target_readable` says the caller may not see it.
pub(crate) fn last_promotions_from_rows(
    rows: Vec<LastPromotionRow>,
    target_readable: impl Fn(Uuid, RepositoryVisibility) -> bool,
) -> HashMap<Uuid, LastPromotion> {
    rows.into_iter()
        .map(|r| {
            let target_repo_key =
                target_readable(r.target_repo_id, r.target_visibility).then_some(r.target_repo_key);
            (
                r.artifact_id,
                LastPromotion {
                    target_repo_key,
                    promoted_at: r.promoted_at,
                    status: r.status,
                },
            )
        })
        .collect()
}

/// The later of two optional promotions (ties keep `current`). Used to fold
/// the files of a grouped listing row (a Maven component) into one state.
pub(crate) fn latest_promotion(
    current: Option<LastPromotion>,
    candidate: Option<&LastPromotion>,
) -> Option<LastPromotion> {
    match (current, candidate) {
        (Some(c), Some(n)) if n.promoted_at > c.promoted_at => Some(n.clone()),
        (Some(c), _) => Some(c),
        (None, n) => n.cloned(),
    }
}

/// Fetch the latest successful promotion for each of `artifact_ids`.
///
/// One `DISTINCT ON` query over `idx_promotion_history_artifact` per page.
/// The target repository key is shown only when the caller could read that
/// repository (grant half plus token-scope half, the same predicate the
/// virtual-member listings use); a failed visibility query redacts every
/// key rather than widening. Best-effort like the uploader-name lookup: a
/// failed history query logs and yields an empty map instead of failing the
/// listing.
pub(crate) async fn fetch_last_promotions(
    db: &sqlx::PgPool,
    artifact_ids: &[Uuid],
    auth: Option<&AuthExtension>,
) -> HashMap<Uuid, LastPromotion> {
    if artifact_ids.is_empty() {
        return HashMap::new();
    }
    let rows: Vec<LastPromotionRow> = match sqlx::query_as(
        r#"
        SELECT DISTINCT ON (ph.artifact_id)
               ph.artifact_id,
               ph.target_repo_id,
               tr.key AS target_repo_key,
               tr.visibility AS target_visibility,
               ph.created_at AS promoted_at,
               ph.status
          FROM promotion_history ph
          JOIN repositories tr ON tr.id = ph.target_repo_id
         WHERE ph.artifact_id = ANY($1)
           AND ph.status = $2
         ORDER BY ph.artifact_id, ph.created_at DESC, ph.id DESC
        "#,
    )
    .bind(artifact_ids)
    .bind(PROMOTED_STATUS)
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "last-promotion lookup failed; omitting promotion state");
            return HashMap::new();
        }
    };
    if rows.is_empty() {
        return HashMap::new();
    }

    let target_ids: Vec<Uuid> = rows
        .iter()
        .map(|r| r.target_repo_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let granted: HashSet<Uuid> = RepositoryService::new(db.clone())
        .filter_visible_repo_ids(&target_ids, &member_grant_visibility(auth))
        .await
        .map(|ids| ids.into_iter().collect())
        .unwrap_or_default();
    last_promotions_from_rows(rows, |id, visibility| {
        granted.contains(&id) && member_passes_token_scope(auth, id, id, visibility)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(artifact_id: Uuid, target: Uuid, key: &str, at: i64) -> LastPromotionRow {
        LastPromotionRow {
            artifact_id,
            target_repo_id: target,
            target_repo_key: key.to_string(),
            target_visibility: RepositoryVisibility::Private,
            promoted_at: DateTime::from_timestamp(at, 0).unwrap(),
            status: PROMOTED_STATUS.to_string(),
        }
    }

    #[test]
    fn rows_map_by_artifact_and_redact_unreadable_targets() {
        let (a1, a2) = (Uuid::new_v4(), Uuid::new_v4());
        let (open, hidden) = (Uuid::new_v4(), Uuid::new_v4());
        let map = last_promotions_from_rows(
            vec![row(a1, open, "release", 10), row(a2, hidden, "secret", 20)],
            |id, _| id == open,
        );
        assert_eq!(map[&a1].target_repo_key.as_deref(), Some("release"));
        assert_eq!(map[&a1].status, "promoted");
        assert_eq!(map[&a1].promoted_at.timestamp(), 10);
        assert_eq!(
            map[&a2].target_repo_key, None,
            "unreadable target is redacted"
        );
        assert_eq!(map[&a2].promoted_at.timestamp(), 20);
    }

    #[test]
    fn latest_promotion_keeps_the_newer_row() {
        let p = |at: i64, key: &str| LastPromotion {
            target_repo_key: Some(key.to_string()),
            promoted_at: DateTime::from_timestamp(at, 0).unwrap(),
            status: PROMOTED_STATUS.to_string(),
        };
        assert_eq!(latest_promotion(None, None), None);
        assert_eq!(latest_promotion(None, Some(&p(1, "a"))), Some(p(1, "a")));
        assert_eq!(latest_promotion(Some(p(1, "a")), None), Some(p(1, "a")));
        assert_eq!(
            latest_promotion(Some(p(1, "a")), Some(&p(2, "b"))),
            Some(p(2, "b"))
        );
        assert_eq!(
            latest_promotion(Some(p(2, "a")), Some(&p(1, "b"))),
            Some(p(2, "a"))
        );
    }

    #[test]
    fn last_promotion_serializes_null_target_key() {
        let p = LastPromotion {
            target_repo_key: None,
            promoted_at: DateTime::from_timestamp(0, 0).unwrap(),
            status: PROMOTED_STATUS.to_string(),
        };
        let json = serde_json::to_value(&p).unwrap();
        assert!(json["target_repo_key"].is_null());
        assert_eq!(json["status"], "promoted");
    }

    // -----------------------------------------------------------------------
    // DB-backed: the listing surfaces (flat, docker-tag grouped) and the
    // by-id artifact endpoint report the latest *promoted* row (#1758).
    // -----------------------------------------------------------------------

    use crate::api::handlers::repositories::{list_artifacts, ListArtifactsQuery};
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::extract::{Extension, Path, Query, State};

    async fn insert_artifact(pool: &sqlx::PgPool, repo_id: Uuid, path: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $2, '1.0', 1, repeat('a', 64), 'application/octet-stream', $3) \
             RETURNING id",
        )
        .bind(repo_id)
        .bind(path)
        .bind(format!("lp-{}", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("insert artifact")
    }

    async fn insert_history(
        pool: &sqlx::PgPool,
        artifact_id: Uuid,
        source: Uuid,
        target: Uuid,
        status: &str,
        at: DateTime<Utc>,
    ) {
        sqlx::query(
            "INSERT INTO promotion_history \
             (artifact_id, source_repo_id, target_repo_id, status, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(artifact_id)
        .bind(source)
        .bind(target)
        .bind(status)
        .bind(at)
        .execute(pool)
        .await
        .expect("insert promotion_history");
    }

    fn query(group_by: Option<&str>) -> ListArtifactsQuery {
        ListArtifactsQuery {
            page: Some(1),
            per_page: Some(50),
            q: None,
            path_prefix: None,
            group_by: group_by.map(str::to_string),
            cursor: None,
            count: None,
        }
    }

    #[tokio::test]
    async fn listings_report_latest_promoted_row_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging_id, staging_key, staging_dir) =
            tdh::create_repo(&pool, "staging", "generic").await;
        let (docker_id, docker_key, docker_dir) =
            tdh::create_repo(&pool, "staging", "docker").await;
        let (target_id, target_key, target_dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (user_id, username) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, staging_id, user_id).await;
        tdh::grant_repo_actions(&pool, staging_id, user_id, &["read"]).await;
        let state = tdh::build_state(pool.clone(), staging_dir.to_string_lossy().as_ref());

        let now = Utc::now();
        let hours = |h: i64| now - chrono::Duration::hours(h);
        let promoted = insert_artifact(&pool, staging_id, "lp/promoted.bin").await;
        let rejected_only = insert_artifact(&pool, staging_id, "lp/rejected.bin").await;
        let never = insert_artifact(&pool, staging_id, "lp/never.bin").await;
        insert_history(&pool, promoted, staging_id, target_id, "promoted", hours(3)).await;
        insert_history(&pool, promoted, staging_id, target_id, "promoted", hours(2)).await;
        // A later rejection must not mask (or be reported as) the promotion.
        insert_history(
            &pool,
            promoted,
            staging_id,
            staging_id,
            "rejected",
            hours(1),
        )
        .await;
        insert_history(
            &pool,
            rejected_only,
            staging_id,
            staging_id,
            "rejected",
            hours(1),
        )
        .await;

        let manifest = insert_artifact(&pool, docker_id, "v2/lp-img/manifests/1.0").await;
        sqlx::query(
            "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
             VALUES ($1, 'lp-img', '1.0', $2, 'application/vnd.oci.image.manifest.v1+json')",
        )
        .bind(docker_id)
        .bind(format!("sha256:{}", "b".repeat(64)))
        .execute(&pool)
        .await
        .expect("seed oci tag");
        insert_history(&pool, manifest, docker_id, target_id, "promoted", hours(2)).await;

        let admin = Extension(Some(tdh::admin_auth(user_id, &username)));
        let reader = Extension(Some(tdh::make_auth(user_id, &username)));
        let flat_admin = list_artifacts(
            State(state.clone()),
            admin.clone(),
            Path(staging_key.clone()),
            Query(query(None)),
        )
        .await;
        let flat_reader = list_artifacts(
            State(state.clone()),
            reader,
            Path(staging_key.clone()),
            Query(query(None)),
        )
        .await;
        let docker_admin = list_artifacts(
            State(state.clone()),
            admin.clone(),
            Path(docker_key.clone()),
            Query(query(Some("docker_tag"))),
        )
        .await;
        let by_id = crate::api::handlers::artifacts::get_artifact(
            State(state.clone()),
            admin,
            Path(promoted),
        )
        .await;

        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(docker_id)
            .execute(&pool)
            .await;
        tdh::cleanup_member_repo(&pool, docker_id, &docker_dir).await;
        tdh::cleanup_member_repo(&pool, target_id, &target_dir).await;
        tdh::cleanup(&pool, staging_id, user_id).await;
        let _ = std::fs::remove_dir_all(&staging_dir);

        let flat_admin = flat_admin.expect("admin flat listing").0;
        let find = |items: &[crate::api::handlers::repositories::ArtifactResponse], id: Uuid| {
            items
                .iter()
                .find(|i| i.id == id)
                .expect("listed")
                .last_promotion
                .clone()
        };
        let lp = find(&flat_admin.items, promoted).expect("promoted artifact carries state");
        assert_eq!(lp.target_repo_key.as_deref(), Some(target_key.as_str()));
        assert_eq!(lp.status, "promoted");
        assert_eq!(lp.promoted_at.timestamp(), hours(2).timestamp());
        assert_eq!(find(&flat_admin.items, rejected_only), None);
        assert_eq!(find(&flat_admin.items, never), None);

        // A caller who cannot read the (private) target sees the promotion
        // but not the target's key.
        let flat_reader = flat_reader.expect("reader flat listing").0;
        let lp = find(&flat_reader.items, promoted).expect("still reported");
        assert_eq!(lp.target_repo_key, None);
        assert_eq!(lp.promoted_at.timestamp(), hours(2).timestamp());

        let docker = docker_admin.expect("docker grouped listing").0;
        let tags = docker.docker_tags.expect("docker_tags present");
        assert_eq!(tags.len(), 1, "{tags:?}");
        assert_eq!(
            tags[0]
                .last_promotion
                .as_ref()
                .and_then(|p| p.target_repo_key.as_deref()),
            Some(target_key.as_str())
        );

        let by_id = by_id.expect("get artifact by id").0;
        assert_eq!(
            by_id.last_promotion.and_then(|p| p.target_repo_key),
            Some(target_key)
        );
    }
}
