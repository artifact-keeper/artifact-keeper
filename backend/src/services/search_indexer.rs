//! Keeps the OpenSearch artifacts index in step with native publishes (#5772)
//!
//! Format handlers write their `artifacts` rows themselves and announce them
//! on the event bus as `artifact.uploaded`, they never call the search service.
//! Without this subscriber a `mvn deploy` or `npm publish` only reached quick
//! search after a full reindex

use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::services::event_bus::{DomainEvent, EventBus};
use crate::services::opensearch_service::{ArtifactDocument, OpenSearchService};

/// Subscribe to the event bus and upsert the search document of every uploaded artifact
pub fn start_search_indexer(event_bus: Arc<EventBus>, db: PgPool, search: Arc<OpenSearchService>) {
    let mut rx = event_bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => index_uploaded_artifact(&db, &search, &event).await,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "Search indexer lagged, those uploads stay out of quick search until a reindex"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

async fn index_uploaded_artifact(db: &PgPool, search: &OpenSearchService, event: &DomainEvent) {
    if event.event_type != "artifact.uploaded" {
        return;
    }
    // A publish whose artifact row could not be resolved carries `name@version` instead of an id
    let Ok(artifact_id) = Uuid::parse_str(&event.entity_id) else {
        return;
    };
    match artifact_document_for(db, artifact_id).await {
        Ok(Some(doc)) => {
            if let Err(e) = search.index_artifact(&doc).await {
                tracing::warn!(artifact_id = %artifact_id, "Failed to index uploaded artifact in OpenSearch: {e}");
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(artifact_id = %artifact_id, "Failed to load uploaded artifact for OpenSearch indexing: {e}");
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ArtifactIndexRow {
    id: Uuid,
    name: String,
    path: String,
    version: Option<String>,
    content_type: String,
    size_bytes: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    repository_id: Uuid,
    repository_key: String,
    repository_name: String,
    format: String,
    is_public: bool,
}

/// The search document of a live artifact, the same fields the REST upload path indexes
pub async fn artifact_document_for(
    db: &PgPool,
    artifact_id: Uuid,
) -> Result<Option<ArtifactDocument>, sqlx::Error> {
    let row: Option<ArtifactIndexRow> = sqlx::query_as(
        r#"
        SELECT
            a.id,
            a.name,
            a.path,
            a.version,
            a.content_type,
            a.size_bytes,
            a.created_at,
            a.repository_id,
            r.key AS repository_key,
            r.name AS repository_name,
            r.format::text AS format,
            r.is_public
        FROM artifacts a
        INNER JOIN repositories r ON a.repository_id = r.id
        WHERE a.id = $1 AND a.is_deleted = false
        "#,
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await?;

    Ok(row.map(|row| ArtifactDocument {
        id: row.id.to_string(),
        name: row.name,
        path: row.path,
        version: row.version,
        format: row.format,
        repository_id: row.repository_id.to_string(),
        repository_key: row.repository_key,
        repository_name: row.repository_name,
        content_type: row.content_type,
        size_bytes: row.size_bytes,
        download_count: 0,
        is_public: row.is_public,
        created_at: row.created_at.timestamp(),
    }))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn npm_publish_body(package: &str, version: &str) -> bytes::Bytes {
        use base64::Engine;
        let tarball = base64::engine::general_purpose::STANDARD.encode(b"tgz");
        bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "name": package,
                "versions": { version: { "name": package, "version": version } },
                "_attachments": { format!("{package}-{version}.tgz"): { "data": tarball } }
            }))
            .expect("publish body"),
        )
    }

    async fn artifact_id_of(fx: &tdh::Fixture, name: &str) -> Uuid {
        sqlx::query_scalar("SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2")
            .bind(fx.repo_id)
            .bind(name)
            .fetch_one(&fx.pool)
            .await
            .expect("published artifact row")
    }

    #[tokio::test]
    async fn native_npm_publish_reaches_the_search_index_5772() {
        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let opensearch = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&opensearch)
            .await;
        let search =
            OpenSearchService::new(&opensearch.uri(), None, None, false).expect("search service");
        start_search_indexer(
            fx.state.event_bus.clone(),
            fx.pool.clone(),
            Arc::new(search),
        );

        let app = fx.router_with_auth(crate::api::handlers::npm::router());
        let (status, body) = tdh::send(
            app,
            tdh::put_json(
                format!("/{}/idxpkg", fx.repo_key),
                npm_publish_body("idxpkg", "1.0.0"),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "npm publish: {status} {}",
            String::from_utf8_lossy(&body)
        );
        let artifact_id = artifact_id_of(&fx, "idxpkg").await;
        let doc_path = format!("/artifacts/_doc/{artifact_id}");

        let mut indexed = None;
        for _ in 0..100 {
            let requests = opensearch.received_requests().await.unwrap_or_default();
            if let Some(req) = requests.iter().find(|r| r.url.path() == doc_path) {
                indexed = Some(serde_json::from_slice::<serde_json::Value>(&req.body).unwrap());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let doc = indexed.expect("a native publish must upsert its search document");
        assert_eq!(doc["id"], artifact_id.to_string());
        assert_eq!(doc["repository_key"], fx.repo_key);
        assert_eq!(doc["name"], "idxpkg");
        assert_eq!(doc["version"], "1.0.0");
        assert_eq!(doc["format"], "npm");
        fx.teardown().await;
    }

    #[tokio::test]
    async fn artifact_document_for_maps_live_rows_only() {
        let Some(fx) = tdh::Fixture::setup("local", "npm").await else {
            return;
        };
        let app = fx.router_with_auth(crate::api::handlers::npm::router());
        let (status, _) = tdh::send(
            app,
            tdh::put_json(
                format!("/{}/docpkg", fx.repo_key),
                npm_publish_body("docpkg", "2.1.0"),
            ),
        )
        .await;
        assert!(status.is_success(), "npm publish: {status}");
        let artifact_id = artifact_id_of(&fx, "docpkg").await;
        let (path, created_at, is_public): (String, chrono::DateTime<chrono::Utc>, bool) =
            sqlx::query_as(
                "SELECT a.path, a.created_at, r.is_public FROM artifacts a \
                 JOIN repositories r ON r.id = a.repository_id WHERE a.id = $1",
            )
            .bind(artifact_id)
            .fetch_one(&fx.pool)
            .await
            .expect("artifact row");

        let doc = artifact_document_for(&fx.pool, artifact_id)
            .await
            .expect("query")
            .expect("live artifact has a document");
        assert_eq!(doc.id, artifact_id.to_string());
        assert_eq!(doc.name, "docpkg");
        assert_eq!(doc.path, path);
        assert_eq!(doc.version.as_deref(), Some("2.1.0"));
        assert_eq!(doc.format, "npm");
        assert_eq!(doc.repository_id, fx.repo_id.to_string());
        assert_eq!(doc.repository_key, fx.repo_key);
        assert_eq!(doc.is_public, is_public);
        assert_eq!(doc.created_at, created_at.timestamp());

        assert!(artifact_document_for(&fx.pool, Uuid::new_v4())
            .await
            .expect("query")
            .is_none());
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(artifact_id)
            .execute(&fx.pool)
            .await
            .expect("soft delete");
        assert!(artifact_document_for(&fx.pool, artifact_id)
            .await
            .expect("query")
            .is_none());
        fx.teardown().await;
    }
}
