//! Reads the [`ResourceIndex`]: repository placement and visibility, and the
//! known projects and groups. Callers read it inside the same snapshot
//! transaction as the legacy state (`begin_snapshot`), so policy and resource
//! facts describe one moment.

use sqlx::PgConnection;
use uuid::Uuid;

use super::snapshot::{RepositoryFacts, ResourceIndex};
use crate::models::repository::RepositoryVisibility;

/// Read the resource index. Select-only.
pub async fn read_resource_index(conn: &mut PgConnection) -> Result<ResourceIndex, sqlx::Error> {
    let repositories: Vec<(Uuid, Option<Uuid>, RepositoryVisibility)> =
        sqlx::query_as("SELECT id, project_id, visibility FROM repositories")
            .fetch_all(&mut *conn)
            .await?;
    let projects: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM projects")
        .fetch_all(&mut *conn)
        .await?;
    let groups: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM groups")
        .fetch_all(&mut *conn)
        .await?;
    Ok(ResourceIndex {
        repositories: repositories
            .into_iter()
            .map(|(id, project, visibility)| {
                (
                    id,
                    RepositoryFacts {
                        project,
                        visibility,
                    },
                )
            })
            .collect(),
        projects: projects.into_iter().map(|(id,)| id).collect(),
        groups: groups.into_iter().map(|(id,)| id).collect(),
    })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::iam_legacy_projection::begin_snapshot;

    #[test]
    fn resource_index_source_contains_only_selects() {
        let src = include_str!("resource_index.rs");
        let production = src.split("mod tests {").next().unwrap().to_uppercase();
        for verb in [
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "TRUNCATE ",
            "ALTER ",
            "DROP ",
            "CREATE ",
        ] {
            assert!(
                !production.contains(&format!("\"{verb}"))
                    && !production.contains(&format!(" {verb}INTO")),
                "resource_index.rs contains a `{verb}` statement"
            );
        }
    }

    #[tokio::test]
    async fn reads_placement_and_visibility_in_a_snapshot() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (group, _) = tdh::create_group(&pool).await;
        let (placed, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let (loose, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let project = Uuid::new_v4();
        sqlx::query("INSERT INTO projects (id, key, name) VALUES ($1, $2, 'p')")
            .bind(project)
            .bind(format!("proj-{project}"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE repositories SET project_id = $2, visibility = 'internal' WHERE id = $1",
        )
        .bind(placed)
        .bind(project)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE repositories SET visibility = 'public' WHERE id = $1")
            .bind(loose)
            .execute(&pool)
            .await
            .unwrap();

        let mut tx = begin_snapshot(&pool).await.unwrap();
        let index = read_resource_index(&mut tx).await.expect("read index");
        tx.rollback().await.unwrap();

        assert_eq!(
            index.repositories.get(&placed),
            Some(&RepositoryFacts {
                project: Some(project),
                visibility: RepositoryVisibility::Internal,
            })
        );
        assert_eq!(
            index.repositories.get(&loose),
            Some(&RepositoryFacts {
                project: None,
                visibility: RepositoryVisibility::Public,
            })
        );
        assert!(index.projects.contains(&project));
        assert!(index.groups.contains(&group));
    }
}
