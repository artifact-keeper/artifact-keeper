//! Per-repository Maven version policy (#5872).
//!
//! A hosted Maven or Gradle repository accepts release versions, SNAPSHOT
//! versions, or both (`repositories.version_policy`). Every seam that writes
//! an artifact into a repository asks [`check_write`] first: the Maven deploy
//! route, the generic artifact upload (which peer replication also pushes
//! through), promotion and approval, and the migration import.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
pub use crate::models::repository::MavenVersionPolicy;

/// Formats a version policy applies to, as `repository_format` labels
const POLICY_FORMATS: [&str; 2] = ["maven", "gradle"];

/// Whether a repository of this format can carry a version policy
pub fn applies_to_format(format: &str) -> bool {
    POLICY_FORMATS.contains(&format.to_ascii_lowercase().as_str())
}

/// Ivy `[type]s` directories under a revision (`org/mod/1.0/jars/mod.jar`)
const IVY_TYPE_DIRS: [&str; 6] = ["jars", "ivys", "poms", "srcs", "docs", "bundles"];

/// The kind of version a written path belongs to: `Some(true)` for a
/// SNAPSHOT, `Some(false)` for a release, `None` for a path that belongs to
/// no single version.
///
/// Only the version directory decides, the one holding the file or, in the
/// Ivy layout, the one above its `[type]s` directory. It is a SNAPSHOT when it
/// ends in `-SNAPSHOT`, case-sensitive like the Maven handler, so an artifact
/// named `db-snapshot` or a version `1.0-SNAPSHOT-rc1` is a release. Group and
/// artifact level `maven-metadata.xml` documents list both kinds and belong
/// to neither, and so does a path too short to carry a
/// `group/artifact/version/file` coordinate.
pub fn path_version_kind(path: &str) -> Option<bool> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (leaf, dirs) = segments.split_last()?;
    let version_dir = match dirs {
        [.., version, kind] if IVY_TYPE_DIRS.contains(kind) => *version,
        [.., version] => *version,
        [] => return None,
    };
    let snapshot = version_dir.ends_with("-SNAPSHOT");
    if leaf.starts_with("maven-metadata.xml") {
        return snapshot.then_some(true);
    }
    if snapshot {
        Some(true)
    } else if segments.len() >= 4 {
        Some(false)
    } else {
        None
    }
}

/// Why `policy` refuses a write of `path` into repository `repo_key`, or
/// `None` when it accepts it
pub fn refusal(policy: MavenVersionPolicy, repo_key: &str, path: &str) -> Option<String> {
    match (policy, path_version_kind(path)) {
        (MavenVersionPolicy::Release, Some(true)) => Some(format!(
            "Repository '{repo_key}' accepts release versions only"
        )),
        (MavenVersionPolicy::Snapshot, Some(false)) => Some(format!(
            "Repository '{repo_key}' accepts snapshot versions only"
        )),
        _ => None,
    }
}

/// The version policy stored for a repository, `Mixed` for a repository that
/// does not exist
pub async fn load(db: &PgPool, repo_id: Uuid) -> Result<MavenVersionPolicy> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT version_policy FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_optional(db)
            .await?;
    Ok(stored
        .as_deref()
        .and_then(MavenVersionPolicy::parse)
        .unwrap_or_default())
}

/// [`refusal`] for a policy as stored in `repositories.version_policy`, for
/// callers that already read the column with their own query
pub fn refusal_stored(stored: &str, repo_key: &str, path: &str) -> Option<String> {
    refusal(
        MavenVersionPolicy::parse(stored).unwrap_or_default(),
        repo_key,
        path,
    )
}

/// The policy of a repository of `format`, `Mixed` without a lookup for a
/// format that carries none. Loaded once for a batch of writes
pub async fn load_for_format(
    db: &PgPool,
    repo_id: Uuid,
    format: &str,
) -> Result<MavenVersionPolicy> {
    if applies_to_format(format) {
        load(db, repo_id).await
    } else {
        Ok(MavenVersionPolicy::Mixed)
    }
}

/// The policy of every Maven or Gradle repository among `repo_ids`, one
/// query for a listing. Other formats are absent from the map
pub async fn load_many(
    db: &PgPool,
    repo_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, MavenVersionPolicy>> {
    if repo_ids.is_empty() {
        return Ok(Default::default());
    }
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, version_policy FROM repositories \
         WHERE id = ANY($1) AND format::text = ANY($2)",
    )
    .bind(repo_ids)
    .bind(POLICY_FORMATS.map(str::to_string).to_vec())
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, stored)| (id, MavenVersionPolicy::parse(&stored).unwrap_or_default()))
        .collect())
}

/// Refuse with 400 a write of `path` into a Maven or Gradle repository whose
/// version policy does not accept it. Any other format passes without a
/// lookup
pub async fn check_write(
    db: &PgPool,
    repo_id: Uuid,
    repo_key: &str,
    format: &str,
    path: &str,
) -> Result<()> {
    if !applies_to_format(format) || path_version_kind(path).is_none() {
        return Ok(());
    }
    let policy = load(db, repo_id).await?;
    match refusal(policy, repo_key, path) {
        Some(reason) => Err(AppError::Validation(reason)),
        None => Ok(()),
    }
}

/// Why the version policy of the repository with key `repo_key` refuses a
/// write of `path`, for the migration import, which writes by destination
/// key. One lookup, none for a path that belongs to no single version, and
/// `None` for an unknown key, which the import reports on its own. The
/// database error is returned as is
pub async fn refusal_by_key(
    db: &PgPool,
    repo_key: &str,
    path: &str,
) -> std::result::Result<Option<String>, sqlx::Error> {
    if path_version_kind(path).is_none() {
        return Ok(None);
    }
    let repo: Option<(String, String)> =
        sqlx::query_as("SELECT format::text, version_policy FROM repositories WHERE key = $1")
            .bind(repo_key)
            .fetch_optional(db)
            .await?;
    Ok(repo.and_then(|(format, policy)| {
        let policy = MavenVersionPolicy::parse(&policy)?;
        applies_to_format(&format)
            .then(|| refusal(policy, repo_key, path))
            .flatten()
    }))
}

/// Whether a repository of this format, hosted (local or staging) or not,
/// can take `policy`. `mixed` fits every repository
pub fn accepts_policy(policy: MavenVersionPolicy, format: &str, hosted: bool) -> bool {
    policy == MavenVersionPolicy::Mixed || (hosted && applies_to_format(format))
}

/// The 400 for a policy on a repository that cannot carry one
pub fn not_applicable() -> AppError {
    AppError::Validation(
        "version_policy applies to local and staging Maven or Gradle repositories only".to_string(),
    )
}

/// Store a repository's version policy. Anything but `mixed` is refused with
/// 400 on a repository that is not a hosted (local or staging) Maven or
/// Gradle repository
pub async fn store(db: &PgPool, repo_id: Uuid, policy: MavenVersionPolicy) -> Result<()> {
    let shape: Option<(String, String)> =
        sqlx::query_as("SELECT format::text, repo_type::text FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_optional(db)
            .await?;
    let Some((format, repo_type)) = shape else {
        return Err(AppError::NotFound("Repository not found".to_string()));
    };
    let hosted = repo_type == "local" || repo_type == "staging";
    if !accepts_policy(policy, &format, hosted) {
        return Err(not_applicable());
    }
    sqlx::query("UPDATE repositories SET version_policy = $1 WHERE id = $2")
        .bind(policy.as_str())
        .bind(repo_id)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_kinds_5872() {
        let cases = [
            ("com/example/lib/1.0/lib-1.0.jar", Some(false)),
            ("com/example/lib/1.0/lib-1.0.pom.sha1", Some(false)),
            (
                "/com/example/lib/1.0-SNAPSHOT/lib-1.0-20260101.120000-1.jar",
                Some(true),
            ),
            (
                "com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.pom.md5",
                Some(true),
            ),
            (
                "com/example/lib/1.0-SNAPSHOT/maven-metadata.xml",
                Some(true),
            ),
            (
                "com/example/lib/1.0-SNAPSHOT/maven-metadata.xml.sha1",
                Some(true),
            ),
            ("org.example/mod/1.0-SNAPSHOT/jars/mod.jar", Some(true)),
            (
                "com/example/lib/1.0-SNAPSHOT-rc1/lib-1.0-SNAPSHOT-rc1.jar",
                Some(false),
            ),
            ("com/example/lib/maven-metadata.xml", None),
            ("com/acme/db-snapshot/1.0/db-snapshot-1.0.jar", Some(false)),
            ("com/acme/db-snapshot/maven-metadata.xml", None),
            (
                "com/example/lib/1.0-snapshot/lib-1.0-snapshot.jar",
                Some(false),
            ),
            ("org.example/mod/1.0/ivys/ivy.xml", Some(false)),
            ("com/example-SNAPSHOT/lib/1.0/lib-1.0.jar", Some(false)),
            ("com/example/maven-metadata.xml.sha1", None),
            ("archetype-catalog.xml", None),
            ("lib/1.0/lib.jar", None),
        ];
        for (path, kind) in cases {
            assert_eq!(path_version_kind(path), kind, "{path}");
        }
    }

    #[test]
    fn refusals_name_the_policy_5872() {
        let snap = "com/example/lib/1.0-SNAPSHOT/lib-1.0-20260101.120000-1.jar";
        let release = "com/example/lib/1.0/lib-1.0.jar";
        let ga_meta = "com/example/lib/maven-metadata.xml";
        assert_eq!(
            refusal(MavenVersionPolicy::Release, "rel", snap).as_deref(),
            Some("Repository 'rel' accepts release versions only")
        );
        assert_eq!(
            refusal(MavenVersionPolicy::Snapshot, "snap", release).as_deref(),
            Some("Repository 'snap' accepts snapshot versions only")
        );
        for policy in [
            MavenVersionPolicy::Mixed,
            MavenVersionPolicy::Release,
            MavenVersionPolicy::Snapshot,
        ] {
            assert_eq!(refusal(policy, "r", ga_meta), None, "{policy:?}");
        }
        assert_eq!(refusal(MavenVersionPolicy::Release, "r", release), None);
        assert_eq!(refusal(MavenVersionPolicy::Snapshot, "r", snap), None);
        assert_eq!(refusal(MavenVersionPolicy::Mixed, "r", snap), None);
        assert_eq!(refusal(MavenVersionPolicy::Mixed, "r", release), None);
    }

    #[test]
    fn policy_values_5872() {
        use MavenVersionPolicy::*;
        for policy in [Mixed, Release, Snapshot] {
            assert_eq!(MavenVersionPolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(MavenVersionPolicy::parse("RELEASE"), None);
        assert!(applies_to_format("maven") && applies_to_format("Gradle"));
        assert!(!applies_to_format("npm"));
        assert!(accepts_policy(Mixed, "npm", false));
        assert!(accepts_policy(Release, "maven", true));
        assert!(!accepts_policy(Release, "maven", false));
        assert!(!accepts_policy(Snapshot, "npm", true));
    }

    #[tokio::test]
    async fn store_and_check_write_5872() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (hosted, hosted_key, hosted_dir) = tdh::create_repo(&pool, "local", "maven").await;
        let (remote, _remote_key, remote_dir) = tdh::create_repo(&pool, "remote", "maven").await;
        let (npm, npm_key, npm_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let snap = "com/example/lib/1.0-SNAPSHOT/lib-1.0-20260101.120000-1.jar";
        let release = "com/example/lib/1.0/lib-1.0.jar";

        let default = load(&pool, hosted).await;
        let stored = store(&pool, hosted, MavenVersionPolicy::Release).await;
        let loaded = load(&pool, hosted).await;
        let snap_write = check_write(&pool, hosted, &hosted_key, "maven", snap).await;
        let release_write = check_write(&pool, hosted, &hosted_key, "maven", release).await;
        let npm_write = check_write(&pool, npm, &npm_key, "npm", snap).await;
        let by_key = refusal_by_key(&pool, &hosted_key, snap).await;
        let by_key_release = refusal_by_key(&pool, &hosted_key, release).await;
        let unknown_key = refusal_by_key(&pool, "no-such-repo-5872", snap).await;
        let on_remote = store(&pool, remote, MavenVersionPolicy::Release).await;
        let on_npm = store(&pool, npm, MavenVersionPolicy::Snapshot).await;
        let mixed_on_npm = store(&pool, npm, MavenVersionPolicy::Mixed).await;
        let missing = store(&pool, Uuid::new_v4(), MavenVersionPolicy::Release).await;
        let many = load_many(&pool, &[hosted, remote, npm]).await;
        let for_npm = load_for_format(&pool, npm, "npm").await;
        let for_hosted = load_for_format(&pool, hosted, "maven").await;

        for (id, dir) in [(hosted, hosted_dir), (remote, remote_dir), (npm, npm_dir)] {
            tdh::cleanup_member_repo(&pool, id, &dir).await;
        }

        assert_eq!(default.ok(), Some(MavenVersionPolicy::Mixed));
        assert!(stored.is_ok(), "{stored:?}");
        assert_eq!(loaded.ok(), Some(MavenVersionPolicy::Release));
        assert!(
            matches!(snap_write, Err(AppError::Validation(_))),
            "{snap_write:?}"
        );
        assert!(release_write.is_ok(), "{release_write:?}");
        assert!(npm_write.is_ok(), "{npm_write:?}");
        assert_eq!(
            by_key.ok().flatten().as_deref(),
            Some(format!("Repository '{hosted_key}' accepts release versions only").as_str())
        );
        assert_eq!(by_key_release.ok(), Some(None));
        assert_eq!(unknown_key.ok(), Some(None));
        assert!(
            matches!(on_remote, Err(AppError::Validation(_))),
            "{on_remote:?}"
        );
        assert!(matches!(on_npm, Err(AppError::Validation(_))), "{on_npm:?}");
        assert!(mixed_on_npm.is_ok(), "{mixed_on_npm:?}");
        assert!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
        let many = many.expect("load_many");
        assert_eq!(many.get(&hosted), Some(&MavenVersionPolicy::Release));
        assert_eq!(many.get(&remote), Some(&MavenVersionPolicy::Mixed));
        assert!(
            !many.contains_key(&npm),
            "an npm repository carries no policy"
        );
        assert_eq!(for_npm.ok(), Some(MavenVersionPolicy::Mixed));
        assert_eq!(for_hosted.ok(), Some(MavenVersionPolicy::Release));
        assert_eq!(
            refusal_stored("release", "r", "com/a/b/1.0-SNAPSHOT/b.jar").as_deref(),
            Some("Repository 'r' accepts release versions only")
        );
        assert_eq!(
            refusal_stored("bogus", "r", "com/a/b/1.0-SNAPSHOT/b.jar"),
            None
        );
    }
}
