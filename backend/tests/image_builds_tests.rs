//! DB-backed tests for the image builder's persistence and runner
//! (issue #4034).
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!     cargo test --test image_builds_tests -- --ignored
//! ```
//!
//! The runner is exercised with a fake `buildctl`: a shell script that
//! records its arguments, prints to stdout/stderr and exits how the test
//! asks. That covers everything around the daemon — the row's status
//! transitions, log capture, the short-lived push token and its revocation,
//! the timeout — without a BuildKit daemon.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::image_build_service::{
    render_containerfile, run_build, BuildJob, ImageBuildSettings, ImageBuildSpec, ImageBuildStore,
    NewImageBuild, PackageGroup, PackageManager,
};
use common::{insert_active_user, require_db_pool, test_config_with_default_jwt};

async fn insert_docker_repo(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("ib-{}", &id.to_string()[..8]);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $2, $3, 'local', 'docker')",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("repositories/{key}"))
    .execute(pool)
    .await
    .expect("failed to create test repository");
    (id, key)
}

async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

fn spec() -> ImageBuildSpec {
    ImageBuildSpec {
        base_image: "python:3.12-slim".into(),
        packages: vec![
            PackageGroup {
                manager: PackageManager::Apt,
                packages: vec!["libgomp1".into()],
                channels: vec![],
            },
            PackageGroup {
                manager: PackageManager::Pip,
                packages: vec!["polars-lts-cpu==1.9.0".into()],
                channels: vec![],
            },
        ],
        multistage: true,
        user: Some("app".into()),
        ..Default::default()
    }
}

/// A `buildctl` stand-in. `$1..` are recorded to `<dir>/args`, the docker
/// config it was handed is copied to `<dir>/config.json`, then it runs
/// `body` and exits with `code`.
fn fake_buildctl(dir: &std::path::Path, body: &str, code: i32) -> String {
    let path = dir.join("buildctl");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{d}/args\"\ncp \"$DOCKER_CONFIG/config.json\" \"{d}/config.json\" 2>/dev/null\n{body}\nexit {code}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

fn settings(buildctl: &str) -> ImageBuildSettings {
    ImageBuildSettings {
        buildkit_addr: Some("tcp://buildkitd.test:1234".into()),
        buildctl_path: buildctl.into(),
        push_registry: Some("registry.test:8080".into()),
        registry_insecure: true,
        base_allowlist: vec!["python:".into()],
        allow_run: false,
        allow_dockerfile: false,
        timeout: Duration::from_secs(60),
        max_concurrent: 4,
        admin_only: true,
        pip_index_url: None,
    }
}

struct Scenario {
    pool: PgPool,
    repo_id: Uuid,
    repo_key: String,
    user_id: Uuid,
    record_id: Uuid,
    dir: tempfile::TempDir,
}

impl Scenario {
    async fn new(image: &str, tag: &str) -> Self {
        let pool = require_db_pool().await;
        let (repo_id, repo_key) = insert_docker_repo(&pool).await;
        let user_id = insert_active_user(&pool, "ib").await;
        let store = ImageBuildStore::new(&pool);
        let spec = spec();
        let containerfile = render_containerfile(&spec);
        let record = store
            .insert(NewImageBuild {
                repository_id: repo_id,
                image,
                tag,
                spec: &spec,
                containerfile: &containerfile,
                requested_by: Some(user_id),
                requested_by_name: "ib-user",
            })
            .await
            .expect("insert build");
        Self {
            pool,
            repo_id,
            repo_key,
            user_id,
            record_id: record.id,
            dir: tempfile::tempdir().unwrap(),
        }
    }

    async fn run(&self, settings: ImageBuildSettings) {
        let store = ImageBuildStore::new(&self.pool);
        let record = store
            .get(self.repo_id, self.record_id)
            .await
            .unwrap()
            .unwrap();
        run_build(BuildJob {
            db: self.pool.clone(),
            config: test_config_with_default_jwt(),
            settings,
            record,
            repository_key: self.repo_key.clone(),
            user_id: self.user_id,
            username: "ib-user".into(),
        })
        .await;
    }

    async fn record(
        &self,
    ) -> artifact_keeper_backend::services::image_build_service::ImageBuildRecord {
        ImageBuildStore::new(&self.pool)
            .get(self.repo_id, self.record_id)
            .await
            .unwrap()
            .expect("record exists")
    }

    async fn log(&self) -> String {
        ImageBuildStore::new(&self.pool)
            .log(self.repo_id, self.record_id)
            .await
            .unwrap()
            .unwrap_or_default()
    }

    /// `(name, revoked)` for every API token minted for the user.
    async fn tokens(&self) -> Vec<(String, bool)> {
        sqlx::query_as::<_, (String, bool)>(
            "SELECT name, revoked_at IS NOT NULL FROM api_tokens WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(self.user_id)
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn finish(self) {
        cleanup(&self.pool, self.repo_id, self.user_id).await;
    }
}

#[tokio::test]
#[ignore]
async fn store_round_trips_a_package_group_spec() {
    let s = Scenario::new("team/app", "1.0").await;
    let store = ImageBuildStore::new(&s.pool);

    let rec = s.record().await;
    assert_eq!(rec.status, "queued");
    assert_eq!(rec.image, "team/app");
    assert_eq!(rec.tag, "1.0");
    assert_eq!(rec.requested_by, Some(s.user_id));
    assert_eq!(rec.requested_by_name, "ib-user");
    assert_eq!(rec.log_bytes, 0);
    assert!(rec.started_at.is_none() && rec.finished_at.is_none());
    assert_eq!(rec.spec["packages"][0]["manager"], "apt");
    assert_eq!(
        rec.spec["packages"][1]["packages"][0],
        "polars-lts-cpu==1.9.0"
    );
    assert_eq!(rec.spec["multistage"], true);
    assert!(rec
        .containerfile
        .contains("FROM python:3.12-slim AS builder"));
    assert!(rec.containerfile.contains("apt-get install"));

    let listed = store.list(s.repo_id, 10).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, s.record_id);
    assert!(store.list(Uuid::new_v4(), 10).await.unwrap().is_empty());
    assert!(store
        .get(Uuid::new_v4(), s.record_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(s.log().await, "");

    let spec_back: ImageBuildSpec = serde_json::from_value(rec.spec.clone()).unwrap();
    assert_eq!(spec_back.groups().len(), 2);
    s.finish().await;
}

#[tokio::test]
#[ignore]
async fn a_successful_build_records_the_log_the_pushed_digest_and_revokes_its_token() {
    let s = Scenario::new("team/app", "1.0").await;
    let digest = format!("sha256:{}", "ab".repeat(32));
    // The push the fake buildctl "did": the tag row the registry writes.
    sqlx::query(
        "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest) VALUES ($1, $2, $3, $4)",
    )
    .bind(s.repo_id)
    .bind("team/app")
    .bind("1.0")
    .bind(&digest)
    .execute(&s.pool)
    .await
    .unwrap();

    let buildctl = fake_buildctl(
        s.dir.path(),
        "echo '#1 [internal] load build definition'\necho '#7 exporting to image' >&2",
        0,
    );
    s.run(settings(&buildctl)).await;

    let rec = s.record().await;
    assert_eq!(rec.status, "succeeded", "error: {:?}", rec.error);
    assert_eq!(rec.digest.as_deref(), Some(digest.as_str()));
    assert!(rec.error.is_none());
    assert!(rec.started_at.is_some() && rec.finished_at.is_some());
    assert!(rec.log_bytes > 0);

    let log = s.log().await;
    assert!(log.contains(&format!("== image build {} ==", s.record_id)));
    assert!(log.contains("base: python:3.12-slim"));
    assert!(log.contains(&format!(
        "target: registry.test:8080/{}/team/app:1.0",
        s.repo_key
    )));
    assert!(log.contains("#1 [internal] load build definition"));
    assert!(
        log.contains("#7 exporting to image"),
        "stderr is captured too"
    );
    assert!(log.contains(&format!("== pushed {digest} ==")));

    // buildctl was pointed at the daemon, asked for max provenance, and told
    // to push to this registry over plain HTTP.
    let args = std::fs::read_to_string(s.dir.path().join("args")).unwrap();
    assert!(args.contains("--addr\ntcp://buildkitd.test:1234\n"));
    assert!(args.contains("attest:provenance=mode=max"));
    assert!(args.contains(&format!(
        "type=image,name=registry.test:8080/{}/team/app:1.0,push=true,oci-mediatypes=true,registry.insecure=true",
        s.repo_key
    )));
    let dockerfile_dir = args
        .lines()
        .find_map(|l| l.strip_prefix("dockerfile="))
        .expect("dockerfile context");
    // The context directory is gone with the build; what it held was the
    // rendered Containerfile and nothing else.
    assert!(!std::path::Path::new(dockerfile_dir).exists());

    // The push credential: Basic <user>:<token> for the push host, minted for
    // this build and revoked once it ended.
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(s.dir.path().join("config.json")).unwrap())
            .unwrap();
    assert!(config["auths"]["registry.test:8080"]["auth"].is_string());
    assert_eq!(
        s.tokens().await,
        vec![(format!("image-build {}", s.record_id), true)]
    );
    s.finish().await;
}

#[tokio::test]
#[ignore]
async fn a_failing_buildctl_marks_the_build_failed_with_its_output() {
    let s = Scenario::new("team/app", "bad").await;
    let buildctl = fake_buildctl(
        s.dir.path(),
        "echo 'error: failed to solve: rayproject/ray:2.56.0: not found' >&2",
        3,
    );
    s.run(settings(&buildctl)).await;

    let rec = s.record().await;
    assert_eq!(rec.status, "failed");
    assert_eq!(rec.error.as_deref(), Some("buildctl exited with 3"));
    assert!(rec.digest.is_none());
    let log = s.log().await;
    assert!(log.contains("failed to solve"));
    assert!(log.contains("== build failed: buildctl exited with 3 =="));
    assert_eq!(
        s.tokens().await,
        vec![(format!("image-build {}", s.record_id), true)]
    );
    s.finish().await;
}

#[tokio::test]
#[ignore]
async fn a_hung_build_is_stopped_at_the_timeout() {
    let s = Scenario::new("team/app", "slow").await;
    let buildctl = fake_buildctl(s.dir.path(), "echo started; sleep 30", 0);
    let mut st = settings(&buildctl);
    st.timeout = Duration::from_secs(2);
    let t0 = Instant::now();
    s.run(st).await;
    assert!(
        t0.elapsed() < Duration::from_secs(15),
        "the child was killed, not waited for"
    );

    let rec = s.record().await;
    assert_eq!(rec.status, "failed");
    assert_eq!(
        rec.error.as_deref(),
        Some("build exceeded 2 seconds and was stopped")
    );
    assert!(s.log().await.contains("started"));
    assert_eq!(
        s.tokens().await,
        vec![(format!("image-build {}", s.record_id), true)]
    );
    s.finish().await;
}

#[tokio::test]
#[ignore]
async fn an_unconfigured_or_missing_buildctl_fails_without_minting_a_token_that_lives() {
    let s = Scenario::new("team/app", "none").await;
    let mut st = settings("/nonexistent/buildctl");
    st.push_registry = None;
    s.run(st).await;
    let rec = s.record().await;
    assert_eq!(rec.status, "failed");
    assert_eq!(
        rec.error.as_deref(),
        Some("image builds are not configured")
    );
    assert!(
        s.tokens().await.is_empty(),
        "no token before the registry check"
    );

    // Re-run the same row with a registry but an unspawnable client: the token
    // is minted for the attempt and revoked when the spawn fails.
    sqlx::query("UPDATE image_builds SET status = 'queued', error = NULL WHERE id = $1")
        .bind(s.record_id)
        .execute(&s.pool)
        .await
        .unwrap();
    s.run(settings("/nonexistent/buildctl")).await;
    let rec = s.record().await;
    assert_eq!(rec.status, "failed");
    assert!(rec
        .error
        .as_deref()
        .unwrap()
        .starts_with("could not start /nonexistent/buildctl"));
    assert_eq!(
        s.tokens().await,
        vec![(format!("image-build {}", s.record_id), true)]
    );
    s.finish().await;
}
