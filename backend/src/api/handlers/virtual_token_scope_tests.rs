//! #4559: a token scoped to a virtual repository reads that virtual's members
//! THROUGH the virtual, still subject to its owner's grants on each member,
//! and never through the member's own URL.
//!
//! Router-level: every request goes through `create_router`, so the format
//! middleware (`repo_visibility_middleware`), the REST `require_visible`
//! gates and the member walks are all the production ones. The two seams the
//! issue names are both exercised: `member_passes_token_scope` (REST
//! `/members` and `/artifacts` listings) and
//! `proxy_helpers::caller_can_read_member` / `try_authorize_virtual_members`
//! (conda repodata and package download, PyPI simple index and download,
//! REST by-path download).
//!
//! Fixture (all repositories PRIVATE):
//!
//! ```text
//! conda-virtual  = [conda-internal (hosted), conda-forge (remote), conda-secret (hosted)]
//! pypi-virtual   = [pypi-internal (hosted), pypi-secret (hosted)]
//! conda-unrelated (hosted, not a member of anything)
//! ```
//!
//! The token owner holds a read grant on every repository except the two
//! `*-secret` members, which stand for "a member the owner cannot read".

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bytes::Bytes;
use std::sync::Arc;
use uuid::Uuid;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::api::handlers::test_db_helpers as tdh;
use crate::api::SharedState;
use crate::services::auth_service::AuthService;

const INTERNAL_PKG: &str = "acme-core-1.0-0.tar.bz2";
const INTERNAL_BYTES: &[u8] = b"conda-internal-package-bytes";
const SECRET_PKG: &str = "secret-sauce-1.0-0.tar.bz2";
const FORGE_PKG: &str = "forge-pkg-2.0-0.conda";
const FORGE_BYTES: &[u8] = b"conda-forge-package-bytes";
const UNRELATED_PKG: &str = "unrelated-1.0-0.tar.bz2";

const PYPI_FILE: &str = "acme_lib-1.0.0-py3-none-any.whl";
const PYPI_BYTES: &[u8] = b"pypi-internal-wheel-bytes";
const PYPI_SECRET_FILE: &str = "secret_lib-1.0.0-py3-none-any.whl";

struct Repo {
    id: Uuid,
    key: String,
    dir: std::path::PathBuf,
}

async fn repo(pool: &sqlx::PgPool, repo_type: &str, format: &str) -> Repo {
    let (id, key, dir) = tdh::create_repo(pool, repo_type, format).await;
    Repo { id, key, dir }
}

struct Rig {
    pool: sqlx::PgPool,
    state: SharedState,
    owner: Uuid,
    conda_virtual: Repo,
    conda_internal: Repo,
    conda_forge: Repo,
    conda_secret: Repo,
    conda_unrelated: Repo,
    pypi_virtual: Repo,
    pypi_internal: Repo,
    pypi_secret: Repo,
    internal_artifact: Uuid,
    _upstream: MockServer,
    _root: tempfile::TempDir,
}

/// Seed a hosted conda package with bytes in the member's storage and the
/// metadata document an upload writes (repodata is built from it).
async fn seed_conda(
    state: &SharedState,
    pool: &sqlx::PgPool,
    r: &Repo,
    filename: &str,
    bytes: &[u8],
    by: Uuid,
) -> Uuid {
    let (name, version, build) =
        crate::formats::conda_native::CondaNativeHandler::parse_package_filename(filename)
            .expect("fixture filename parses");
    let path = format!("noarch/{filename}");
    let info = tdh::make_repo_info(r.id, &r.key, &r.dir, "local", None);
    let id = tdh::seed_artifact(
        state,
        pool,
        &info,
        &format!("conda/{}/{path}", r.id),
        &path,
        &name,
        &version,
        "application/x-tar",
        Bytes::copy_from_slice(bytes),
        by,
    )
    .await;
    sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, 'conda', $2)",
    )
    .bind(id)
    .bind(serde_json::json!({
        "name": name, "version": version, "build": build, "build_number": 0,
        "subdir": "noarch", "depends": [], "constrains": [], "license": "MIT",
        "md5": "0".repeat(32),
    }))
    .execute(pool)
    .await
    .expect("conda metadata");
    id
}

async fn seed_pypi(
    state: &SharedState,
    pool: &sqlx::PgPool,
    r: &Repo,
    project: &str,
    filename: &str,
    bytes: &[u8],
    by: Uuid,
) {
    let path = format!("{project}/1.0.0/{filename}");
    let info = tdh::make_repo_info(r.id, &r.key, &r.dir, "local", None);
    tdh::seed_artifact(
        state,
        pool,
        &info,
        &path,
        &path,
        project,
        "1.0.0",
        "application/zip",
        Bytes::copy_from_slice(bytes),
        by,
    )
    .await;
}

impl Rig {
    async fn new(pool: sqlx::PgPool) -> Self {
        let upstream = MockServer::start().await;
        let forge_record = serde_json::json!({
            "build": "0", "build_number": 0, "depends": [], "md5": "1".repeat(32),
            "name": "forge-pkg", "sha256": "2".repeat(64), "size": FORGE_BYTES.len(),
            "subdir": "noarch", "version": "2.0",
        });
        Mock::given(method("GET"))
            .and(wm_path("/noarch/repodata.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "info": {"subdir": "noarch"},
                "packages": {},
                "packages.conda": { FORGE_PKG: forge_record },
                "repodata_version": 1,
            })))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/noarch/{FORGE_PKG}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(FORGE_BYTES.to_vec()))
            .mount(&upstream)
            .await;

        let conda_virtual = repo(&pool, "virtual", "conda").await;
        let conda_internal = repo(&pool, "local", "conda").await;
        let conda_forge = repo(&pool, "remote", "conda").await;
        let conda_secret = repo(&pool, "local", "conda").await;
        let conda_unrelated = repo(&pool, "local", "conda").await;
        let pypi_virtual = repo(&pool, "virtual", "pypi").await;
        let pypi_internal = repo(&pool, "local", "pypi").await;
        let pypi_secret = repo(&pool, "local", "pypi").await;
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream.uri())
            .bind(conda_forge.id)
            .execute(&pool)
            .await
            .expect("point conda-forge at the mock upstream");
        tdh::link_virtual_member(&pool, conda_virtual.id, conda_internal.id, 1).await;
        tdh::link_virtual_member(&pool, conda_virtual.id, conda_forge.id, 2).await;
        tdh::link_virtual_member(&pool, conda_virtual.id, conda_secret.id, 3).await;
        tdh::link_virtual_member(&pool, pypi_virtual.id, pypi_internal.id, 1).await;
        tdh::link_virtual_member(&pool, pypi_virtual.id, pypi_secret.id, 2).await;

        let (owner, _name) = tdh::create_user(&pool).await;
        for r in [
            &conda_virtual,
            &conda_internal,
            &conda_forge,
            &conda_unrelated,
            &pypi_virtual,
            &pypi_internal,
        ] {
            tdh::grant_repo_role(&pool, r.id, owner, "reader").await;
        }

        let root = tempfile::tempdir().expect("storage root");
        let root_path = root.path().to_str().expect("utf8").to_string();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), &root_path);
        let state = tdh::build_state_with_proxy(pool.clone(), &root_path, proxy);

        let internal_artifact = seed_conda(
            &state,
            &pool,
            &conda_internal,
            INTERNAL_PKG,
            INTERNAL_BYTES,
            owner,
        )
        .await;
        seed_conda(&state, &pool, &conda_secret, SECRET_PKG, b"secret", owner).await;
        seed_conda(
            &state,
            &pool,
            &conda_unrelated,
            UNRELATED_PKG,
            b"unrelated",
            owner,
        )
        .await;
        seed_pypi(
            &state,
            &pool,
            &pypi_internal,
            "acme-lib",
            PYPI_FILE,
            PYPI_BYTES,
            owner,
        )
        .await;
        seed_pypi(
            &state,
            &pool,
            &pypi_secret,
            "secret-lib",
            PYPI_SECRET_FILE,
            b"secret",
            owner,
        )
        .await;

        Self {
            pool,
            state,
            owner,
            conda_virtual,
            conda_internal,
            conda_forge,
            conda_secret,
            conda_unrelated,
            pypi_virtual,
            pypi_internal,
            pypi_secret,
            internal_artifact,
            _upstream: upstream,
            _root: root,
        }
    }

    async fn mint(&self, name: &str) -> (String, Uuid) {
        AuthService::new(self.pool.clone(), Arc::new(self.state.config.clone()))
            .generate_api_token(
                self.owner,
                name,
                vec![
                    "read:artifacts".to_string(),
                    "read:repositories".to_string(),
                ],
                None,
            )
            .await
            .expect("mint API token")
    }

    /// A repository token on `repo`, pinned the way `create_repo_token`
    /// (`repo_tokens.rs`) pins it: restriction marker, then the join row.
    async fn repo_token(&self, repo: &Repo) -> String {
        let (token, id) = self.mint("consumer-repo").await;
        sqlx::query("UPDATE api_tokens SET repository_restricted = true WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .expect("mark restricted");
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(id)
            .bind(repo.id)
            .execute(&self.pool)
            .await
            .expect("pin token");
        token
    }

    /// A user token whose `repo_selector` names only `repo`.
    async fn selector_token(&self, repo: &Repo) -> String {
        let (token, id) = self.mint("consumer-selector").await;
        crate::services::repo_selector_service::store_token_selector(
            &self.pool,
            id,
            &serde_json::json!({ "match_repos": [repo.id] }),
        )
        .await
        .expect("store selector");
        token
    }

    async fn get(&self, token: &str, uri: String) -> (StatusCode, Bytes) {
        let app = crate::api::routes::create_router(self.state.clone());
        // An empty `token` sends no header: the credential is in the path.
        let mut req = Request::builder().method("GET").uri(uri);
        if !token.is_empty() {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let req = req.body(Body::empty()).expect("request");
        tdh::send(app, req).await
    }

    /// `/conda/<key>/noarch/<file>` status, plus the body.
    async fn conda(&self, token: &str, r: &Repo, file: &str) -> (StatusCode, Bytes) {
        self.get(token, format!("/conda/{}/noarch/{file}", r.key))
            .await
    }

    async fn repodata_names(&self, token: &str, r: &Repo) -> (StatusCode, Vec<String>) {
        let (status, body) = self.conda(token, r, "repodata.json").await;
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let mut names: Vec<String> = ["packages", "packages.conda"]
            .iter()
            .filter_map(|k| doc.get(*k).and_then(|v| v.as_object()))
            .flat_map(|m| m.keys().cloned())
            .collect();
        names.sort();
        (status, names)
    }

    async fn rest_json(&self, token: &str, uri: String) -> (StatusCode, serde_json::Value) {
        let (status, body) = self.get(token, uri).await;
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    async fn member_keys(&self, token: &str, r: &Repo) -> (StatusCode, Vec<String>) {
        let (status, json) = self
            .rest_json(token, format!("/api/v1/repositories/{}/members", r.key))
            .await;
        let keys = json["members"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|m| m["member_repo_key"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        (status, keys)
    }

    async fn artifact_paths(&self, token: &str, r: &Repo) -> (StatusCode, Vec<String>) {
        let (status, json) = self
            .rest_json(token, format!("/api/v1/repositories/{}/artifacts", r.key))
            .await;
        let paths = json["items"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|a| a["path"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        (status, paths)
    }

    async fn cleanup(self) {
        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(self.owner)
            .execute(&self.pool)
            .await;
        for r in [
            &self.conda_virtual,
            &self.conda_internal,
            &self.conda_forge,
            &self.conda_secret,
            &self.conda_unrelated,
            &self.pypi_virtual,
            &self.pypi_internal,
            &self.pypi_secret,
        ] {
            let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
                .bind(r.id)
                .execute(&self.pool)
                .await;
            let _ = sqlx::query("DELETE FROM proxy_cache_artifacts WHERE repository_id = $1")
                .bind(r.id)
                .execute(&self.pool)
                .await;
            tdh::cleanup_member_repo(&self.pool, r.id, &r.dir).await;
        }
        tdh::cleanup_user(&self.pool, self.owner).await;
    }
}

/// The issue's token matrix, for a repository token and for a user token
/// whose selector names the virtual: through `conda-virtual` the hosted
/// member's package and the remote member's package download and both appear
/// in the merged repodata; directly, `conda-internal` and `conda-forge` are
/// refused exactly as before; an unrelated repository is unchanged; and the
/// member the owner holds no grant on stays invisible and undownloadable
/// through the virtual.
#[tokio::test]
async fn virtual_scoped_token_reads_conda_members_through_the_virtual_only_4559() {
    let Some(pool) = tdh::try_pool().await else {
        return;
    };
    let rig = Rig::new(pool).await;

    // Positive control: the owner's unrestricted token reads every granted
    // repository directly, so the refusals below are the token scope's doing.
    let (owner_token, _) = rig.mint("owner-unrestricted").await;
    let owner_internal = rig
        .conda(&owner_token, &rig.conda_internal, INTERNAL_PKG)
        .await
        .0;
    let owner_unrelated = rig
        .conda(&owner_token, &rig.conda_unrelated, UNRELATED_PKG)
        .await
        .0;

    let mut rows = Vec::new();
    for (label, token) in [
        ("repository token", rig.repo_token(&rig.conda_virtual).await),
        (
            "selector token",
            rig.selector_token(&rig.conda_virtual).await,
        ),
    ] {
        let v = &rig.conda_virtual;
        let (repodata_status, names) = rig.repodata_names(&token, v).await;
        let via_internal = rig.conda(&token, v, INTERNAL_PKG).await;
        let via_forge = rig.conda(&token, v, FORGE_PKG).await;
        let via_secret = rig.conda(&token, v, SECRET_PKG).await.0;
        // The rattler `/t/<token>/` layout routes through the same virtual.
        let t_form = rig
            .get(
                "",
                format!("/t/{token}/conda/{}/noarch/{INTERNAL_PKG}", v.key),
            )
            .await
            .0;
        let direct_internal = rig.conda(&token, &rig.conda_internal, INTERNAL_PKG).await.0;
        let direct_internal_repodata = rig
            .conda(&token, &rig.conda_internal, "repodata.json")
            .await
            .0;
        let direct_forge = rig.conda(&token, &rig.conda_forge, FORGE_PKG).await.0;
        let direct_forge_repodata = rig.conda(&token, &rig.conda_forge, "repodata.json").await.0;
        let unrelated = rig
            .conda(&token, &rig.conda_unrelated, UNRELATED_PKG)
            .await
            .0;
        rows.push((
            label,
            repodata_status,
            names,
            via_internal,
            via_forge,
            via_secret,
            t_form,
            [
                direct_internal,
                direct_internal_repodata,
                direct_forge,
                direct_forge_repodata,
                unrelated,
            ],
        ));
    }
    rig.cleanup().await;

    assert_eq!(
        owner_internal,
        StatusCode::OK,
        "control: owner reads conda-internal"
    );
    assert_eq!(
        owner_unrelated,
        StatusCode::OK,
        "control: owner reads the unrelated repo"
    );
    for (label, repodata_status, names, via_internal, via_forge, via_secret, t_form, direct) in rows
    {
        assert_eq!(repodata_status, StatusCode::OK, "{label}: virtual repodata");
        assert_eq!(
            names,
            vec![INTERNAL_PKG.to_string(), FORGE_PKG.to_string()],
            "{label}: the merged repodata lists both readable members and not the \
             member the owner cannot read"
        );
        assert_eq!(
            via_internal.0,
            StatusCode::OK,
            "{label}: hosted member through the virtual"
        );
        assert_eq!(&via_internal.1[..], INTERNAL_BYTES, "{label}");
        assert_eq!(
            via_forge.0,
            StatusCode::OK,
            "{label}: remote member through the virtual"
        );
        assert_eq!(&via_forge.1[..], FORGE_BYTES, "{label}");
        assert_eq!(
            via_secret,
            StatusCode::NOT_FOUND,
            "{label}: a member the owner cannot read stays undownloadable through the virtual"
        );
        assert_eq!(
            t_form,
            StatusCode::OK,
            "{label}: /t/<token>/ form of the virtual"
        );
        for (what, status) in [
            "conda-internal package",
            "conda-internal repodata",
            "conda-forge package",
            "conda-forge repodata",
            "unrelated package",
        ]
        .iter()
        .zip(direct)
        {
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{label}: a direct read of {what} stays refused (existence-hiding 404)"
            );
        }
    }
}

/// The same seam on a second format: a PyPI virtual. The simple index and
/// the file download through the virtual work for a repository token minted
/// on it; the member the owner cannot read is absent; direct reads stay
/// refused.
#[tokio::test]
async fn virtual_scoped_token_reads_pypi_members_through_the_virtual_only_4559() {
    let Some(pool) = tdh::try_pool().await else {
        return;
    };
    let rig = Rig::new(pool).await;
    let token = rig.repo_token(&rig.pypi_virtual).await;
    let v = rig.pypi_virtual.key.clone();
    let m = rig.pypi_internal.key.clone();

    let (index_status, index) = rig.get(&token, format!("/pypi/{v}/simple/acme-lib/")).await;
    let (root_status, root) = rig.get(&token, format!("/pypi/{v}/simple/")).await;
    let (dl_status, dl) = rig
        .get(&token, format!("/pypi/{v}/simple/acme-lib/{PYPI_FILE}"))
        .await;
    let secret_index = rig
        .get(&token, format!("/pypi/{v}/simple/secret-lib/"))
        .await;
    let secret_dl = rig
        .get(
            &token,
            format!("/pypi/{v}/simple/secret-lib/{PYPI_SECRET_FILE}"),
        )
        .await
        .0;
    let direct_index = rig
        .get(&token, format!("/pypi/{m}/simple/acme-lib/"))
        .await
        .0;
    let direct_dl = rig
        .get(&token, format!("/pypi/{m}/simple/acme-lib/{PYPI_FILE}"))
        .await
        .0;
    rig.cleanup().await;

    let index = String::from_utf8_lossy(&index).into_owned();
    let root = String::from_utf8_lossy(&root).into_owned();
    assert_eq!(index_status, StatusCode::OK, "{index}");
    assert!(index.contains(PYPI_FILE), "{index}");
    assert_eq!(root_status, StatusCode::OK, "{root}");
    assert!(root.contains("acme-lib"), "{root}");
    assert!(
        !root.contains("secret-lib"),
        "the member the owner cannot read must not be enumerated: {root}"
    );
    assert_eq!(dl_status, StatusCode::OK);
    assert_eq!(&dl[..], PYPI_BYTES);
    assert!(
        !String::from_utf8_lossy(&secret_index.1).contains(PYPI_SECRET_FILE),
        "secret project through the virtual: {:?}",
        secret_index.0
    );
    assert_eq!(secret_dl, StatusCode::NOT_FOUND);
    assert_eq!(
        direct_index,
        StatusCode::NOT_FOUND,
        "direct member index stays refused"
    );
    assert_eq!(
        direct_dl,
        StatusCode::NOT_FOUND,
        "direct member download stays refused"
    );
}

/// The listing seam (`member_passes_token_scope`): `GET /members` and
/// `GET /artifacts` of the virtual list the members the owner may read and
/// nothing from the member it cannot, and the REST by-path download through
/// the virtual agrees with the listing and is recorded against the member's
/// artifact. The member's own REST endpoints stay refused.
#[tokio::test]
async fn virtual_scoped_token_lists_only_readable_members_4559() {
    let Some(pool) = tdh::try_pool().await else {
        return;
    };
    let rig = Rig::new(pool).await;
    let token = rig.repo_token(&rig.conda_virtual).await;
    let v = &rig.conda_virtual;

    let (members_status, members) = rig.member_keys(&token, v).await;
    let (artifacts_status, paths) = rig.artifact_paths(&token, v).await;
    let rest_dl = rig
        .get(
            &token,
            format!(
                "/api/v1/repositories/{}/download/noarch/{INTERNAL_PKG}",
                v.key
            ),
        )
        .await;
    // The generic route records a hosted winner off its artifact id: the
    // download is attributed to conda-internal's artifact, as for any caller.
    let downloads = tdh::download_count_eventually(&rig.pool, rig.internal_artifact, 1).await;
    let rest_secret_dl = rig
        .get(
            &token,
            format!(
                "/api/v1/repositories/{}/download/noarch/{SECRET_PKG}",
                v.key
            ),
        )
        .await
        .0;
    let direct_members = rig
        .get(
            &token,
            format!("/api/v1/repositories/{}", rig.conda_internal.key),
        )
        .await
        .0;
    let direct_artifacts = rig.artifact_paths(&token, &rig.conda_internal).await.0;
    let keys = (
        rig.conda_internal.key.clone(),
        rig.conda_forge.key.clone(),
        rig.conda_secret.key.clone(),
    );
    rig.cleanup().await;

    assert_eq!(members_status, StatusCode::OK);
    assert!(members.contains(&keys.0), "{members:?}");
    assert!(members.contains(&keys.1), "{members:?}");
    assert!(
        !members.contains(&keys.2),
        "a member the owner cannot read must not be enumerated: {members:?}"
    );
    assert_eq!(artifacts_status, StatusCode::OK);
    let internal_path = format!("noarch/{INTERNAL_PKG}");
    let secret_path = format!("noarch/{SECRET_PKG}");
    assert!(paths.contains(&internal_path), "{paths:?}");
    assert!(!paths.contains(&secret_path), "{paths:?}");
    assert_eq!(rest_dl.0, StatusCode::OK);
    assert_eq!(&rest_dl.1[..], INTERNAL_BYTES);
    assert_eq!(
        downloads, 1,
        "a download through the virtual is recorded against the member's artifact"
    );
    assert_eq!(rest_secret_dl, StatusCode::NOT_FOUND);
    assert_eq!(
        direct_members,
        StatusCode::NOT_FOUND,
        "member GET stays refused"
    );
    assert_eq!(
        direct_artifacts,
        StatusCode::NOT_FOUND,
        "member listing stays refused"
    );
}

/// Why the parent term is confined to requests routed through the virtual
/// (#4583): with an allowlist on `conda-virtual` that admits nothing from
/// remotes, the consumer token can read neither the remote member's package
/// through the virtual (the allowlist applies) nor `conda-forge` directly
/// (the token scope applies), so the allowlist cannot be bypassed. The hosted
/// member, which the allowlist does not filter, still downloads.
#[tokio::test]
async fn virtual_scoped_token_cannot_bypass_the_conda_allowlist_4559() {
    let Some(pool) = tdh::try_pool().await else {
        return;
    };
    let rig = Rig::new(pool).await;
    crate::services::conda_allowlist::save_allowlist(
        &rig.pool,
        rig.conda_virtual.id,
        &crate::services::conda_allowlist::CondaAllowlist {
            enabled: true,
            entries: vec![],
        },
    )
    .await
    .expect("save allowlist");
    let token = rig.repo_token(&rig.conda_virtual).await;
    let v = &rig.conda_virtual;

    let (repodata_status, names) = rig.repodata_names(&token, v).await;
    let via_forge = rig.conda(&token, v, FORGE_PKG).await.0;
    let via_internal = rig.conda(&token, v, INTERNAL_PKG).await.0;
    let direct_forge = rig.conda(&token, &rig.conda_forge, FORGE_PKG).await.0;
    let _ =
        crate::services::conda_allowlist::delete_allowlist(&rig.pool, rig.conda_virtual.id).await;
    rig.cleanup().await;

    assert_eq!(repodata_status, StatusCode::OK);
    assert_eq!(
        names,
        vec![INTERNAL_PKG.to_string()],
        "the allowlist drops the remote record"
    );
    assert_eq!(
        via_forge,
        StatusCode::NOT_FOUND,
        "the allowlist refuses the remote download"
    );
    assert_eq!(
        via_internal,
        StatusCode::OK,
        "hosted members are not filtered"
    );
    assert_eq!(
        direct_forge,
        StatusCode::NOT_FOUND,
        "the virtual-scoped token cannot route around the allowlist via the member URL"
    );
}
