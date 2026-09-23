use super::*;
use crate::api::handlers::{repositories, test_db_helpers as tdh};
use axum::http::Request;
use flate2::read::GzDecoder;
use std::io::Read;

const RPM: &str = "pkg-1.2.3-1.noarch.rpm";

fn app(f: &tdh::Fixture) -> Router {
    tdh::router_with_auth_ext(
        Router::new()
            .nest("/rpm", super::router())
            .nest("/api/v1/repositories", repositories::router())
            .nest("/api/v1/uploads", crate::api::handlers::upload::router()),
        f.state.clone(),
        tdh::admin_auth(f.user_id, &f.username),
    )
}

async fn request(
    f: &tdh::Fixture,
    method: &str,
    path: &str,
    content_type: &str,
    body: impl Into<Body>,
) -> (StatusCode, Bytes) {
    tdh::send(
        app(f),
        Request::builder()
            .method(method)
            .uri(path)
            .header(CONTENT_TYPE, content_type)
            .body(body.into())
            .unwrap(),
    )
    .await
}

async fn get(f: &tdh::Fixture, path: &str) -> (StatusCode, Bytes) {
    request(f, "GET", path, "application/octet-stream", Body::empty()).await
}

fn text(bytes: &[u8]) -> String {
    let mut xml = String::new();
    GzDecoder::new(bytes).read_to_string(&mut xml).unwrap();
    xml
}

async fn depth(f: &tdh::Fixture, value: u32, expected: StatusCode) -> serde_json::Value {
    let (status, bytes) = request(
        f,
        "PATCH",
        &format!("/api/v1/repositories/{}", f.repo_key),
        "application/json",
        format!(r#"{{"repodata_depth":{value}}}"#),
    )
    .await;
    assert_eq!(status, expected, "{}", String::from_utf8_lossy(&bytes));
    serde_json::from_slice(&bytes).unwrap()
}

async fn upload(f: &tdh::Fixture, path: &str, content: &'static str) {
    let (status, body) = request(
        f,
        "PUT",
        &format!("/rpm/{}/{}", f.repo_key, rpm_layout::location_href(path)),
        "application/x-rpm",
        content,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn roots_isolate_identical_nevra_bytes_and_all_metadata_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    let configured = depth(&f, 1, StatusCode::OK).await;
    assert_eq!(configured["repodata_depth"], 1);
    assert_eq!(configured["repodata_depth_editable"], true);
    let mut events = f.state.event_bus.subscribe();
    let base = format!("/rpm/{}", f.repo_key);
    for endpoint in [
        "repomd.xml",
        "primary.xml.gz",
        "filelists.xml.gz",
        "other.xml.gz",
        "updateinfo.xml.gz",
    ] {
        assert_eq!(
            get(&f, &format!("{base}/repodata/{endpoint}")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&f, &format!("{base}/empty/repodata/{endpoint}"))
                .await
                .0,
            StatusCode::OK
        );
    }
    for (path, content) in [
        (format!("a/{RPM}"), "root-a"),
        (format!("b/{RPM}"), "root-b"),
        ("a/nested/extra-1-1.noarch.rpm".to_string(), "descendant"),
        (format!("a-other/{RPM}"), "boundary"),
        (format!("packages/{RPM}"), "reserved-route"),
        (format!("upload/{RPM}"), "upload-route"),
        ("a &%_/special &%?#-1-1.noarch.rpm".to_string(), "escaped"),
    ] {
        upload(&f, &path, content).await;
        let (status, bytes) =
            get(&f, &format!("{base}/{}", rpm_layout::location_href(&path))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, content.as_bytes());
    }
    let published = std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| event.event_type == "artifact.uploaded")
        .count();
    assert_eq!(
        published, 7,
        "each native upload emits exactly one publish event"
    );
    let (status, a) = get(&f, &format!("{base}/a/repodata/primary.xml.gz")).await;
    assert_eq!(status, StatusCode::OK);
    let primary = text(&a);
    assert!(primary.contains("packages=\"2\""));
    assert!(primary.contains(&format!("href=\"{RPM}\"")));
    assert!(primary.contains("href=\"nested/extra-1-1.noarch.rpm\""));
    assert!(primary.contains(&sha256_hex(b"root-a")));
    assert!(!primary.contains(&sha256_hex(b"root-b")));
    assert!(!primary.contains(&sha256_hex(b"boundary")));
    let (_, b) = get(&f, &format!("{base}/b/repodata/primary.xml.gz")).await;
    assert!(text(&b).contains("packages=\"1\""));
    assert!(text(&b).contains(&sha256_hex(b"root-b")));
    for path in [
        RPM.to_string(),
        format!("missing/{RPM}"),
        "a/nested/repodata/repomd.xml".into(),
        "@1/repodata/repomd.xml".into(),
    ] {
        assert_eq!(
            get(&f, &format!("{base}/{path}")).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let (_, special) = get(&f, &format!("{base}/a%20%26%25_/repodata/primary.xml.gz")).await;
    assert!(text(&special).contains("special%20%26%25%3F%23-1-1.noarch.rpm"));
    let (_, before) = get(&f, &format!("{base}/a/repodata/repomd.xml")).await;
    let (_, again) = get(&f, &format!("{base}/a/repodata/repomd.xml")).await;
    assert_eq!(before, again);
    let (_, sibling) = get(&f, &format!("{base}/b/repodata/repomd.xml")).await;
    let (status, body) = request(
        &f,
        "DELETE",
        &format!("/api/v1/repositories/{}/artifacts/a/{RPM}", f.repo_key),
        "application/json",
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let (_, after) = get(&f, &format!("{base}/a/repodata/repomd.xml")).await;
    assert_ne!(before, after);
    assert_eq!(
        get(&f, &format!("{base}/b/repodata/repomd.xml")).await.1,
        sibling
    );
    sqlx::query("UPDATE artifacts SET is_deleted = false WHERE repository_id=$1 AND path=$2")
        .bind(f.repo_id)
        .bind(format!("a/{RPM}"))
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(get(&f, &format!("{base}/a/{RPM}")).await.1, "root-a");
    let (_, restored) = get(&f, &format!("{base}/a/repodata/repomd.xml")).await;
    assert_ne!(after, restored);
    sqlx::query("UPDATE artifact_metadata SET metadata = metadata || '{\"summary\":\"enriched after upload\"}'::jsonb \
        WHERE artifact_id=(SELECT id FROM artifacts WHERE repository_id=$1 AND path=$2)")
        .bind(f.repo_id).bind(format!("a/{RPM}")).execute(&f.pool).await.unwrap();
    let (_, enriched) = get(&f, &format!("{base}/a/repodata/primary.xml.gz")).await;
    assert!(text(&enriched).contains("enriched after upload"));
    assert_eq!(
        get(&f, &format!("{base}/b/repodata/repomd.xml")).await.1,
        sibling
    );
    let populated = depth(&f, 1, StatusCode::OK).await;
    assert_eq!(populated["repodata_depth_editable"], false);
    assert_eq!(depth(&f, 2, StatusCode::CONFLICT).await["code"], "CONFLICT");
    f.teardown().await;
}

#[tokio::test]
async fn depth_two_rejects_shallow_native_generic_multipart_and_chunked_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    depth(&f, 2, StatusCode::OK).await;
    let base = format!("/api/v1/repositories/{}/artifacts", f.repo_key);
    let native = format!("/rpm/{}", f.repo_key);
    for path in [RPM.to_string(), format!("el9/{RPM}")] {
        for url in [format!("{native}/{path}"), format!("{base}/{path}")] {
            let (status, bytes) = request(&f, "PUT", &url, "application/x-rpm", "shallow").await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{url}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }
    let path = format!("el9/x86_64/deeper/{RPM}");
    let multipart = |path: &str| {
        format!(
        "--rpm-depth\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{path}\r\n--rpm-depth\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{RPM}\"\r\nContent-Type: application/x-rpm\r\n\r\nmultipart\r\n--rpm-depth--\r\n"
    )
    };
    for (path, expected) in [
        (RPM, StatusCode::BAD_REQUEST),
        (path.as_str(), StatusCode::CREATED),
    ] {
        let (status, bytes) = request(
            &f,
            "POST",
            &base,
            "multipart/form-data; boundary=rpm-depth",
            multipart(path),
        )
        .await;
        assert_eq!(status, expected, "{}", String::from_utf8_lossy(&bytes));
    }
    let (status, bytes) = request(&f, "POST", "/api/v1/uploads", "application/json",
        serde_json::json!({"repository_key":f.repo_key,"artifact_path":RPM,"total_size":4,"checksum_sha256":sha256_hex(b"test"),"content_type":"application/x-rpm"}).to_string()).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let (status, primary) = get(&f, &format!("{native}/el9/x86_64/repodata/primary.xml.gz")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(text(&primary).contains(&format!("href=\"deeper/{RPM}\"")));
    for root in ["", "el9", "el9/x86_64/deeper"] {
        let url = if root.is_empty() {
            format!("{native}/repodata/repomd.xml")
        } else {
            format!("{native}/{root}/repodata/repomd.xml")
        };
        assert_eq!(get(&f, &url).await.0, StatusCode::NOT_FOUND);
    }
    let post = Request::builder()
        .method("POST")
        .uri(format!("{native}/upload"))
        .header("X-Package-Filename", format!("el9/aarch64/{RPM}"))
        .body(Body::from("post"))
        .unwrap();
    assert_eq!(tdh::send(app(&f), post).await.0, StatusCode::CREATED);
    assert_eq!(
        get(&f, &format!("{native}/el9/aarch64/{RPM}")).await.1,
        "post"
    );
    f.teardown().await;
}

#[test]
fn repository_openapi_describes_depth_contract_4216() {
    use utoipa::OpenApi;
    let document =
        serde_json::to_value(super::super::repositories::RepositoriesApiDoc::openapi()).unwrap();
    let schemas = &document["components"]["schemas"];
    for name in ["CreateRepositoryRequest", "UpdateRepositoryRequest"] {
        let schema = &schemas[name];
        let field = &schema["properties"]["repodata_depth"];
        assert_eq!(field["type"], "integer");
        assert_eq!(field["minimum"].as_f64(), Some(0.0));
        assert_eq!(field["maximum"].as_f64(), Some(1023.0));
        assert_ne!(field["nullable"], true);
        assert!(!schema["required"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|name| name == "repodata_depth"));
    }
    let required = schemas["RepositoryResponse"]["required"]
        .as_array()
        .unwrap();
    for field in ["repodata_depth", "repodata_depth_editable"] {
        assert!(required.iter().any(|name| name == field));
    }
    assert_eq!(
        document["paths"]["/api/v1/repositories/_/capabilities"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/RepositoryCapabilities"
    );
    assert_eq!(
        schemas["RepositoryCapabilities"]["properties"]["rpm_repodata_depth"]["$ref"],
        "#/components/schemas/RpmRepodataDepthCapability"
    );
    for field in ["supported", "min", "max", "default"] {
        assert!(schemas["RpmRepodataDepthCapability"]["properties"]
            .get(field)
            .is_some());
    }
    for (path, method) in [
        ("/api/v1/repositories", "post"),
        ("/api/v1/repositories/{key}", "patch"),
    ] {
        for status in ["400", "409", "422"] {
            assert!(document["paths"][path][method]["responses"]
                .get(status)
                .is_some());
        }
    }
}

#[tokio::test]
async fn positive_detection_and_configuration_responses_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    let (_, bytes) = get(&f, "/api/v1/repositories/_/capabilities").await;
    let capability: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        capability["rpm_repodata_depth"],
        serde_json::json!({"supported":true,"min":0,"max":1023,"default":0})
    );
    let url = format!("/api/v1/repositories/{}", f.repo_key);
    for value in ["null", "-1", "1.1", "1024", "\"1\""] {
        assert_eq!(
            request(
                &f,
                "PATCH",
                &url,
                "application/json",
                format!(r#"{{"repodata_depth":{value}}}"#)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    depth(&f, 1, StatusCode::OK).await;
    let (_, bytes) = get(&f, &format!("/api/v1/repositories?q={}", f.repo_key)).await;
    let listing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(listing["items"][0]["repodata_depth"], 1);
    assert_eq!(listing["items"][0]["repodata_depth_editable"], true);
    let (_, bytes) = get(&f, &url).await;
    let detail: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(detail["repodata_depth"], 1);
    let (status, _) = request(
        &f,
        "PATCH",
        &url,
        "application/json",
        r#"{"name":"still-scoped"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rpm_layout::depth(&f.pool, f.repo_id).await.unwrap(), 1);
    let (_, bytes) = request(
        &f,
        "PATCH",
        &url,
        "application/json",
        r#"{"curation_enabled":true}"#,
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
        "UNPROCESSABLE_ENTITY"
    );
    f.teardown().await;
}

#[tokio::test]
async fn each_root_signature_verifies_only_its_own_cached_manifest_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    depth(&f, 1, StatusCode::OK).await;
    super::tests::attach_signing_key(&f, "gpg").await;
    upload(&f, &format!("a/{RPM}"), "a").await;
    upload(&f, &format!("b/{RPM}"), "b").await;
    let base = format!("/rpm/{}", f.repo_key);
    let (_, a) = get(&f, &format!("{base}/a/repodata/repomd.xml")).await;
    let (_, b) = get(&f, &format!("{base}/b/repodata/repomd.xml")).await;
    let (status, signature) = get(&f, &format!("{base}/a/repodata/repomd.xml.asc")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, key) = get(&f, &format!("{base}/a/repodata/repomd.xml.key")).await;
    assert_eq!(status, StatusCode::OK);
    let signature = String::from_utf8(signature.to_vec()).unwrap();
    let key = String::from_utf8(key.to_vec()).unwrap();
    crate::services::signing_service::verify_detached(&key, &a, &signature).unwrap();
    assert!(crate::services::signing_service::verify_detached(&key, &b, &signature).is_err());
    for file in ["repomd.xml.asc", "repomd.xml.key"] {
        assert_eq!(
            get(&f, &format!("{base}/repodata/{file}")).await.0,
            StatusCode::NOT_FOUND
        );
    }
    f.teardown().await;
}

#[tokio::test]
async fn chunk_completion_keeps_full_path_and_rechecks_layout_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    depth(&f, 1, StatusCode::OK).await;
    for (path, change_depth, expected) in [
        (format!("a/{RPM}"), true, StatusCode::BAD_REQUEST),
        (format!("el9/x86_64/{RPM}"), false, StatusCode::OK),
    ] {
        let payload = "chunked";
        let (status, body) = request(
            &f,
            "POST",
            "/api/v1/uploads",
            "application/json",
            serde_json::json!({"repository_key":f.repo_key, "artifact_path":path,
                "total_size":payload.len(), "checksum_sha256":sha256_hex(payload.as_bytes())})
            .to_string(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session = created["session_id"].as_str().unwrap();
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/uploads/{session}"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(
                "content-range",
                format!("bytes 0-{}/{}", payload.len() - 1, payload.len()),
            )
            .body(Body::from(payload))
            .unwrap();
        assert_eq!(tdh::send(app(&f), req).await.0, StatusCode::OK);
        if change_depth {
            depth(&f, 2, StatusCode::OK).await;
        }
        let (status, body) = request(
            &f,
            "PUT",
            &format!("/api/v1/uploads/{session}/complete"),
            "application/json",
            Body::empty(),
        )
        .await;
        assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
        let (status, bytes) = get(&f, &format!("/rpm/{}/{}", f.repo_key, path)).await;
        if expected == StatusCode::OK {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(bytes, payload);
        } else {
            assert_eq!(status, StatusCode::NOT_FOUND);
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE repository_id=$1")
                    .bind(f.repo_id)
                    .fetch_one(&f.pool)
                    .await
                    .unwrap();
            assert_eq!(count, 0);
        }
    }
    f.teardown().await;
}

#[tokio::test]
async fn held_configuration_lock_returns_conflict_without_partial_artifacts_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    depth(&f, 1, StatusCode::OK).await;
    let mut config = f.pool.begin().await.unwrap();
    rpm_layout::set_depth(&mut config, f.repo_id, 2)
        .await
        .unwrap();
    for url in [
        format!("/rpm/{}/a/b/{RPM}", f.repo_key),
        format!("/api/v1/repositories/{}/artifacts/a/b/{RPM}", f.repo_key),
    ] {
        let (status, body) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            request(&f, "PUT", &url, "application/x-rpm", "held-lock"),
        )
        .await
        .unwrap();
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{}",
            String::from_utf8_lossy(&body)
        );
    }
    config.commit().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE repository_id=$1")
        .bind(f.repo_id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    f.teardown().await;
}

#[tokio::test]
async fn create_contract_permissions_and_unsupported_settings_are_atomic_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    for (format, kind, expected) in [
        ("rpm", "hosted", StatusCode::OK),
        ("generic", "local", StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let key = format!("depth-{}", uuid::Uuid::new_v4().simple());
        let (status, body) = request(&f, "POST",         "/api/v1/repositories", "application/json",
            serde_json::json!({"key":key,"name":key,"format":format,"repo_type":kind,"repodata_depth":2}).to_string()).await;
        assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
        let row: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT id FROM repositories WHERE key=$1")
                .bind(&key)
                .fetch_optional(&f.pool)
                .await
                .unwrap();
        if expected == StatusCode::OK {
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["repodata_depth"], 2);
            assert_eq!(body["repodata_depth_editable"], true);
            assert_eq!(body["repo_type"], "local");
            sqlx::query("DELETE FROM repositories WHERE id=$1")
                .bind(row.unwrap())
                .execute(&f.pool)
                .await
                .unwrap();
        } else {
            assert!(
                row.is_none(),
                "unsupported create must not leave a repository"
            );
        }
    }
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}", f.repo_key))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"repodata_depth":1}"#))
        .unwrap();
    assert_eq!(
        tdh::send(f.router_with_auth(repositories::router()), req)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(rpm_layout::depth(&f.pool, f.repo_id).await.unwrap(), 0);
    depth(&f, 1, StatusCode::OK).await;
    let (status, body) = request(
        &f,
        "PATCH",
        &format!("/api/v1/repositories/{}", f.repo_key),
        "application/json",
        r#"{"curation_enabled":true,"name":"must-roll-back"}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (name, curated): (String, bool) =
        sqlx::query_as("SELECT name,curation_enabled FROM repositories WHERE id=$1")
            .bind(f.repo_id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_ne!(name, "must-roll-back");
    assert!(!curated);
    f.teardown().await;
}

#[tokio::test]
async fn production_router_loopback_http_contract_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    sqlx::query("UPDATE users SET is_admin=true,must_change_password=false WHERE id=$1")
        .bind(f.user_id)
        .execute(&f.pool)
        .await
        .unwrap();
    let auth = tdh::bearer_for(&f.state, f.user_id).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let router = crate::api::routes::create_router(f.state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let capability = client
        .get(format!("{base}/api/v1/repositories/_/capabilities"))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(capability.status(), StatusCode::OK);
    assert_eq!(
        capability.json::<serde_json::Value>().await.unwrap()["rpm_repodata_depth"]["supported"],
        true
    );
    let saved = client
        .patch(format!("{base}/api/v1/repositories/{}", f.repo_key))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"repodata_depth":1}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        saved.status(),
        StatusCode::OK,
        "{}",
        saved.text().await.unwrap()
    );
    let path = format!("{base}/rpm/{}/build-a/{RPM}", f.repo_key);
    let uploaded = client
        .put(&path)
        .header("Authorization", &auth)
        .body("over TCP")
        .send()
        .await
        .unwrap();
    assert_eq!(
        uploaded.status(),
        StatusCode::CREATED,
        "{}",
        uploaded.text().await.unwrap()
    );
    let downloaded = client
        .get(&path)
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(downloaded.text().await.unwrap(), "over TCP");
    let metadata = client
        .get(format!(
            "{base}/rpm/{}/build-a/repodata/repomd.xml",
            f.repo_key
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    assert!(metadata
        .text()
        .await
        .unwrap()
        .contains("repodata/primary.xml.gz"));

    // Optional task-local browser smoke: no production main, scheduler, or gRPC.
    if let Ok(info_path) = std::env::var("AK_RPM_DEPTH_LIVE_INFO") {
        use std::io::Write as _;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let info_path = std::path::PathBuf::from(info_path);
        let stop_path = info_path.with_extension("stop");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut info = options.open(&info_path).unwrap();
        info.write_all(
            &serde_json::to_vec_pretty(&serde_json::json!({
                "base_url":base, "authorization":auth, "repository_key":f.repo_key,
                "repository_id":f.repo_id, "user_id":f.user_id, "username":f.username,
            }))
            .unwrap(),
        )
        .unwrap();
        drop(info);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
        while tokio::time::Instant::now() < deadline && !stop_path.exists() {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        std::fs::remove_file(info_path).unwrap();
        if stop_path.exists() {
            std::fs::remove_file(stop_path).unwrap();
        }
    }
    stop.send(()).unwrap();
    server.await.unwrap();
    f.teardown().await;
}
