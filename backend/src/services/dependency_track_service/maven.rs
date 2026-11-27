//! Maven-only Dependency-Track policy and collection provisioning.
//!
//! API contract verified against /api/openapi.json from the official 4.14.0
//! executable (GET /project/lookup, PUT /project, GET and PATCH /project/{uuid}).
//! PATCH sends parent and unchanged state flags, never a serialized GET response.

use super::*;
use crate::formats::maven::{MavenCoordinates, MavenHandler};
use crate::services::cluster_lock::{lease_object_id, ClusterLock, PgAdvisoryLock};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, Semaphore};
use uuid::Uuid;

const DIRECT_CHILDREN: &str = "AGGREGATE_DIRECT_CHILDREN";
const DT_PROJECT_NAME_LIMIT: usize = 255;

const MAVEN_PROVISIONING_TIMEOUT: Duration = Duration::from_secs(30);
const MAVEN_PROVISIONING_LOCK_CLASS: i32 = 0x4454_4d56; // "DTMV"
const MAX_MAVEN_LOCK_SESSIONS: usize = 4;

#[derive(Debug)]
pub(super) struct MavenProvisioning {
    in_flight: std::sync::Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
    sessions: Semaphore,
}

impl Default for MavenProvisioning {
    fn default() -> Self {
        Self {
            in_flight: Default::default(),
            sessions: Semaphore::new(MAX_MAVEN_LOCK_SESSIONS),
        }
    }
}

impl MavenProvisioning {
    async fn lock(&self, name: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            in_flight.retain(|_, lock| lock.strong_count() != 0);
            match in_flight.get(name).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    in_flight.insert(name.to_owned(), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }
}

fn project_name(repository_id: Uuid, coordinates: &MavenCoordinates) -> String {
    let identity = format!(
        "{}:{}",
        urlencoding::encode(&coordinates.group_id),
        urlencoding::encode(&coordinates.artifact_id),
    );
    let name = format!("{identity} [{repository_id}]");
    if name.len() <= DT_PROJECT_NAME_LIMIT {
        return name;
    }
    // The extra colon distinguishes a hashed identity from a literal group:artifact.
    let digest = Sha256::digest(identity.as_bytes());
    format!("maven:sha256:{digest:x} [{repository_id}]")
}

impl DependencyTrackService {
    /// Sidecars have their own upload handling and are not classifier artifacts.
    /// In particular, don't parse `sources.jar.asc` as classifier `sources.jar`.
    pub fn maven_coordinates(&self, format: Option<&str>, path: &str) -> Option<MavenCoordinates> {
        if format != Some("maven")
            || MavenHandler::is_metadata(path)
            || [".asc", ".md5", ".sha1", ".sha256", ".sha512"]
                .iter()
                .any(|suffix| path.ends_with(suffix))
        {
            return None;
        }
        MavenHandler::parse_coordinates(path).ok()
    }

    pub fn excludes_maven_classifier(&self, coordinates: &MavenCoordinates) -> bool {
        coordinates.classifier.as_ref().is_some_and(|classifier| {
            self.config
                .maven_excluded_classifiers
                .contains(&classifier.to_lowercase())
        })
    }

    pub fn auto_collections(&self) -> bool {
        self.config.auto_collections
    }

    pub async fn get_or_create_maven_project(
        &self,
        db: &sqlx::PgPool,
        repository_id: Uuid,
        coordinates: &MavenCoordinates,
        description: &str,
    ) -> Result<DtProject> {
        if self.excludes_maven_classifier(coordinates) {
            return Err(AppError::Validation("Excluded Maven classifier".into()));
        }
        let name = project_name(repository_id, coordinates);
        tokio::time::timeout(MAVEN_PROVISIONING_TIMEOUT, async {
            // Established projects only need an exact read; the session lock
            // covers changes to the hierarchy across replicas.
            let version = Some(coordinates.version.as_str());
            if let Some(child) = self.find_maven_project(&name, version, coordinates).await? {
                if child.parent.is_some() {
                    return Ok(child);
                }
            }

            let _local = self.maven_provisioning.lock(&name).await;
            let _session_slot = self
                .maven_provisioning
                .sessions
                .acquire()
                .await
                .expect("semaphore is never closed");
            // DT checks name/version before inserting, but concurrent creates
            // can still both succeed. Use a dedicated PostgreSQL session with
            // no open transaction or checked-out request-pool connection.
            let lease = PgAdvisoryLock::new(db.clone())
                .acquire_blocking(
                    MAVEN_PROVISIONING_LOCK_CLASS,
                    lease_object_id(&name),
                    MAVEN_PROVISIONING_TIMEOUT,
                )
                .await?
                .ok_or_else(|| maven_provisioning_timeout(&name))?;
            let result = self
                .provision_maven_project(&name, coordinates, description)
                .await;
            lease.release().await;
            result
        })
        .await
        .map_err(|_| maven_provisioning_timeout(&name))?
    }

    async fn provision_maven_project(
        &self,
        name: &str,
        coordinates: &MavenCoordinates,
        description: &str,
    ) -> Result<DtProject> {
        let version = Some(coordinates.version.as_str());
        let child = self.find_maven_project(name, version, coordinates).await?;
        if let Some(child) = child.as_ref().filter(|child| child.parent.is_some()) {
            return Ok(child.clone());
        }

        let parent = match self.find_maven_project(name, None, coordinates).await? {
            Some(parent) => parent,
            None => {
                let parent = self
                    .create_maven_project(&CreateProjectRequest {
                        name: name.to_owned(),
                        version: None,
                        description: Some(description.into()),
                        group: Some(coordinates.group_id.clone()),
                        purl: Some(maven_purl(coordinates, false)),
                        parent: None,
                        collection_logic: Some(DIRECT_CHILDREN.into()),
                    })
                    .await?;
                validate_maven_project(&parent, name, None, coordinates)?;
                info!(collection_uuid = %parent.uuid, maven_identity = %name,
                    "Provisioned Dependency-Track Maven collection");
                parent
            }
        };

        let child = match child {
            Some(child) => child,
            None => {
                let child = self
                    .create_maven_project(&CreateProjectRequest {
                        name: name.to_owned(),
                        version: Some(coordinates.version.clone()),
                        description: Some(description.into()),
                        group: Some(coordinates.group_id.clone()),
                        purl: Some(maven_purl(coordinates, true)),
                        parent: Some(DtProjectParent {
                            uuid: parent.uuid.clone(),
                        }),
                        collection_logic: None,
                    })
                    .await?;
                validate_maven_project(&child, name, version, coordinates)?;
                child
            }
        };
        if child.parent.as_ref().is_some_and(|p| p.uuid == parent.uuid) {
            return Ok(child);
        }
        self.attach_maven_parent(child, &parent, coordinates).await
    }

    async fn find_maven_project(
        &self,
        name: &str,
        version: Option<&str>,
        coordinates: &MavenCoordinates,
    ) -> Result<Option<DtProject>> {
        let Some(summary) = self.find_project(name, version).await? else {
            return Ok(None);
        };
        // Read details before relying on the parent relationship or flags.
        let project = self.maven_project_details(&summary.uuid).await?;
        validate_maven_project(&project, name, version, coordinates)?;
        Ok(Some(project))
    }

    async fn maven_project_details(&self, uuid: &str) -> Result<DtProject> {
        let endpoint = format!(
            "{}/api/v1/project/{}",
            self.config.base_url,
            urlencoding::encode(uuid)
        );
        let response = self
            .client
            .get(&endpoint)
            .header("X-Api-Key", self.api_key()?)
            .send()
            .await
            .map_err(|e| dt_transport_err("Maven project details", e))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(dt_upstream_status_err(
                "Maven project details",
                &endpoint,
                status,
                &body,
            ));
        }
        response
            .json()
            .await
            .map_err(|e| dt_upstream_parse_err("Maven project details", e))
    }

    async fn create_maven_project(&self, request: &CreateProjectRequest) -> Result<DtProject> {
        let endpoint = format!("{}/api/v1/project", self.config.base_url);
        let response = self
            .client
            .put(&endpoint)
            .header("X-Api-Key", self.api_key()?)
            .json(request)
            .send()
            .await
            .map_err(|e| dt_transport_err("Maven project creation", e))?;
        if response.status() == StatusCode::CONFLICT {
            // Another creator may have won the name/version race.
            // Retry reads only; never turn a permission failure into a create.
            for attempt in 0..3 {
                if let Some(project) = self
                    .find_project(&request.name, request.version.as_deref())
                    .await?
                {
                    return self.maven_project_details(&project.uuid).await;
                }
                tokio::time::sleep(Duration::from_millis(50 * (attempt + 1))).await;
            }
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(dt_upstream_status_err(
                "Maven project creation",
                &endpoint,
                status,
                &body,
            ));
        }
        response
            .json()
            .await
            .map_err(|e| dt_upstream_parse_err("Maven project creation", e))
    }

    async fn attach_maven_parent(
        &self,
        child: DtProject,
        parent: &DtProject,
        coordinates: &MavenCoordinates,
    ) -> Result<DtProject> {
        // Re-read before assignment, including after a concurrent create conflict.
        let mut child = self.maven_project_details(&child.uuid).await?;
        validate_maven_project(
            &child,
            &parent.name,
            Some(&coordinates.version),
            coordinates,
        )?;
        if let Some(existing) = child.parent.as_ref() {
            if existing.uuid != parent.uuid {
                warn!(project_uuid = %child.uuid, parent_uuid = %existing.uuid,
                    expected_parent_uuid = %parent.uuid, "Preserving different existing Dependency-Track parent");
            }
            return Ok(child);
        }
        let mut seen = HashSet::from([child.uuid.clone()]);
        let mut ancestor = parent.clone();
        loop {
            if !seen.insert(ancestor.uuid.clone()) {
                return Err(AppError::Validation(format!(
                    "Dependency-Track Maven project {} has a cyclic parent relationship",
                    child.name,
                )));
            }
            let Some(next) = ancestor.parent else { break };
            ancestor = self.maven_project_details(&next.uuid).await?;
        }
        // DT 4.14 deserializes PATCH into Project with primitive defaults:
        // active=true, isLatest=false, collectionLogic=NONE. Omitting these
        // would silently reactivate an inactive child or clear its latest flag.
        let (Some(active), Some(is_latest)) = (child.active, child.is_latest) else {
            return Err(AppError::BadGateway(
                "Dependency-Track full project response omitted active/isLatest; refusing parent update".into(),
            ));
        };
        let endpoint = format!(
            "{}/api/v1/project/{}",
            self.config.base_url,
            urlencoding::encode(&child.uuid)
        );
        let response = self
            .client
            .patch(&endpoint)
            .header("X-Api-Key", self.api_key()?)
            .json(&serde_json::json!({
                "parent": {"uuid": parent.uuid},
                "active": active,
                "isLatest": is_latest,
                "collectionLogic": child.collection_logic.as_deref().unwrap_or("NONE"),
            }))
            .send()
            .await
            .map_err(|e| dt_transport_err("Maven parent assignment", e))?;
        if !response.status().is_success() && response.status() != StatusCode::NOT_MODIFIED {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(dt_upstream_status_err(
                "Maven parent assignment",
                &endpoint,
                status,
                &body,
            ));
        }
        info!(project_uuid = %child.uuid, collection_uuid = %parent.uuid,
            "Assigned Dependency-Track Maven collection parent");
        child.parent = Some(DtProjectParent {
            uuid: parent.uuid.clone(),
        });
        Ok(child)
    }
}

fn maven_provisioning_timeout(name: &str) -> AppError {
    AppError::ServiceUnavailable(format!(
        "Dependency-Track Maven provisioning timed out for {name}"
    ))
}

fn validate_maven_project(
    project: &DtProject,
    name: &str,
    version: Option<&str>,
    coordinates: &MavenCoordinates,
) -> Result<()> {
    let valid_collection_logic = match version {
        None => project.collection_logic.as_deref() == Some(DIRECT_CHILDREN),
        Some(_) => matches!(project.collection_logic.as_deref(), None | Some("NONE")),
    };
    if project.name != name
        || project.version.as_deref() != version
        || !valid_collection_logic
        || project
            .group
            .as_deref()
            .is_some_and(|group| group != coordinates.group_id)
        || (project.purl.is_some() && !purl_matches(project, coordinates))
    {
        return Err(AppError::Validation(format!(
            "Dependency-Track project {} conflicts with scoped Maven identity {name} (version {version:?})",
            project.uuid,
        )));
    }
    Ok(())
}

fn purl_matches(project: &DtProject, coordinates: &MavenCoordinates) -> bool {
    let Some(purl) = project
        .purl
        .as_deref()
        .and_then(|p| p.strip_prefix("pkg:maven/"))
    else {
        return false;
    };
    let path = purl.split(['@', '?', '#']).next().unwrap_or_default();
    let Some((group, artifact)) = path.rsplit_once('/') else {
        return false;
    };
    urlencoding::decode(group).is_ok_and(|g| g == coordinates.group_id)
        && urlencoding::decode(artifact).is_ok_and(|a| a == coordinates.artifact_id)
}

fn maven_purl(coordinates: &MavenCoordinates, versioned: bool) -> String {
    let mut purl = format!(
        "pkg:maven/{}/{}",
        urlencoding::encode(&coordinates.group_id),
        urlencoding::encode(&coordinates.artifact_id)
    );
    if versioned {
        purl.push('@');
        purl.push_str(&urlencoding::encode(&coordinates.version));
    }
    purl
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const REPOSITORY: Uuid = Uuid::from_u128(1);
    const SCOPED_NAME: &str = "ru.molnet:core [00000000-0000-0000-0000-000000000001]";

    async fn provision(
        svc: &DependencyTrackService,
        coordinates: &MavenCoordinates,
    ) -> Result<DtProject> {
        let name = project_name(REPOSITORY, coordinates);
        let _guard = svc.maven_provisioning.lock(&name).await;
        svc.provision_maven_project(&name, coordinates, "repo")
            .await
    }

    fn service(url: &str, collections: bool, csv: &str) -> DependencyTrackService {
        DependencyTrackService {
            client: Client::new(),
            config: DependencyTrackConfig {
                base_url: url.into(),
                api_key: Some("test-key".into()),
                api_key_file: None,
                enabled: true,
                auto_collections: collections,
                maven_excluded_classifiers: DependencyTrackConfig::parse_excluded_classifiers(csv),
            },
            page_size: DT_PAGE_SIZE,
            cached_file_key: std::sync::Mutex::new(CachedFileKey::default()),
            maven_provisioning: Default::default(),
        }
    }

    fn coordinates(version: &str) -> MavenCoordinates {
        MavenHandler::parse_coordinates(&format!("ru/molnet/core/{version}/core-{version}.jar"))
            .unwrap()
    }

    #[test]
    fn long_project_names_fit_dependency_tracks_limit() {
        let mut c = coordinates("1.0");
        c.group_id = "g".repeat(220);
        let name = project_name(REPOSITORY, &c);
        assert!(name.len() <= DT_PROJECT_NAME_LIMIT);
        assert!(name.starts_with("maven:sha256:"));
        c.version = "2.0".into();
        assert_eq!(project_name(REPOSITORY, &c), name);
        c.artifact_id = "other".into();
        assert_ne!(project_name(REPOSITORY, &c), name);
    }

    #[test]
    fn csv_normalization_and_independent_switches() {
        assert!(DependencyTrackConfig::parse_excluded_classifiers(" , , ").is_empty());
        assert!(DependencyTrackConfig::parse_excluded_classifiers("").is_empty());
        let csv = " Javadoc, sources ,SOURCES,,tests,test-sources, Test-Javadoc ";
        let parsed = DependencyTrackConfig::parse_excluded_classifiers(csv);
        assert_eq!(parsed.len(), 5);
        assert!(parsed.contains("test-sources"));
        for collections in [false, true] {
            for (suffix, excluded) in [
                (".jar", false),
                (".pom", false),
                (".war", false),
                ("-JAVADOC.jar", true),
                ("-sources.jar", true),
                ("-tests.jar", true),
                ("-test-sources.jar", true),
                ("-test-javadoc.jar", true),
                ("-linux-x86_64.jar", false),
                ("-sources-extra.jar", false),
            ] {
                let svc = service("http://localhost", collections, csv);
                let path = format!("g/core/1.0/core-1.0{suffix}");
                let c = svc.maven_coordinates(Some("maven"), &path).unwrap();
                assert_eq!(svc.excludes_maven_classifier(&c), excluded, "{path}");
                let disabled = service("http://localhost", collections, "");
                assert!(!disabled.excludes_maven_classifier(&c));
            }
        }
    }

    #[test]
    fn classifier_coordinates_and_sidecars() {
        let svc = service("http://localhost", true, "sources,tests,javadoc");
        for artifact in ["core-sources", "core-tests", "core-javadoc"] {
            let c = svc
                .maven_coordinates(
                    Some("maven"),
                    &format!("g/{artifact}/1.0/{artifact}-1.0.jar"),
                )
                .unwrap();
            assert!(c.classifier.is_none());
            assert!(!svc.excludes_maven_classifier(&c));
        }
        for (filename, excluded) in [
            ("core-1.0-SNAPSHOT.jar", false),
            ("core-1.0-SNAPSHOT-sources.jar", true),
            ("core-1.0-20261031.123456-12.jar", false),
            ("core-1.0-20261031.123456-12-sources.jar", true),
        ] {
            let c = svc
                .maven_coordinates(Some("maven"), &format!("g/core/1.0-SNAPSHOT/{filename}"))
                .unwrap();
            assert_eq!(svc.excludes_maven_classifier(&c), excluded);
            assert_eq!(c.version, "1.0-SNAPSHOT");
        }
        for format in ["npm", "pypi", "nuget", "docker", "cargo", "generic"] {
            assert!(svc
                .maven_coordinates(Some(format), "g/core/1/core-1-sources.jar")
                .is_none());
        }
        for file in [
            "maven-metadata.xml",
            "core-1-sources.jar.asc",
            "core-1-sources.jar.sha256",
            "core-1.jar.md5",
        ] {
            assert!(svc
                .maven_coordinates(Some("maven"), &format!("g/core/1/{file}"))
                .is_none());
        }
        assert!(svc
            .maven_coordinates(Some("maven"), "invalid.jar")
            .is_none());
    }

    /// Stateful HTTP fake: omits parents in lookup, supports a competing
    /// creator and can simulate DT accepting duplicate names and versions.
    #[derive(Default)]
    struct Portfolio {
        projects: Vec<Value>,
        allow_duplicates: bool,
        conflict_once: bool,
        fault: Option<(String, String, u16)>,
        uploads: Vec<String>,
    }

    #[derive(Clone)]
    struct Api(Arc<Mutex<Portfolio>>);

    impl Respond for Api {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            let mut state = self.0.lock().unwrap();
            let method = req.method.as_str();
            let path = req.url.path();
            if let Some((verb, endpoint, status)) = &state.fault {
                if method == verb && path == endpoint {
                    return ResponseTemplate::new(*status)
                        .set_body_string("injected upstream failure");
                }
            }
            if method == "GET" && path == "/api/v1/project/lookup" {
                let query: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
                let found = state.projects.iter().find(|p| {
                    p["name"].as_str() == query.get("name").map(|v| v.as_ref())
                        && p["version"].as_str() == query.get("version").map(|v| v.as_ref())
                });
                let response = match found {
                    Some(p) => {
                        let mut summary = p.clone();
                        summary.as_object_mut().unwrap().remove("parent");
                        ResponseTemplate::new(200).set_body_json(summary)
                    }
                    None => ResponseTemplate::new(404),
                };
                return if state.allow_duplicates {
                    response.set_delay(Duration::from_millis(30))
                } else {
                    response
                };
            }
            if let Some(uuid) = path.strip_prefix("/api/v1/project/") {
                if let Some(project) = state.projects.iter_mut().find(|p| p["uuid"] == uuid) {
                    if method == "PATCH" {
                        let body: Value = serde_json::from_slice(&req.body).unwrap();
                        assert_eq!(
                            body.as_object().unwrap().len(),
                            4,
                            "partial update contains parent and unchanged primitive flags only"
                        );
                        project["parent"] = body["parent"].clone();
                        // Model DT's actual PATCH primitive defaults so a
                        // parent-only request would fail the preservation test.
                        project["active"] = body.get("active").cloned().unwrap_or(json!(true));
                        project["isLatest"] = body.get("isLatest").cloned().unwrap_or(json!(false));
                        project["collectionLogic"] = body
                            .get("collectionLogic")
                            .cloned()
                            .unwrap_or(json!("NONE"));
                    }
                    return ResponseTemplate::new(200).set_body_json(project.clone());
                }
            }
            if method == "PUT" && path == "/api/v1/project" {
                let mut body: Value = serde_json::from_slice(&req.body).unwrap();
                if !state.allow_duplicates
                    && state
                        .projects
                        .iter()
                        .any(|p| p["name"] == body["name"] && p["version"] == body["version"])
                {
                    return ResponseTemplate::new(409);
                }
                body["uuid"] = json!(uuid::Uuid::new_v4().to_string());
                body["active"] = json!(true);
                body["isLatest"] = json!(false);
                state.projects.push(body.clone());
                if state.conflict_once {
                    state.conflict_once = false;
                    return ResponseTemplate::new(409);
                }
                return ResponseTemplate::new(201).set_body_json(body);
            }
            if method == "PUT" && path == "/api/v1/bom" {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                state.uploads.push(body["project"].as_str().unwrap().into());
                return ResponseTemplate::new(200).set_body_json(json!({"token": "upload-token"}));
            }
            ResponseTemplate::new(404)
        }
    }

    async fn api(
        portfolio: Portfolio,
    ) -> (MockServer, Arc<Mutex<Portfolio>>, DependencyTrackService) {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(portfolio));
        Mock::given(|_: &Request| true)
            .respond_with(Api(state.clone()))
            .mount(&server)
            .await;
        let svc = service(&server.uri(), true, "");
        (server, state, svc)
    }

    fn parent(name: &str) -> Value {
        json!({"uuid": "parent", "name": name, "version": null,
            "group": "ru.molnet", "purl": "pkg:maven/ru.molnet/core",
            "collectionLogic": DIRECT_CHILDREN})
    }

    fn child(parent: Option<&str>) -> Value {
        let mut p = json!({"uuid": "child", "name": SCOPED_NAME, "version": "1.0", "group": "ru.molnet",
            "description": "operator description", "collectionLogic": "NONE", "active": false, "isLatest": true});
        if let Some(uuid) = parent {
            p["parent"] = json!({"uuid": uuid});
        }
        p
    }

    #[tokio::test]
    async fn creates_collection_and_version_and_uploads_only_to_child() {
        let (_server, state, svc) = api(Portfolio::default()).await;
        let c = provision(&svc, &coordinates("1.0")).await.unwrap();
        svc.upload_sbom(&c.uuid, "{}").await.unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.projects.len(), 2);
        assert_eq!(state.projects[0]["version"], Value::Null);
        assert_eq!(state.projects[0]["collectionLogic"], DIRECT_CHILDREN);
        assert_eq!(state.projects[0]["name"], SCOPED_NAME);
        assert_eq!(
            state.projects[1]["parent"]["uuid"],
            state.projects[0]["uuid"]
        );
        assert_eq!(state.uploads, vec![c.uuid]);
    }

    #[tokio::test]
    async fn reuses_scoped_collection_and_links_child_without_replacing_fields() {
        let (server, state, svc) = api(Portfolio {
            projects: vec![parent(SCOPED_NAME), child(None)],
            ..Default::default()
        })
        .await;
        for _ in 0..2 {
            let c = provision(&svc, &coordinates("1.0")).await.unwrap();
            assert_eq!(c.uuid, "child");
            svc.upload_sbom(&c.uuid, "{}").await.unwrap();
        }
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method.as_str() == "PATCH")
                .count(),
            1
        );
        assert!(!requests
            .iter()
            .any(|r| r.method.as_str() == "PUT" && r.url.path() == "/api/v1/project"));
        let state = state.lock().unwrap();
        assert_eq!(state.projects[1]["description"], "operator description");
        assert_eq!(state.projects[1]["active"], false);
        assert_eq!(state.projects[1]["isLatest"], true);
        assert_eq!(state.projects[1]["parent"]["uuid"], "parent");
        assert_eq!(state.uploads.len(), 2);
    }

    #[tokio::test]
    async fn preserves_different_parent_and_creates_no_redundant_collection() {
        let other = json!({"uuid": "other", "name": "department", "version": null, "collectionLogic": DIRECT_CHILDREN});
        let (server, _, svc) = api(Portfolio {
            projects: vec![other, child(Some("other"))],
            ..Default::default()
        })
        .await;
        let db = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        db.close().await;
        let c = svc
            .get_or_create_maven_project(&db, REPOSITORY, &coordinates("1.0"), "repo")
            .await
            .unwrap();
        assert_eq!(c.parent.unwrap().uuid, "other");
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn parallel_versions_and_creation_conflicts_are_idempotent() {
        let (_server, state, svc) = api(Portfolio {
            conflict_once: true,
            ..Default::default()
        })
        .await;
        // Two independent clients exercise DT conflict recovery as well as the
        // per-client lock. Both upload versions under one parent.
        let second = service(&svc.config.base_url, true, "");
        let first_coords = coordinates("1.0");
        let second_coords = coordinates("2.0");
        let (a, b, c) = tokio::join!(
            provision(&svc, &first_coords),
            provision(&svc, &second_coords),
            provision(&second, &first_coords),
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_eq!(a.uuid, c.unwrap().uuid);
        assert_eq!(a.parent.unwrap().uuid, b.parent.unwrap().uuid);
        assert_eq!(state.lock().unwrap().projects.len(), 3);
    }

    #[tokio::test]
    async fn conflicting_scoped_projects_never_mutate() {
        let mut wrong_group = child(None);
        wrong_group["group"] = json!("wrong.group");
        let mut versioned_collection = child(None);
        versioned_collection["collectionLogic"] = json!(DIRECT_CHILDREN);
        let mut wrong_collection = parent(SCOPED_NAME);
        wrong_collection["collectionLogic"] = json!("NONE");
        for project in [wrong_group, versioned_collection, wrong_collection] {
            let (server, _, svc) = api(Portfolio {
                projects: vec![project],
                ..Default::default()
            })
            .await;
            assert!(provision(&svc, &coordinates("1.0")).await.is_err());
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET"));
        }
    }

    #[tokio::test]
    async fn excludes_before_any_http_call() {
        let server = MockServer::start().await;
        let db = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        for collections in [false, true] {
            let svc = service(&server.uri(), collections, "JAVADOC");
            let c = svc
                .maven_coordinates(Some("maven"), "g/core/1/core-1-javadoc.jar")
                .unwrap();
            assert!(svc
                .get_or_create_maven_project(&db, REPOSITORY, &c, "repo")
                .await
                .is_err());
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn upstream_failures_are_returned_without_destructive_requests() {
        for status in [401, 403, 409, 500, 503] {
            for (method, path, projects) in [
                ("GET", "/api/v1/project/lookup", vec![]),
                ("PUT", "/api/v1/project", vec![]),
                (
                    "PATCH",
                    "/api/v1/project/child",
                    vec![parent(SCOPED_NAME), child(None)],
                ),
            ] {
                let (server, _, svc) = api(Portfolio {
                    projects,
                    fault: Some((method.into(), path.into(), status)),
                    ..Default::default()
                })
                .await;
                let err = provision(&svc, &coordinates("1.0")).await.unwrap_err();
                assert!(err.to_string().contains(&status.to_string()), "{err}");
                let requests = server.received_requests().await.unwrap();
                assert!(!requests.iter().any(|r| r.method.as_str() == "DELETE"
                    || r.method.as_str() == "POST"
                    || r.url.path() == "/api/v1/bom"));
            }
        }
    }

    #[tokio::test]
    async fn disabled_features_keep_existing_request_contract() {
        let (_server, state, mut svc) = api(Portfolio::default()).await;
        svc.config.auto_collections = false;
        let project = svc
            .get_or_create_project("core", Some("1.0"), Some("repo"))
            .await
            .unwrap();
        svc.upload_sbom(&project.uuid, "{}").await.unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.projects.len(), 1);
        assert!(state.projects[0].get("parent").is_none());
        assert!(state.projects[0].get("group").is_none());
        assert!(state.projects[0].get("collectionLogic").is_none());
        assert_eq!(state.projects[0]["name"], "core");
        assert_eq!(state.uploads, vec![project.uuid]);
    }

    #[tokio::test]
    async fn separates_repositories_with_the_same_coordinates_and_leaves_unscoped_projects_intact()
    {
        let mut unscoped_child = child(Some("parent"));
        unscoped_child["name"] = json!("ru.molnet:core");
        unscoped_child["purl"] = json!("pkg:maven/ru.molnet/core@1.0");
        let unscoped = vec![parent("ru.molnet:core"), unscoped_child];
        let (server, state, svc) = api(Portfolio {
            projects: unscoped.clone(),
            ..Default::default()
        })
        .await;
        let c = coordinates("1.0");
        let other_name = project_name(Uuid::from_u128(2), &c);
        let first = provision(&svc, &c).await.unwrap();
        let second = svc
            .provision_maven_project(&other_name, &c, "repo")
            .await
            .unwrap();
        assert_ne!(first.uuid, second.uuid);
        assert_ne!(first.parent.unwrap().uuid, second.parent.unwrap().uuid);
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| { r.method.as_str() != "GET" || r.url.path() != "/api/v1/project" }));
        let state = state.lock().unwrap();
        assert_eq!(state.projects.len(), 6);
        assert_eq!(&state.projects[..2], unscoped.as_slice());
    }

    #[tokio::test]
    async fn a_busy_project_does_not_block_other_coordinates() {
        let (_server, _, svc) = api(Portfolio::default()).await;
        let name = project_name(REPOSITORY, &coordinates("1.0"));
        let _guard = svc.maven_provisioning.lock(&name).await;
        let next_version = project_name(REPOSITORY, &coordinates("2.0"));
        assert!(tokio::time::timeout(
            Duration::from_millis(25),
            svc.maven_provisioning.lock(&next_version),
        )
        .await
        .is_err());

        let mut other = coordinates("1.0");
        other.artifact_id = "other".into();
        tokio::time::timeout(Duration::from_secs(5), provision(&svc, &other))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cycle_is_rejected_before_parent_assignment() {
        let mut p = parent(SCOPED_NAME);
        p["parent"] = json!({"uuid": "child"});
        let (server, _, svc) = api(Portfolio {
            projects: vec![p, child(None)],
            ..Default::default()
        })
        .await;
        let err = provision(&svc, &coordinates("1.0")).await.unwrap_err();
        assert!(err.to_string().contains("cyclic"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn jar_and_pom_keep_one_version_project_and_separate_uploads() {
        let (_server, state, svc) = api(Portfolio::default()).await;
        for extension in ["jar", "pom"] {
            let c = svc
                .maven_coordinates(
                    Some("maven"),
                    &format!("ru/molnet/core/1.0/core-1.0.{extension}"),
                )
                .unwrap();
            let p = provision(&svc, &c).await.unwrap();
            svc.upload_sbom(&p.uuid, &format!("{{\"inventory\":\"{extension}\"}}"))
                .await
                .unwrap();
        }
        let state = state.lock().unwrap();
        assert_eq!(state.projects.len(), 2);
        assert_eq!(state.uploads.len(), 2);
        assert_eq!(state.uploads[0], state.uploads[1]);
    }

    #[tokio::test]
    async fn database_lock_serializes_replicas_and_releases_after_errors() {
        let Some(db) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let (_server, state, svc) = api(Portfolio {
            allow_duplicates: true,
            fault: Some(("PUT".into(), "/api/v1/project".into(), 503)),
            ..Default::default()
        })
        .await;
        let a = coordinates("1.0");
        let b = coordinates("2.0");
        assert!(svc
            .get_or_create_maven_project(&db, REPOSITORY, &a, "repo")
            .await
            .is_err());
        state.lock().unwrap().fault = None;
        let other = service(&svc.config.base_url, true, "");
        let (first, second, repeated) = tokio::join!(
            svc.get_or_create_maven_project(&db, REPOSITORY, &a, "repo"),
            other.get_or_create_maven_project(&db, REPOSITORY, &b, "repo"),
            other.get_or_create_maven_project(&db, REPOSITORY, &a, "repo"),
        );
        let first = first.unwrap();
        assert_eq!(first.uuid, repeated.unwrap().uuid);
        assert_eq!(
            first.parent.unwrap().uuid,
            second.unwrap().parent.unwrap().uuid
        );
        assert_eq!(state.lock().unwrap().projects.len(), 3);
    }
}
