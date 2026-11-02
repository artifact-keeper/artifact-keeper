//! Maven-only Dependency-Track policy and collection provisioning.
//!
//! API contract verified against /api/openapi.json from the official 4.14.0
//! executable (PUT /project, GET /project/{uuid}, PATCH /project/{uuid}).
//! PATCH sends only parent, never a serialized GET response: POST replaces fields.

use super::*;
use crate::formats::maven::{MavenCoordinates, MavenHandler};
use std::collections::HashSet;

const DIRECT_CHILDREN: &str = "AGGREGATE_DIRECT_CHILDREN";

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

    /// Provisioning runs only after the scanner's classifier eligibility check.
    /// No local scan state is read or written by this method.
    pub async fn get_or_create_maven_project(
        &self,
        coordinates: &MavenCoordinates,
        legacy_name: &str,
        description: &str,
    ) -> Result<DtProject> {
        // Defense in depth for future callers: excluded artifacts make zero requests.
        if self.excludes_maven_classifier(coordinates) {
            return Err(AppError::Validation("Excluded Maven classifier".into()));
        }
        let _guard = self.maven_provisioning.lock().await;
        let identity = format!("{}:{}", coordinates.group_id, coordinates.artifact_id);
        let projects = self.list_projects().await?;
        let mut collections = Vec::new();
        let mut children = Vec::new();
        let mut related_parents = HashSet::new();

        for summary in projects {
            // A renamed legacy collection with only a group cannot establish
            // artifact identity. Don't create a second collection beside it.
            let unidentified_collection = summary.version.is_none()
                && is_collection(&summary)
                && summary.group.as_deref() == Some(coordinates.group_id.as_str())
                && summary.purl.is_none()
                && !summary
                    .name
                    .starts_with(&format!("{}:", coordinates.group_id));
            // Exact names or structured PURL identity only. No fuzzy matching.
            if summary.name != identity
                && summary.name != coordinates.artifact_id
                && summary.name != legacy_name
                && !purl_matches(&summary, coordinates)
                && !unidentified_collection
            {
                continue;
            }
            // List and lookup responses may omit parent. Always fetch full details.
            let project = self.maven_project_details(&summary.uuid).await?;
            let strong_identity = project_matches(&project, coordinates);
            if !strong_identity {
                // A conflicting explicit namespace proves this is another artifact.
                if project
                    .group
                    .as_deref()
                    .is_some_and(|g| g != coordinates.group_id)
                    || project.purl.is_some()
                {
                    continue;
                }
                return Err(ambiguous(
                    &identity,
                    "legacy project lacks unambiguous Maven artifact identity",
                ));
            }
            // Older versions may point to a renamed collection whose list
            // response carries no identity fields. Inspect that lineage too.
            if project.version.is_some() {
                if let Some(parent) = &project.parent {
                    related_parents.insert(parent.uuid.clone());
                }
            }
            if project.version.is_none() {
                if project.collection_logic.as_deref() != Some(DIRECT_CHILDREN) {
                    return Err(ambiguous(
                        &identity,
                        "unversioned project is not a direct-child collection",
                    ));
                }
                collections.push(project);
            } else if project.version.as_deref() == Some(coordinates.version.as_str()) {
                if is_collection(&project) {
                    return Err(ambiguous(
                        &identity,
                        "versioned project is itself a collection",
                    ));
                }
                children.push(project);
            }
        }
        let mut unidentified_parent = false;
        for uuid in related_parents {
            if collections.iter().any(|p| p.uuid == uuid) {
                continue;
            }
            let parent = self.maven_project_details(&uuid).await?;
            if project_matches(&parent, coordinates)
                && parent.version.is_none()
                && parent.collection_logic.as_deref() == Some(DIRECT_CHILDREN)
            {
                collections.push(parent);
            } else {
                unidentified_parent = true;
            }
        }
        if children.len() > 1 || collections.len() > 1 {
            return Err(ambiguous(&identity, "multiple exact project identities"));
        }
        let child = children.pop();
        // A legacy child can identify a renamed collection through its actual parent.
        // A different parent is preserved, and no redundant collection is created.
        if let Some(existing) = child.as_ref() {
            if let Some(parent_ref) = existing.parent.as_ref() {
                let parent = self.maven_project_details(&parent_ref.uuid).await?;
                if !project_matches(&parent, coordinates)
                    || parent.version.is_some()
                    || parent.collection_logic.as_deref() != Some(DIRECT_CHILDREN)
                    || collections.first().is_some_and(|p| p.uuid != parent.uuid)
                {
                    warn!(project_uuid = %existing.uuid, parent_uuid = %parent.uuid,
                        maven_identity = %identity, "Preserving different existing Dependency-Track parent");
                    return Ok(existing.clone());
                }
                info!(collection_uuid = %parent.uuid, maven_identity = %identity,
                    "Reusing existing Dependency-Track Maven collection");
                return Ok(existing.clone());
            }
        }

        if unidentified_parent {
            return Err(ambiguous(
                &identity,
                "another version has an unidentified existing parent",
            ));
        }

        let parent = if let Some(parent) = collections.pop() {
            info!(collection_uuid = %parent.uuid, maven_identity = %identity,
                "Reusing existing Dependency-Track Maven collection");
            parent
        } else {
            let parent = self
                .create_maven_project(&CreateProjectRequest {
                    name: identity.clone(),
                    version: None,
                    description: Some(description.into()),
                    group: Some(coordinates.group_id.clone()),
                    purl: Some(maven_purl(coordinates, false)),
                    parent: None,
                    collection_logic: Some(DIRECT_CHILDREN.into()),
                })
                .await?;
            if !project_matches(&parent, coordinates)
                || parent.version.is_some()
                || parent.collection_logic.as_deref() != Some(DIRECT_CHILDREN)
            {
                return Err(ambiguous(&identity, "conflicting collection identity"));
            }
            info!(collection_uuid = %parent.uuid, maven_identity = %identity,
                "Provisioned Dependency-Track Maven collection");
            parent
        };

        let child = if let Some(child) = child {
            child
        } else {
            // New children use the qualified identity too: DT uniqueness is
            // name/version, NOT group/name/version. Keep exact legacy children.
            self.create_maven_project(&CreateProjectRequest {
                name: identity.clone(),
                version: Some(coordinates.version.clone()),
                description: Some(description.into()),
                group: Some(coordinates.group_id.clone()),
                purl: Some(maven_purl(coordinates, true)),
                parent: Some(DtProjectParent {
                    uuid: parent.uuid.clone(),
                }),
                collection_logic: None,
            })
            .await?
        };
        if !project_matches(&child, coordinates)
            || child.version.as_deref() != Some(coordinates.version.as_str())
            || is_collection(&child)
        {
            return Err(ambiguous(&identity, "conflicting child identity"));
        }
        self.attach_maven_parent(child, &parent).await
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
            // Another AK instance may have won the unique name/version race.
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

    async fn attach_maven_parent(&self, child: DtProject, parent: &DtProject) -> Result<DtProject> {
        // Re-read before assignment, including after a concurrent create conflict.
        let mut child = self.maven_project_details(&child.uuid).await?;
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
                return Err(ambiguous(&child.name, "cyclic parent relationship"));
            }
            let Some(next) = ancestor.parent else { break };
            ancestor = self.maven_project_details(&next.uuid).await?;
        }
        let endpoint = format!(
            "{}/api/v1/project/{}",
            self.config.base_url,
            urlencoding::encode(&child.uuid)
        );
        let response = self
            .client
            .patch(&endpoint)
            .header("X-Api-Key", self.api_key()?)
            .json(&serde_json::json!({"parent": {"uuid": parent.uuid}}))
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

fn ambiguous(identity: &str, reason: &str) -> AppError {
    warn!(
        maven_identity = identity,
        reason, "Dependency-Track Maven identity is ambiguous; preserving existing projects"
    );
    AppError::Validation(format!(
        "Dependency-Track Maven identity {identity}: {reason}"
    ))
}

fn is_collection(project: &DtProject) -> bool {
    project
        .collection_logic
        .as_deref()
        .is_some_and(|logic| logic != "NONE")
}

fn project_matches(project: &DtProject, coordinates: &MavenCoordinates) -> bool {
    if project
        .group
        .as_deref()
        .is_some_and(|group| group != coordinates.group_id)
    {
        return false;
    }
    if project.purl.is_some() {
        return purl_matches(project, coordinates);
    }
    project.name == format!("{}:{}", coordinates.group_id, coordinates.artifact_id)
        || (project.name == coordinates.artifact_id
            && project.group.as_deref() == Some(coordinates.group_id.as_str()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn service(url: &str, collections: bool, csv: &str) -> DependencyTrackService {
        DependencyTrackService::new(DependencyTrackConfig {
            base_url: url.into(),
            api_key: Some("test-key".into()),
            api_key_file: None,
            enabled: true,
            auto_collections: collections,
            maven_excluded_classifiers: DependencyTrackConfig::parse_excluded_classifiers(csv),
        })
        .unwrap()
    }

    fn coordinates(version: &str) -> MavenCoordinates {
        MavenHandler::parse_coordinates(&format!("ru/molnet/core/{version}/core-{version}.jar"))
            .unwrap()
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

    /// Stateful HTTP fake: omits parents in list/lookup, enforces unique
    /// name/version, supports a competing creator and records every request.
    #[derive(Default)]
    struct Portfolio {
        projects: Vec<Value>,
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
            if method == "GET" && path == "/api/v1/project" {
                let projects: Vec<_> = state
                    .projects
                    .iter()
                    .map(|p| {
                        let mut summary = p.clone();
                        summary.as_object_mut().unwrap().remove("parent");
                        summary
                    })
                    .collect();
                return ResponseTemplate::new(200)
                    .insert_header("X-Total-Count", projects.len().to_string())
                    .set_body_json(projects);
            }
            if method == "GET" && path == "/api/v1/project/lookup" {
                let query: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
                let found = state.projects.iter().find(|p| {
                    p["name"].as_str() == query.get("name").map(|v| v.as_ref())
                        && p["version"].as_str() == query.get("version").map(|v| v.as_ref())
                });
                return match found {
                    Some(p) => {
                        let mut summary = p.clone();
                        summary.as_object_mut().unwrap().remove("parent");
                        ResponseTemplate::new(200).set_body_json(summary)
                    }
                    None => ResponseTemplate::new(404),
                };
            }
            if let Some(uuid) = path.strip_prefix("/api/v1/project/") {
                if let Some(project) = state.projects.iter_mut().find(|p| p["uuid"] == uuid) {
                    if method == "PATCH" {
                        let body: Value = serde_json::from_slice(&req.body).unwrap();
                        assert_eq!(
                            body.as_object().unwrap().len(),
                            1,
                            "partial update preserves project fields"
                        );
                        project["parent"] = body["parent"].clone();
                    }
                    return ResponseTemplate::new(200).set_body_json(project.clone());
                }
            }
            if method == "PUT" && path == "/api/v1/project" {
                let mut body: Value = serde_json::from_slice(&req.body).unwrap();
                if state
                    .projects
                    .iter()
                    .any(|p| p["name"] == body["name"] && p["version"] == body["version"])
                {
                    return ResponseTemplate::new(409);
                }
                body["uuid"] = json!(uuid::Uuid::new_v4().to_string());
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
        let mut p = json!({"uuid": "child", "name": "core", "version": "1.0", "group": "ru.molnet",
            "description": "operator description", "collectionLogic": "NONE"});
        if let Some(uuid) = parent {
            p["parent"] = json!({"uuid": uuid});
        }
        p
    }

    #[tokio::test]
    async fn creates_collection_and_version_and_uploads_only_to_child() {
        let (_server, state, svc) = api(Portfolio::default()).await;
        let c = svc
            .get_or_create_maven_project(&coordinates("1.0"), "core", "repo")
            .await
            .unwrap();
        svc.upload_sbom(&c.uuid, "{}").await.unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.projects.len(), 2);
        assert_eq!(state.projects[0]["version"], Value::Null);
        assert_eq!(state.projects[0]["collectionLogic"], DIRECT_CHILDREN);
        assert_eq!(state.projects[0]["name"], "ru.molnet:core");
        assert_eq!(
            state.projects[1]["parent"]["uuid"],
            state.projects[0]["uuid"]
        );
        assert_eq!(state.uploads, vec![c.uuid]);
    }

    #[tokio::test]
    async fn reuses_renamed_collection_and_links_legacy_child_without_replacing_fields() {
        let (server, state, svc) = api(Portfolio {
            projects: vec![parent("old collection label"), child(None)],
            ..Default::default()
        })
        .await;
        for _ in 0..2 {
            let c = svc
                .get_or_create_maven_project(&coordinates("1.0"), "core", "repo")
                .await
                .unwrap();
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
        let c = svc
            .get_or_create_maven_project(&coordinates("1.0"), "core", "repo")
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
            svc.get_or_create_maven_project(&first_coords, "core", "repo"),
            svc.get_or_create_maven_project(&second_coords, "core", "repo"),
            second.get_or_create_maven_project(&first_coords, "core", "repo"),
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_eq!(a.uuid, c.unwrap().uuid);
        assert_eq!(a.parent.unwrap().uuid, b.parent.unwrap().uuid);
        assert_eq!(state.lock().unwrap().projects.len(), 3);
    }

    #[tokio::test]
    async fn ambiguous_legacy_identity_and_multiple_collections_never_mutate() {
        let mut unknown = child(None);
        unknown.as_object_mut().unwrap().remove("group");
        let mut duplicate = parent("another label");
        duplicate["uuid"] = json!("second-parent");
        let mut renamed = parent("historic label");
        renamed.as_object_mut().unwrap().remove("purl");
        for projects in [
            vec![unknown],
            vec![parent("first"), duplicate],
            vec![renamed],
        ] {
            let (server, _, svc) = api(Portfolio {
                projects,
                ..Default::default()
            })
            .await;
            assert!(svc
                .get_or_create_maven_project(&coordinates("1.0"), "core", "repo")
                .await
                .is_err());
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
        for collections in [false, true] {
            let svc = service(&server.uri(), collections, "JAVADOC");
            let c = svc
                .maven_coordinates(Some("maven"), "g/core/1/core-1-javadoc.jar")
                .unwrap();
            assert!(svc
                .get_or_create_maven_project(&c, "core", "repo")
                .await
                .is_err());
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn upstream_failures_are_returned_without_destructive_requests() {
        for status in [401, 403, 409, 500, 503] {
            for (method, path, projects) in [
                ("GET", "/api/v1/project", vec![]),
                ("PUT", "/api/v1/project", vec![]),
                (
                    "PATCH",
                    "/api/v1/project/child",
                    vec![parent("old"), child(None)],
                ),
            ] {
                let (server, _, svc) = api(Portfolio {
                    projects,
                    fault: Some((method.into(), path.into(), status)),
                    ..Default::default()
                })
                .await;
                let err = svc
                    .get_or_create_maven_project(&coordinates("1.0"), "core", "repo")
                    .await
                    .unwrap_err();
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
    async fn older_version_lineage_prevents_duplicate_renamed_collection() {
        let mut older = child(Some("parent"));
        older["version"] = json!("0.9");
        // Simulate a collection with a nonstandard name and no namespace proof.
        let uncertain = json!({"uuid": "parent", "name": "historic collection", "version": null, "collectionLogic": DIRECT_CHILDREN});
        let (server, _, svc) = api(Portfolio {
            projects: vec![older, uncertain],
            ..Default::default()
        })
        .await;
        assert!(svc
            .get_or_create_maven_project(&coordinates("1.0"), "core", "repo")
            .await
            .is_err());
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn cycle_is_rejected_before_parent_assignment() {
        let mut p = parent("collection");
        p["parent"] = json!({"uuid": "child"});
        let (server, _, svc) = api(Portfolio {
            projects: vec![p, child(None)],
            ..Default::default()
        })
        .await;
        let err = svc
            .get_or_create_maven_project(&coordinates("1.0"), "core", "repo")
            .await
            .unwrap_err();
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
            let p = svc
                .get_or_create_maven_project(&c, "core", "repo")
                .await
                .unwrap();
            svc.upload_sbom(&p.uuid, &format!("{{\"inventory\":\"{extension}\"}}"))
                .await
                .unwrap();
        }
        let state = state.lock().unwrap();
        assert_eq!(state.projects.len(), 2);
        assert_eq!(state.uploads.len(), 2);
        assert_eq!(state.uploads[0], state.uploads[1]);
    }
}
