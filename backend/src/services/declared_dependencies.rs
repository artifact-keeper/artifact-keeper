//! Declared-dependency extraction for SBOM generation (#870).
//!
//! The SBOM read path historically sourced components only from scanner
//! output (`scan_packages` / `scan_findings`). For an artifact a scanner
//! cannot enumerate, a bare Maven `.jar` with no lockfile, or any upload that
//! was never scanned, that yields an empty component list which the SBOM then
//! presents as an authoritative "no dependencies." That is the defect behind
//! issue #870: the empty result is indistinguishable from a real empty SBOM.
//!
//! This module adds a second source: the artifact's own *declared*
//! dependencies, parsed from its manifest (Maven POM, npm `package.json`,
//! Helm `Chart.yaml`). Declared dependencies are merged with scanner output by
//! [`merge_dependencies`], and the combined result carries an honest
//! [`InventoryCompleteness`] verdict so a downstream consumer can tell a
//! direct-deps-only SBOM apart from a full scanner inventory.
//!
//! Scope and honesty boundaries:
//!   - Declared dependencies are *direct* only. Transitive resolution is the
//!     scanner's job; a declared-only SBOM is marked [`InventoryCompleteness::Declared`].
//!   - Maven `${property}` versions are resolved against the POM's own
//!     `<properties>` and the built-in `${project.*}` expressions. Versions
//!     inherited from a parent or `<dependencyManagement>` BOM are not fetched
//!     (the parent POM is usually upstream and not in the registry); such
//!     dependencies are emitted with a `None` version and the SBOM is marked
//!     [`InventoryCompleteness::Partial`].
//!   - npm/Helm declared versions are ranges (`^4.0.0`), not pinned versions,
//!     so no purl is synthesized for them (a purl implies an exact version).

use crate::formats::maven::PomProject;
use crate::services::sbom_service::DependencyInfo;
use serde_json::Value;
use std::collections::BTreeMap;

/// Inventory completeness verdict for a generated SBOM (#870), extending the
/// #1153 scan-completeness signal. Rendered into the SBOM as a
/// `metadata.properties` entry (CycloneDX) or a `creationInfo.comment` line
/// (SPDX) by `SbomService::generate_sbom_with_completeness`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryCompleteness {
    /// A scanner enumerated the full package set for this artifact. The
    /// component list is authoritative.
    Complete,
    /// Only the artifact's directly-declared dependencies are known (no
    /// scanner inventory). Transitive dependencies are not included.
    Declared,
    /// Dependency data is present but known to be incomplete: a scanner pass
    /// was vulnerability-only (legacy `scan_findings` fallback), or some
    /// declared versions could not be resolved (Maven `${property}` /
    /// `dependencyManagement`).
    Partial,
    /// No dependency data from any source. The SBOM has zero components and
    /// says so explicitly rather than implying the artifact has no deps.
    None,
}

impl InventoryCompleteness {
    /// String form embedded in the SBOM document.
    pub fn as_str(self) -> &'static str {
        match self {
            InventoryCompleteness::Complete => "complete",
            InventoryCompleteness::Declared => "declared",
            InventoryCompleteness::Partial => "partial",
            InventoryCompleteness::None => "none",
        }
    }

    /// The value to thread into `generate_sbom_with_completeness`.
    ///
    /// Returns `None` for [`InventoryCompleteness::Complete`] so a fully
    /// scanned artifact keeps byte-identical SBOM output and a warm
    /// content-hash cache, preserving the pre-#870 contract documented on
    /// `SbomService::generate_sbom_with_completeness` (#1153).
    pub fn to_signal(self) -> Option<&'static str> {
        match self {
            InventoryCompleteness::Complete => None,
            other => Some(other.as_str()),
        }
    }
}

/// What each dependency source produced, used to compute the SBOM
/// completeness verdict via [`verdict`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SourceSignal {
    /// The scanner produced a full package inventory (`scan_packages` rows).
    pub package_inventory: bool,
    /// The only scanner signal was vulnerability findings (`scan_findings`),
    /// i.e. a CVE-only component list, not a full inventory.
    pub findings_only: bool,
    /// Number of declared dependencies extracted from the manifest.
    pub declared: usize,
    /// At least one declared dependency had an unresolved version (e.g. a
    /// Maven `${property}` or a managed version inherited from a BOM).
    pub declared_unresolved: bool,
}

/// Compute the SBOM inventory completeness verdict from what each source
/// produced. See [`InventoryCompleteness`] for the meaning of each value.
pub fn verdict(s: &SourceSignal) -> InventoryCompleteness {
    if s.package_inventory {
        return InventoryCompleteness::Complete;
    }
    if s.findings_only {
        // CVE-only inventory (optionally augmented with declared direct deps)
        // is incomplete by construction.
        return InventoryCompleteness::Partial;
    }
    if s.declared == 0 {
        return InventoryCompleteness::None;
    }
    if s.declared_unresolved {
        return InventoryCompleteness::Partial;
    }
    InventoryCompleteness::Declared
}

/// A version is "resolved" if it is concrete: non-empty and free of any
/// unsubstituted Maven property placeholder (`${...}`).
pub fn is_resolved_version(version: &str) -> bool {
    !version.is_empty() && !version.contains("${")
}

/// Build a Maven purl: `pkg:maven/<groupId>/<artifactId>@<version>`.
///
/// Returns `None` when group or artifact is empty, or when the version is
/// missing or unresolved (a purl must carry a concrete version).
pub fn maven_purl(group_id: &str, artifact_id: &str, version: Option<&str>) -> Option<String> {
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }
    let v = version?;
    if !is_resolved_version(v) {
        return None;
    }
    Some(format!("pkg:maven/{}/{}@{}", group_id, artifact_id, v))
}

/// Resolve Maven `${...}` placeholders in `raw` against a POM's own
/// `<properties>` and the built-in `${project.version}` / `${project.groupId}`
/// expressions.
///
/// Unknown placeholders are left intact so callers can detect them via
/// [`is_resolved_version`]. Input with no `${` is returned unchanged.
pub fn interpolate_pom_value(raw: &str, pom: &PomProject) -> String {
    if !raw.contains("${") {
        return raw.to_string();
    }
    let project_version = pom
        .version
        .clone()
        .or_else(|| pom.parent.as_ref().and_then(|p| p.version.clone()));
    let project_group = pom
        .group_id
        .clone()
        .or_else(|| pom.parent.as_ref().and_then(|p| p.group_id.clone()));

    let mut out = raw.to_string();
    if let Some(v) = &project_version {
        out = out
            .replace("${project.version}", v)
            .replace("${version}", v);
    }
    if let Some(g) = &project_group {
        out = out
            .replace("${project.groupId}", g)
            .replace("${groupId}", g);
    }
    if let Some(props) = &pom.properties {
        for (k, val) in props {
            out = out.replace(&format!("${{{}}}", k), val);
        }
    }
    out
}

/// Extract direct Maven dependencies from a parsed POM, resolving
/// `${property}` versions against the POM where possible.
///
/// `test`-scoped dependencies are excluded (they are not shipped with the
/// artifact). The dependency name is `groupId:artifactId`, matching how Maven
/// coordinates are conventionally displayed.
pub fn maven_deps_from_pom(pom: &PomProject) -> Vec<DependencyInfo> {
    let deps = match &pom.dependencies {
        Some(d) => &d.dependency,
        None => return Vec::new(),
    };
    deps.iter()
        .filter(|d| d.scope.as_deref() != Some("test"))
        .filter_map(|d| {
            let group = interpolate_pom_value(&d.group_id, pom);
            let artifact = interpolate_pom_value(&d.artifact_id, pom);
            if group.is_empty() || artifact.is_empty() {
                return None;
            }
            let version = d
                .version
                .as_deref()
                .map(|v| interpolate_pom_value(v, pom))
                .filter(|v| is_resolved_version(v));
            let purl = maven_purl(&group, &artifact, version.as_deref());
            Some(DependencyInfo {
                name: format!("{}:{}", group, artifact),
                version,
                purl,
                license: None,
                sha256: None,
            })
        })
        .collect()
}

/// Extract Maven dependencies from the `dependencies` array stored in
/// `artifact_metadata.metadata` at upload time. Each element is a serialized
/// `PomDependency` (`{groupId, artifactId, version, scope, ...}`).
///
/// Unlike [`maven_deps_from_pom`], the POM `<properties>` context is not
/// available here, so a `${...}` version is emitted as unresolved (`None`).
/// Callers that need property resolution should fall back to reading the POM
/// from storage and using [`maven_deps_from_pom`].
pub fn maven_deps_from_metadata(deps: &Value) -> Vec<DependencyInfo> {
    let arr = match deps.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .filter_map(|d| {
            let group = d.get("groupId").and_then(|v| v.as_str()).unwrap_or("");
            let artifact = d.get("artifactId").and_then(|v| v.as_str()).unwrap_or("");
            if group.is_empty() || artifact.is_empty() {
                return None;
            }
            if d.get("scope").and_then(|v| v.as_str()) == Some("test") {
                return None;
            }
            let version = d
                .get("version")
                .and_then(|v| v.as_str())
                .filter(|v| is_resolved_version(v))
                .map(|v| v.to_string());
            let purl = maven_purl(group, artifact, version.as_deref());
            Some(DependencyInfo {
                name: format!("{}:{}", group, artifact),
                version,
                purl,
                license: None,
                sha256: None,
            })
        })
        .collect()
}

/// Returns true if any element of a stored Maven `dependencies` array carries
/// an unresolved (`${...}`) version. Used to decide whether to fall back to
/// reading the full POM from storage for property resolution.
pub fn maven_metadata_has_unresolved(deps: &Value) -> bool {
    deps.as_array()
        .map(|arr| {
            arr.iter().any(|d| {
                d.get("version")
                    .and_then(|v| v.as_str())
                    .map(|v| !is_resolved_version(v))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Extract declared npm runtime dependencies from the stored `version_data`
/// object (the parsed `package.json`).
///
/// Includes `dependencies` and `optionalDependencies`; excludes
/// `devDependencies` (not shipped at runtime). package.json versions are
/// ranges (`^4.0.0`), not pinned versions, so the range is emitted as the
/// version and no purl is synthesized. Output should be treated as
/// [`InventoryCompleteness::Declared`], never `Complete`.
pub fn npm_deps_from_version_data(version_data: &Value) -> Vec<DependencyInfo> {
    let mut out: BTreeMap<String, DependencyInfo> = BTreeMap::new();
    for key in ["dependencies", "optionalDependencies"] {
        if let Some(obj) = version_data.get(key).and_then(|v| v.as_object()) {
            for (name, range) in obj {
                if name.is_empty() {
                    continue;
                }
                let version = range
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());
                out.entry(name.clone()).or_insert(DependencyInfo {
                    name: name.clone(),
                    version,
                    purl: None,
                    license: None,
                    sha256: None,
                });
            }
        }
    }
    out.into_values().collect()
}

/// Extract declared Helm chart dependencies from the stored `chart` object
/// (parsed `Chart.yaml`). Each entry is `{name, version, repository}`. Helm
/// dependency versions can be ranges, so no purl is synthesized.
pub fn helm_deps_from_chart(chart: &Value) -> Vec<DependencyInfo> {
    let arr = match chart.get("dependencies").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .filter_map(|d| {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                return None;
            }
            let version = d
                .get("version")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Some(DependencyInfo {
                name: name.to_string(),
                version,
                purl: None,
                license: None,
                sha256: None,
            })
        })
        .collect()
}

/// Merge scanner-derived and declared dependency lists into one deduplicated
/// list.
///
/// Dedup key is the purl when present, otherwise `(name, version)`. Scanner
/// rows are kept first and win on collision: they carry license, purl, and
/// scanner-resolved exact versions that the declared manifest lacks. Declared
/// rows then fill in dependencies the scanner did not enumerate.
pub fn merge_dependencies(
    scanner: Vec<DependencyInfo>,
    declared: Vec<DependencyInfo>,
) -> Vec<DependencyInfo> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<DependencyInfo> = Vec::with_capacity(scanner.len() + declared.len());
    for dep in scanner.into_iter().chain(declared) {
        let key = match &dep.purl {
            Some(p) => format!("purl\u{0}{}", p),
            None => format!(
                "nv\u{0}{}\u{0}{}",
                dep.name,
                dep.version.as_deref().unwrap_or("")
            ),
        };
        if seen.insert(key) {
            out.push(dep);
        }
    }
    out
}

/// Extract declared dependencies from already-loaded manifest metadata for a
/// repository `format`. Pure: no database or object-storage access.
///
/// Returns `(deps, any_version_unresolved)`. Unknown or unsupported formats
/// return an empty list. For Maven this reads the `dependencies` array stored
/// at upload and does NOT resolve `${property}` versions (it has no POM
/// `<properties>` context); a caller that needs property resolution should
/// read the POM from storage and use [`maven_deps_from_pom`].
///
/// Shared by the on-demand `/sbom` read path and the on-scan Dependency-Track
/// submission path so both surfaces extract declared dependencies identically.
pub fn declared_deps_from_manifest(format: &str, metadata: &Value) -> (Vec<DependencyInfo>, bool) {
    match format.to_lowercase().as_str() {
        "maven" => {
            let stored = metadata.get("dependencies");
            let mut unresolved = stored.map(maven_metadata_has_unresolved).unwrap_or(false);
            let deps = stored.map(maven_deps_from_metadata).unwrap_or_default();
            unresolved = unresolved || deps.iter().any(|d| d.version.is_none());
            (deps, unresolved)
        }
        "npm" | "yarn" | "pnpm" | "bower" => {
            let vd = metadata.get("version_data").cloned().unwrap_or(Value::Null);
            (npm_deps_from_version_data(&vd), false)
        }
        "helm" | "helm_oci" => {
            let chart = metadata.get("chart").cloned().unwrap_or(Value::Null);
            (helm_deps_from_chart(&chart), false)
        }
        _ => (Vec::new(), false),
    }
}

/// Merge scanner-derived and declared dependencies and compute the SBOM
/// completeness signal in one step.
///
/// Returns `(merged_deps, completeness_signal)` where the signal is the value
/// to pass to `generate_sbom_with_completeness` (`None` == `complete`). Shared
/// by the on-demand `/sbom` read path and the on-scan Dependency-Track
/// submission path so both compute the same merge and verdict.
pub fn assemble_dependencies(
    scanner: Vec<DependencyInfo>,
    declared: Vec<DependencyInfo>,
    package_inventory: bool,
    findings_only: bool,
    declared_unresolved: bool,
) -> (Vec<DependencyInfo>, Option<&'static str>) {
    let declared_count = declared.len();
    let merged = merge_dependencies(scanner, declared);
    let signal = verdict(&SourceSignal {
        package_inventory,
        findings_only,
        declared: declared_count,
        declared_unresolved,
    })
    .to_signal();
    (merged, signal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::maven::MavenHandler;

    fn dep(name: &str, version: Option<&str>, purl: Option<&str>) -> DependencyInfo {
        DependencyInfo {
            name: name.to_string(),
            version: version.map(|s| s.to_string()),
            purl: purl.map(|s| s.to_string()),
            license: None,
            sha256: None,
        }
    }

    // ---- InventoryCompleteness ----

    #[test]
    fn completeness_as_str() {
        assert_eq!(InventoryCompleteness::Complete.as_str(), "complete");
        assert_eq!(InventoryCompleteness::Declared.as_str(), "declared");
        assert_eq!(InventoryCompleteness::Partial.as_str(), "partial");
        assert_eq!(InventoryCompleteness::None.as_str(), "none");
    }

    #[test]
    fn complete_maps_to_none_signal_to_preserve_cache() {
        // Complete must produce None so existing complete SBOMs hash
        // identically and their content-hash cache stays valid.
        assert_eq!(InventoryCompleteness::Complete.to_signal(), None);
        assert_eq!(
            InventoryCompleteness::Declared.to_signal(),
            Some("declared")
        );
        assert_eq!(InventoryCompleteness::Partial.to_signal(), Some("partial"));
        assert_eq!(InventoryCompleteness::None.to_signal(), Some("none"));
    }

    // ---- verdict ----

    #[test]
    fn verdict_scanner_inventory_is_complete() {
        let s = SourceSignal {
            package_inventory: true,
            declared: 5,
            ..Default::default()
        };
        assert_eq!(verdict(&s), InventoryCompleteness::Complete);
    }

    #[test]
    fn verdict_findings_only_is_partial() {
        let s = SourceSignal {
            findings_only: true,
            declared: 3,
            ..Default::default()
        };
        assert_eq!(verdict(&s), InventoryCompleteness::Partial);
    }

    #[test]
    fn verdict_no_sources_is_none() {
        assert_eq!(
            verdict(&SourceSignal::default()),
            InventoryCompleteness::None
        );
    }

    #[test]
    fn verdict_declared_only_is_declared() {
        let s = SourceSignal {
            declared: 4,
            ..Default::default()
        };
        assert_eq!(verdict(&s), InventoryCompleteness::Declared);
    }

    #[test]
    fn verdict_declared_with_unresolved_is_partial() {
        let s = SourceSignal {
            declared: 4,
            declared_unresolved: true,
            ..Default::default()
        };
        assert_eq!(verdict(&s), InventoryCompleteness::Partial);
    }

    // ---- is_resolved_version / maven_purl ----

    #[test]
    fn resolved_version_detection() {
        assert!(is_resolved_version("1.2.3"));
        assert!(!is_resolved_version(""));
        assert!(!is_resolved_version("${project.version}"));
        assert!(!is_resolved_version("${foo.bar}-SNAPSHOT"));
    }

    #[test]
    fn maven_purl_happy_path() {
        assert_eq!(
            maven_purl("com.google.guava", "guava", Some("32.1.3-jre")),
            Some("pkg:maven/com.google.guava/guava@32.1.3-jre".to_string())
        );
    }

    #[test]
    fn maven_purl_rejects_empty_or_unresolved() {
        assert_eq!(maven_purl("", "guava", Some("1.0")), None);
        assert_eq!(maven_purl("g", "", Some("1.0")), None);
        assert_eq!(maven_purl("g", "a", None), None);
        assert_eq!(maven_purl("g", "a", Some("${v}")), None);
    }

    // ---- interpolate_pom_value ----

    fn parse(pom: &str) -> PomProject {
        MavenHandler::parse_pom(pom.as_bytes()).expect("pom parses")
    }

    #[test]
    fn interpolate_passes_through_plain_value() {
        let pom = parse("<project><version>1.0</version></project>");
        assert_eq!(interpolate_pom_value("4.17.21", &pom), "4.17.21");
    }

    #[test]
    fn interpolate_resolves_project_version() {
        let pom = parse("<project><version>2.5.0</version></project>");
        assert_eq!(interpolate_pom_value("${project.version}", &pom), "2.5.0");
    }

    #[test]
    fn interpolate_resolves_property() {
        let pom = parse(
            "<project><version>1.0</version>\
             <properties><spring.version>6.1.2</spring.version></properties></project>",
        );
        assert_eq!(interpolate_pom_value("${spring.version}", &pom), "6.1.2");
    }

    #[test]
    fn interpolate_leaves_unknown_placeholder_intact() {
        let pom = parse("<project><version>1.0</version></project>");
        assert_eq!(
            interpolate_pom_value("${unknown.prop}", &pom),
            "${unknown.prop}"
        );
    }

    // ---- maven_deps_from_pom ----

    #[test]
    fn maven_pom_extracts_direct_deps_with_purls() {
        let pom = parse(
            "<project><groupId>com.example</groupId><artifactId>app</artifactId>\
             <version>1.0.0</version>\
             <dependencies>\
               <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.3-jre</version></dependency>\
             </dependencies></project>",
        );
        let deps = maven_deps_from_pom(&pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(deps[0].version.as_deref(), Some("32.1.3-jre"));
        assert_eq!(
            deps[0].purl.as_deref(),
            Some("pkg:maven/com.google.guava/guava@32.1.3-jre")
        );
    }

    #[test]
    fn maven_pom_excludes_test_scope() {
        let pom = parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <dependencies>\
               <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>5.10.0</version><scope>test</scope></dependency>\
               <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.3-jre</version></dependency>\
             </dependencies></project>",
        );
        let deps = maven_deps_from_pom(&pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "com.google.guava:guava");
    }

    #[test]
    fn maven_pom_resolves_property_version() {
        let pom = parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <properties><guava.version>32.1.3-jre</guava.version></properties>\
             <dependencies>\
               <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>${guava.version}</version></dependency>\
             </dependencies></project>",
        );
        let deps = maven_deps_from_pom(&pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version.as_deref(), Some("32.1.3-jre"));
        assert_eq!(
            deps[0].purl.as_deref(),
            Some("pkg:maven/com.google.guava/guava@32.1.3-jre")
        );
    }

    #[test]
    fn maven_pom_managed_version_emits_none_and_no_purl() {
        // No <version> means the version is managed by a parent/BOM we do not
        // fetch. Emit the dependency with a null version rather than dropping it.
        let pom = parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>\
             <dependencies>\
               <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId></dependency>\
             </dependencies></project>",
        );
        let deps = maven_deps_from_pom(&pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "org.springframework:spring-core");
        assert_eq!(deps[0].version, None);
        assert_eq!(deps[0].purl, None);
    }

    #[test]
    fn maven_pom_no_dependencies_is_empty() {
        let pom = parse(
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>",
        );
        assert!(maven_deps_from_pom(&pom).is_empty());
    }

    // ---- maven_deps_from_metadata ----

    #[test]
    fn maven_metadata_extracts_deps() {
        let meta = serde_json::json!([
            {"groupId": "com.google.guava", "artifactId": "guava", "version": "32.1.3-jre"},
            {"groupId": "org.junit.jupiter", "artifactId": "junit-jupiter", "version": "5.10.0", "scope": "test"}
        ]);
        let deps = maven_deps_from_metadata(&meta);
        assert_eq!(deps.len(), 1, "test scope excluded");
        assert_eq!(deps[0].name, "com.google.guava:guava");
        assert_eq!(
            deps[0].purl.as_deref(),
            Some("pkg:maven/com.google.guava/guava@32.1.3-jre")
        );
    }

    #[test]
    fn maven_metadata_unresolved_version_has_none_and_no_purl() {
        let meta = serde_json::json!([
            {"groupId": "g", "artifactId": "a", "version": "${some.version}"}
        ]);
        let deps = maven_deps_from_metadata(&meta);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, None);
        assert_eq!(deps[0].purl, None);
    }

    #[test]
    fn maven_metadata_non_array_is_empty() {
        assert!(maven_deps_from_metadata(&serde_json::json!({"x": 1})).is_empty());
        assert!(maven_deps_from_metadata(&serde_json::Value::Null).is_empty());
    }

    #[test]
    fn maven_metadata_has_unresolved_detects_placeholder() {
        let resolved = serde_json::json!([{"groupId":"g","artifactId":"a","version":"1.0"}]);
        let unresolved = serde_json::json!([{"groupId":"g","artifactId":"a","version":"${v}"}]);
        assert!(!maven_metadata_has_unresolved(&resolved));
        assert!(maven_metadata_has_unresolved(&unresolved));
    }

    // ---- npm_deps_from_version_data ----

    #[test]
    fn npm_extracts_deps_excludes_dev() {
        let vd = serde_json::json!({
            "name": "my-pkg",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.21", "axios": "1.6.0"},
            "devDependencies": {"vitest": "^1.0.0"}
        });
        let deps = npm_deps_from_version_data(&vd);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"axios"));
        assert!(!names.contains(&"vitest"), "devDependencies excluded");
    }

    #[test]
    fn npm_emits_range_as_version_without_purl() {
        let vd = serde_json::json!({"dependencies": {"lodash": "^4.17.21"}});
        let deps = npm_deps_from_version_data(&vd);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version.as_deref(), Some("^4.17.21"));
        assert_eq!(deps[0].purl, None, "range is not a pinned version");
    }

    #[test]
    fn npm_includes_optional_dependencies() {
        let vd = serde_json::json!({
            "dependencies": {"a": "1.0.0"},
            "optionalDependencies": {"b": "2.0.0"}
        });
        let deps = npm_deps_from_version_data(&vd);
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn npm_no_deps_is_empty() {
        assert!(npm_deps_from_version_data(&serde_json::json!({"name": "x"})).is_empty());
    }

    // ---- helm_deps_from_chart ----

    #[test]
    fn helm_extracts_chart_dependencies() {
        let chart = serde_json::json!({
            "name": "my-chart",
            "version": "1.0.0",
            "dependencies": [
                {"name": "postgresql", "version": "12.1.2", "repository": "https://charts.bitnami.com/bitnami"},
                {"name": "redis", "version": "17.0.0"}
            ]
        });
        let deps = helm_deps_from_chart(&chart);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "postgresql");
        assert_eq!(deps[0].version.as_deref(), Some("12.1.2"));
        assert_eq!(deps[0].purl, None);
    }

    #[test]
    fn helm_no_dependencies_is_empty() {
        assert!(helm_deps_from_chart(&serde_json::json!({"name": "c"})).is_empty());
    }

    // ---- merge_dependencies ----

    #[test]
    fn merge_dedupes_by_purl_scanner_wins() {
        let scanner = vec![dep(
            "com.google.guava:guava",
            Some("32.1.3-jre"),
            Some("pkg:maven/com.google.guava/guava@32.1.3-jre"),
        )];
        let declared = vec![dep(
            "com.google.guava:guava",
            Some("32.1.3-jre"),
            Some("pkg:maven/com.google.guava/guava@32.1.3-jre"),
        )];
        let merged = merge_dependencies(scanner, declared);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn merge_keeps_declared_not_seen_by_scanner() {
        let scanner = vec![dep("a", Some("1.0"), Some("pkg:maven/x/a@1.0"))];
        let declared = vec![
            dep("a", Some("1.0"), Some("pkg:maven/x/a@1.0")), // dup
            dep("b", Some("2.0"), Some("pkg:maven/x/b@2.0")), // new
        ];
        let merged = merge_dependencies(scanner, declared);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].name, "a");
        assert_eq!(merged[1].name, "b");
    }

    #[test]
    fn merge_dedupes_by_name_version_when_no_purl() {
        let scanner = vec![dep("lodash", Some("^4.17.21"), None)];
        let declared = vec![dep("lodash", Some("^4.17.21"), None)];
        let merged = merge_dependencies(scanner, declared);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn merge_distinguishes_same_name_different_version() {
        let scanner = vec![dep("lodash", Some("4.17.21"), None)];
        let declared = vec![dep("lodash", Some("^4.0.0"), None)];
        let merged = merge_dependencies(scanner, declared);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_empty_inputs() {
        assert!(merge_dependencies(vec![], vec![]).is_empty());
    }

    // ---- declared_deps_from_manifest ----

    #[test]
    fn manifest_maven_reads_dependencies_and_flags_unresolved() {
        let meta = serde_json::json!({
            "dependencies": [
                {"groupId": "com.google.guava", "artifactId": "guava", "version": "32.1.3-jre"},
                {"groupId": "g", "artifactId": "managed"}
            ]
        });
        let (deps, unresolved) = declared_deps_from_manifest("maven", &meta);
        assert_eq!(deps.len(), 2);
        assert!(unresolved, "a missing/managed version flags unresolved");
    }

    #[test]
    fn manifest_maven_case_insensitive_format() {
        let meta = serde_json::json!({
            "dependencies": [{"groupId": "g", "artifactId": "a", "version": "1.0"}]
        });
        let (deps, unresolved) = declared_deps_from_manifest("Maven", &meta);
        assert_eq!(deps.len(), 1);
        assert!(!unresolved);
    }

    #[test]
    fn manifest_npm_reads_version_data() {
        let meta = serde_json::json!({
            "version_data": {"dependencies": {"lodash": "^4.17.21"}}
        });
        let (deps, unresolved) = declared_deps_from_manifest("npm", &meta);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "lodash");
        assert!(!unresolved);
    }

    #[test]
    fn manifest_helm_reads_chart_dependencies() {
        let meta = serde_json::json!({
            "chart": {"dependencies": [{"name": "redis", "version": "17.0.0"}]}
        });
        let (deps, _) = declared_deps_from_manifest("helm", &meta);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "redis");
    }

    #[test]
    fn manifest_unknown_format_is_empty() {
        let (deps, unresolved) =
            declared_deps_from_manifest("cargo", &serde_json::json!({"dependencies": []}));
        assert!(deps.is_empty());
        assert!(!unresolved);
    }

    #[test]
    fn manifest_missing_keys_are_empty() {
        assert!(declared_deps_from_manifest("maven", &serde_json::json!({}))
            .0
            .is_empty());
        assert!(declared_deps_from_manifest("npm", &serde_json::json!({}))
            .0
            .is_empty());
        assert!(declared_deps_from_manifest("helm", &serde_json::json!({}))
            .0
            .is_empty());
    }

    // ---- assemble_dependencies ----

    #[test]
    fn assemble_scanner_inventory_is_complete_signal_none() {
        let scanner = vec![dep("a", Some("1.0"), Some("pkg:maven/x/a@1.0"))];
        let (merged, signal) = assemble_dependencies(scanner, vec![], true, false, false);
        assert_eq!(merged.len(), 1);
        assert_eq!(signal, None, "complete maps to None to preserve cache");
    }

    #[test]
    fn assemble_declared_only_is_declared_signal() {
        let declared = vec![dep("com.x:a", Some("1.0"), Some("pkg:maven/com.x/a@1.0"))];
        let (merged, signal) = assemble_dependencies(vec![], declared, false, false, false);
        assert_eq!(merged.len(), 1);
        assert_eq!(signal, Some("declared"));
    }

    #[test]
    fn assemble_merges_and_dedupes_then_signals() {
        let scanner = vec![dep("a", Some("1.0"), Some("pkg:maven/x/a@1.0"))];
        let declared = vec![
            dep("a", Some("1.0"), Some("pkg:maven/x/a@1.0")), // dup
            dep("com.x:b", None, None),                       // new
        ];
        let (merged, signal) = assemble_dependencies(scanner, declared, true, false, true);
        assert_eq!(merged.len(), 2, "duplicate collapsed");
        // package_inventory present, so verdict is complete regardless of unresolved.
        assert_eq!(signal, None);
    }

    #[test]
    fn assemble_no_sources_is_none_signal() {
        let (merged, signal) = assemble_dependencies(vec![], vec![], false, false, false);
        assert!(merged.is_empty());
        assert_eq!(signal, Some("none"));
    }
}
