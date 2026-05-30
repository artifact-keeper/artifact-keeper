//! Format-aware parser for artifact name and version, derived from the
//! source filename (and path, for formats where the filename is ambiguous).
//!
//! Used by the migration worker (`migration_worker::transfer_artifact`) to
//! populate `artifacts.name` and `artifacts.version` correctly when ingesting
//! from external registries. Without this, every artifact would be stored
//! with its full filename in the `name` column and an empty `version`, which
//! breaks per-format index endpoints (e.g. PyPI `simple/`, Helm `index.yaml`,
//! npm metadata) since those endpoints group by canonical package name and
//! require a version.

/// Parsed artifact identity. `name` is always populated; `version` is `None`
/// when the format/filename combination doesn't expose a parseable version
/// (in which case the caller should still INSERT the row but leave
/// `artifacts.version` NULL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArtifact {
    pub name: String,
    pub version: Option<String>,
}

/// Parse `(name, version)` from a source artifact's filename and path,
/// using the destination repository's package format to choose the parser.
///
/// `package_type` is matched case-insensitively against the canonical format
/// keys (e.g. `"pypi"`, `"helm"`, `"npm"`, `"maven"`). Unknown formats fall
/// back to the legacy behaviour of using the filename as the name with no
/// version, which preserves backward compatibility for formats whose parser
/// hasn't been written yet.
///
/// `artifact_path` is the source-side path (e.g.
/// `"airflow_aws_batch/0.0.4/airflow_aws_batch-0.0.4-py3-none-any.whl"`).
/// `filename` should be the last path segment.
pub fn parse_name_and_version(
    package_type: &str,
    filename: &str,
    artifact_path: &str,
) -> ParsedArtifact {
    let pt = package_type.to_lowercase();
    match pt.as_str() {
        "pypi" | "poetry" | "conda" => parse_pypi(filename, artifact_path),
        "helm" | "helm_oci" => parse_helm(filename),
        "npm" | "yarn" | "pnpm" | "bower" => parse_npm(filename, artifact_path),
        "maven" | "gradle" | "sbt" | "ivy" => parse_maven(filename, artifact_path),
        _ => fallback(filename),
    }
}

/// Extract format-specific package metadata from the artifact bytes.
///
/// Returns the JSON document the caller should store in
/// `artifact_metadata.metadata` (under the `version_data` key for npm,
/// `chart` for helm, `metadata` for PyPI). Returns `None` when the format
/// is unsupported or the bytes don't contain extractable metadata.
///
/// Used by the migration worker so that downstream per-format endpoints
/// (npm package metadata, helm `index.yaml`, PyPI simple index) can
/// surface real `dependencies`, `appVersion`, etc. instead of `null`.
/// Without this, npm clients see empty dep lists for migrated packages
/// and don't install transitive dependencies — exposed concretely on a
/// 6,227-row migration where `pip install` and `npm install` succeeded
/// for direct deps but transitive resolution broke whenever a Careem-
/// internal package depended on something else.
pub fn extract_artifact_metadata(
    package_type: &str,
    artifact_data: &[u8],
) -> Option<serde_json::Value> {
    match package_type.to_lowercase().as_str() {
        "npm" | "yarn" | "pnpm" | "bower" => extract_npm_metadata(artifact_data),
        "helm" | "helm_oci" => extract_helm_metadata(artifact_data),
        _ => None,
    }
}

/// Extract format-specific package metadata by reading from a file on disk.
///
/// Same semantics as `extract_artifact_metadata` but accepts a path instead
/// of an in-memory slice. The migration worker uses this after streaming an
/// artifact to a temp file so it never has to re-buffer the full artifact
/// in memory (issue #1422). For formats with no metadata extractor
/// (anything other than npm/helm today) this returns `None` without opening
/// the file at all.
pub fn extract_artifact_metadata_from_path(
    package_type: &str,
    path: &std::path::Path,
) -> Option<serde_json::Value> {
    let pt = package_type.to_lowercase();
    let needs_read = matches!(
        pt.as_str(),
        "npm" | "yarn" | "pnpm" | "bower" | "helm" | "helm_oci"
    );
    if !needs_read {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let reader = std::io::BufReader::new(file);
    match pt.as_str() {
        "npm" | "yarn" | "pnpm" | "bower" => extract_npm_metadata_reader(reader),
        "helm" | "helm_oci" => extract_helm_metadata_reader(reader),
        _ => None,
    }
}

/// Extract npm package metadata from a `.tgz` tarball.
///
/// Reads the first `package.json` found inside the gzipped tar. The
/// returned JSON value is wrapped under the `version_data` key — that's
/// the projection AK's npm metadata builder reads at
/// `GET /npm/<repo>/<package>` (see `handlers::npm::build_npm_metadata_response`),
/// where `version_data.dependencies` flows through to clients verbatim.
fn extract_npm_metadata(artifact_data: &[u8]) -> Option<serde_json::Value> {
    extract_npm_metadata_reader(artifact_data)
}

fn extract_npm_metadata_reader<R: std::io::Read>(reader: R) -> Option<serde_json::Value> {
    use std::io::Read;
    let gz = flate2::read::GzDecoder::new(reader);
    let mut tar = tar::Archive::new(gz);
    let entries = tar.entries().ok()?;
    for entry in entries.flatten() {
        let path = entry.path().ok()?;
        let name = path.to_string_lossy();
        // Most npm tarballs use the `package/` prefix, but some publish
        // tools put the actual package name first or omit the prefix
        // entirely. Match any path ending in `/package.json` or the bare
        // `package.json` at the root.
        if name == "package.json" || name.ends_with("/package.json") {
            // Drop the moved entry — re-iterate is messy with `tar`'s
            // Read-once entries iterator, so capture the bytes here.
            drop(name);
            drop(path);
            let mut buf = String::new();
            let mut e = entry;
            e.read_to_string(&mut buf).ok()?;
            let pkg: serde_json::Value = serde_json::from_str(&buf).ok()?;
            return Some(serde_json::json!({ "version_data": pkg }));
        }
    }
    None
}

/// Extract helm chart metadata from a `.tgz` tarball.
///
/// Reads the first `Chart.yaml` found inside the gzipped tar. AK's helm
/// `index_yaml` builder reads `metadata.chart` and falls back to other
/// known fields; we store the parsed YAML under both `chart` (for full
/// fidelity) and a couple of flat fields (`description`, `appVersion`)
/// matching what the index builder probes individually.
fn extract_helm_metadata(artifact_data: &[u8]) -> Option<serde_json::Value> {
    extract_helm_metadata_reader(artifact_data)
}

fn extract_helm_metadata_reader<R: std::io::Read>(reader: R) -> Option<serde_json::Value> {
    use std::io::Read;
    let gz = flate2::read::GzDecoder::new(reader);
    let mut tar = tar::Archive::new(gz);
    let entries = tar.entries().ok()?;
    for entry in entries.flatten() {
        let path = entry.path().ok()?;
        let name = path.to_string_lossy();
        if name == "Chart.yaml" || name.ends_with("/Chart.yaml") {
            drop(name);
            drop(path);
            let mut buf = String::new();
            let mut e = entry;
            e.read_to_string(&mut buf).ok()?;
            let chart: serde_json::Value = serde_yaml::from_str(&buf).ok()?;
            let description = chart
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from);
            let app_version = chart
                .get("appVersion")
                .and_then(|v| v.as_str())
                .map(String::from);
            let mut wrapper = serde_json::json!({ "chart": chart });
            if let Some(d) = description {
                wrapper["description"] = serde_json::Value::String(d);
            }
            if let Some(a) = app_version {
                wrapper["appVersion"] = serde_json::Value::String(a);
            }
            return Some(wrapper);
        }
    }
    None
}

fn fallback(filename: &str) -> ParsedArtifact {
    ParsedArtifact {
        name: filename.to_string(),
        version: None,
    }
}

// ---------------------------------------------------------------------------
// PyPI
// ---------------------------------------------------------------------------

/// PyPI parser. Wheels follow PEP 427:
/// `{distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl`.
/// Source distributions are `{name}-{version}.tar.gz` (or `.zip`).
///
/// Falls back to JFrog-style path layout
/// `<repo>/<package>/<version>/<filename>` if the filename can't be parsed
/// (e.g. dev-version with non-canonical separators).
fn parse_pypi(filename: &str, artifact_path: &str) -> ParsedArtifact {
    if filename.ends_with(".whl") {
        let stem = filename.trim_end_matches(".whl");
        let parts: Vec<&str> = stem.split('-').collect();
        if parts.len() >= 5 {
            return ParsedArtifact {
                name: parts[0].to_string(),
                version: Some(parts[1].to_string()),
            };
        }
    } else if filename.ends_with(".tar.gz") || filename.ends_with(".zip") {
        let stem = filename
            .trim_end_matches(".tar.gz")
            .trim_end_matches(".zip");
        // sdist format: `<name>-<version>` — version is the trailing token
        // separated by the rightmost `-` that precedes a digit-led component.
        if let Some((name, version)) = rsplit_name_version(stem) {
            return ParsedArtifact {
                name,
                version: Some(version),
            };
        }
    }
    parse_from_path_segments(artifact_path).unwrap_or_else(|| fallback(filename))
}

// ---------------------------------------------------------------------------
// Helm
// ---------------------------------------------------------------------------

/// Helm chart filename parser. Charts follow `<chart>-<version>.tgz` per the
/// Helm packaging convention. We accept versions starting with `v` (common
/// in Careem's internal naming) and fall back to `<name>` with no version
/// when the filename is just `<chart>.tgz` (some charts in older registries
/// don't encode the version in the filename and rely on path layout — those
/// require a different reconciliation step that's out of scope here).
fn parse_helm(filename: &str) -> ParsedArtifact {
    if let Some(stem) = filename.strip_suffix(".tgz") {
        if let Some((name, version)) = rsplit_name_version(stem) {
            return ParsedArtifact {
                name,
                version: Some(version),
            };
        }
        return ParsedArtifact {
            name: stem.to_string(),
            version: None,
        };
    }
    fallback(filename)
}

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------

/// npm tarballs are `<name>-<version>.tgz` for unscoped packages, or
/// `@scope/<name>/-/<name>-<version>.tgz` in JFrog's storage layout. The
/// scope is recovered from the path when present.
fn parse_npm(filename: &str, artifact_path: &str) -> ParsedArtifact {
    let (base_name, version) = if let Some(stem) = filename.strip_suffix(".tgz") {
        match rsplit_name_version(stem) {
            Some((n, v)) => (n, Some(v)),
            None => (stem.to_string(), None),
        }
    } else {
        return fallback(filename);
    };

    // Recover scope (e.g. "@careem") from the path when present — JFrog
    // stores scoped npm tarballs under `<scope>/<name>/-/<name>-<version>.tgz`.
    if let Some(scope) = artifact_path.split('/').find(|seg| seg.starts_with('@')) {
        return ParsedArtifact {
            name: format!("{}/{}", scope, base_name),
            version,
        };
    }
    ParsedArtifact {
        name: base_name,
        version,
    }
}

// ---------------------------------------------------------------------------
// Maven
// ---------------------------------------------------------------------------

/// Maven path layout is GAV-canonical:
/// `<group as path>/<artifactId>/<version>/<artifactId>-<version>(-classifier)?.<ext>`.
/// Group and artifactId come from path segments; version comes from the
/// segment immediately before the filename. The artifact "name" stored in
/// Artifact Keeper is the artifactId (without the group); callers that need
/// the GAV can reconstruct it from the path + name + version.
fn parse_maven(filename: &str, artifact_path: &str) -> ParsedArtifact {
    let segs: Vec<&str> = artifact_path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() >= 3 {
        let version = segs[segs.len() - 2].to_string();
        let artifact_id = segs[segs.len() - 3].to_string();
        return ParsedArtifact {
            name: artifact_id,
            version: Some(version),
        };
    }
    fallback(filename)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Split `<name>-<version>` by the rightmost hyphen that precedes a
/// version-shaped token (digit, optional leading `v`). Returns `None` if no
/// such split exists.
fn rsplit_name_version(stem: &str) -> Option<(String, String)> {
    // Walk hyphens right-to-left until we find one whose RHS begins with a
    // version-ish token.
    let bytes = stem.as_bytes();
    let mut i = bytes.len();
    while let Some(pos) = stem[..i].rfind('-') {
        let candidate = &stem[pos + 1..];
        if looks_like_version(candidate) {
            return Some((stem[..pos].to_string(), candidate.to_string()));
        }
        i = pos;
    }
    None
}

/// True if `s` looks like the start of a PEP 440 / SemVer / Helm-style version:
/// optional leading `v`, then a digit.
fn looks_like_version(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if first == 'v' || first == 'V' {
        return chars.next().is_some_and(|c| c.is_ascii_digit());
    }
    first.is_ascii_digit()
}

/// JFrog-style fallback: `<repo>/<package>/<version>/<filename>` (4 segments).
fn parse_from_path_segments(artifact_path: &str) -> Option<ParsedArtifact> {
    let segs: Vec<&str> = artifact_path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() >= 3 {
        // `<package>/<version>/<filename>` (when artifact_path is repo-relative)
        let pkg = segs[segs.len() - 3].to_string();
        let ver = segs[segs.len() - 2].to_string();
        if !pkg.is_empty() && !ver.is_empty() {
            return Some(ParsedArtifact {
                name: pkg,
                version: Some(ver),
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pypi_wheel() {
        let p = parse_name_and_version(
            "pypi",
            "airflow_aws_batch-0.0.4-py3-none-any.whl",
            "airflow_aws_batch/0.0.4/airflow_aws_batch-0.0.4-py3-none-any.whl",
        );
        assert_eq!(p.name, "airflow_aws_batch");
        assert_eq!(p.version.as_deref(), Some("0.0.4"));
    }

    #[test]
    fn pypi_sdist_targz() {
        let p = parse_name_and_version(
            "pypi",
            "care_nlp-1.0.9.tar.gz",
            "care_nlp/1.0.9/care_nlp-1.0.9.tar.gz",
        );
        assert_eq!(p.name, "care_nlp");
        assert_eq!(p.version.as_deref(), Some("1.0.9"));
    }

    #[test]
    fn pypi_sdist_dev_version_falls_back_to_path() {
        // Dev versions like "0.0.2.devHEXSHA" don't satisfy looks_like_version
        // for the rsplit because the version contains underscores/letters at
        // the start of subcomponents — but the path still works.
        let p = parse_name_and_version(
            "pypi",
            "airflow_aws_batch-0.0.2.dev3a99a40b.tar.gz",
            "airflow_aws_batch/0.0.2.dev3a99a40b/airflow_aws_batch-0.0.2.dev3a99a40b.tar.gz",
        );
        assert_eq!(p.name, "airflow_aws_batch");
        assert_eq!(p.version.as_deref(), Some("0.0.2.dev3a99a40b"));
    }

    #[test]
    fn helm_chart_with_v_prefix() {
        let p = parse_name_and_version(
            "helm",
            "careem-service-v1.9.1.tgz",
            "careem-service/v1.9.1/careem-service-v1.9.1.tgz",
        );
        assert_eq!(p.name, "careem-service");
        assert_eq!(p.version.as_deref(), Some("v1.9.1"));
    }

    #[test]
    fn helm_chart_plain_version() {
        let p = parse_name_and_version(
            "helm",
            "nginx-ingress-controller-1.41.3.tgz",
            "nginx-ingress-controller/1.41.3/nginx-ingress-controller-1.41.3.tgz",
        );
        assert_eq!(p.name, "nginx-ingress-controller");
        assert_eq!(p.version.as_deref(), Some("1.41.3"));
    }

    #[test]
    fn helm_chart_no_version_in_filename() {
        // Some charts in older registries are stored as just `<chart>.tgz`
        // and rely on the path for version. We surface name without version
        // here; a separate path-based reconciliation step handles those.
        let p = parse_name_and_version("helm", "airflow.tgz", "1.7.90/airflow.tgz");
        assert_eq!(p.name, "airflow");
        assert_eq!(p.version, None);
    }

    #[test]
    fn npm_unscoped() {
        let p = parse_name_and_version("npm", "lodash-4.17.21.tgz", "lodash/-/lodash-4.17.21.tgz");
        assert_eq!(p.name, "lodash");
        assert_eq!(p.version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn npm_scoped() {
        let p = parse_name_and_version(
            "npm",
            "logger-2.3.0.tgz",
            "@careem/logger/-/logger-2.3.0.tgz",
        );
        assert_eq!(p.name, "@careem/logger");
        assert_eq!(p.version.as_deref(), Some("2.3.0"));
    }

    #[test]
    fn maven_jar() {
        let p = parse_name_and_version(
            "maven",
            "guava-31.1-jre.jar",
            "com/google/guava/guava/31.1-jre/guava-31.1-jre.jar",
        );
        assert_eq!(p.name, "guava");
        assert_eq!(p.version.as_deref(), Some("31.1-jre"));
    }

    #[test]
    fn unknown_format_falls_back() {
        let p = parse_name_and_version("rpm", "blah-1.2.3.rpm", "x/y/blah-1.2.3.rpm");
        assert_eq!(p.name, "blah-1.2.3.rpm");
        assert_eq!(p.version, None);
    }

    #[test]
    fn case_insensitive_format() {
        let p = parse_name_and_version("PyPI", "lib-1.0.0.tar.gz", "lib/1.0.0/lib-1.0.0.tar.gz");
        assert_eq!(p.name, "lib");
        assert_eq!(p.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn looks_like_version_smoke() {
        assert!(looks_like_version("1.0.0"));
        assert!(looks_like_version("v1.0.0"));
        assert!(looks_like_version("0"));
        assert!(!looks_like_version(""));
        assert!(!looks_like_version("alpha"));
        assert!(!looks_like_version("v"));
    }

    // -----------------------------------------------------------------
    // extract_artifact_metadata
    // -----------------------------------------------------------------

    /// Build a minimal `.tgz` containing a single file at the given path
    /// with the given contents — used by the metadata-extraction tests
    /// without needing a fixture file on disk.
    fn make_tgz(path: &str, contents: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut tar_buf: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_buf).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn extract_npm_metadata_with_package_prefix() {
        let pkg_json =
            br#"{"name":"@careem/foo","version":"1.2.3","dependencies":{"lodash":"^4.0.0"}}"#;
        let tgz = make_tgz("package/package.json", pkg_json);
        let meta = extract_artifact_metadata("npm", &tgz).expect("metadata");
        let vd = meta.get("version_data").expect("version_data key");
        assert_eq!(vd.get("name").and_then(|v| v.as_str()), Some("@careem/foo"));
        assert_eq!(vd.get("version").and_then(|v| v.as_str()), Some("1.2.3"));
        assert_eq!(
            vd.pointer("/dependencies/lodash").and_then(|v| v.as_str()),
            Some("^4.0.0"),
        );
    }

    #[test]
    fn extract_npm_metadata_with_named_prefix() {
        // Some publish tools use `<package>/package.json` instead of
        // `package/package.json`. Both should work.
        let pkg_json = br#"{"name":"my-pkg","version":"0.1.0"}"#;
        let tgz = make_tgz("my-pkg/package.json", pkg_json);
        let meta = extract_artifact_metadata("npm", &tgz).expect("metadata");
        assert_eq!(
            meta.pointer("/version_data/name").and_then(|v| v.as_str()),
            Some("my-pkg"),
        );
    }

    #[test]
    fn extract_npm_metadata_returns_none_when_no_package_json() {
        let tgz = make_tgz("package/README.md", b"hello");
        let meta = extract_artifact_metadata("npm", &tgz);
        assert!(meta.is_none());
    }

    #[test]
    fn extract_helm_metadata() {
        let chart_yaml = b"apiVersion: v2\nname: careem-service\nversion: v1.9.1\nappVersion: \"1.0.0\"\ndescription: Careem service chart\n";
        let tgz = make_tgz("careem-service/Chart.yaml", chart_yaml);
        let meta = extract_artifact_metadata("helm", &tgz).expect("metadata");
        assert_eq!(
            meta.pointer("/chart/name").and_then(|v| v.as_str()),
            Some("careem-service"),
        );
        assert_eq!(
            meta.pointer("/chart/version").and_then(|v| v.as_str()),
            Some("v1.9.1"),
        );
        assert_eq!(
            meta.get("description").and_then(|v| v.as_str()),
            Some("Careem service chart"),
        );
        assert_eq!(
            meta.get("appVersion").and_then(|v| v.as_str()),
            Some("1.0.0"),
        );
    }

    #[test]
    fn extract_metadata_unknown_format_returns_none() {
        let tgz = make_tgz("package/package.json", br#"{"name":"x","version":"0.0.0"}"#);
        assert!(extract_artifact_metadata("rpm", &tgz).is_none());
        assert!(extract_artifact_metadata("docker", &tgz).is_none());
    }

    #[test]
    fn extract_metadata_handles_invalid_bytes() {
        // Garbage bytes shouldn't panic — just return None.
        let garbage = b"not a tarball";
        assert!(extract_artifact_metadata("npm", garbage).is_none());
        assert!(extract_artifact_metadata("helm", garbage).is_none());
    }
}
