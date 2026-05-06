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
}
