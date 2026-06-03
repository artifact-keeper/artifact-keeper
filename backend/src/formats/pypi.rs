//! PyPI format handler.
//!
//! Implements PEP 503 Simple Repository API for Python packages.
//! Supports wheel (.whl) and source distribution (.tar.gz) files.

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use tar::Archive;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// PyPI format handler
pub struct PypiHandler;

impl PypiHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse PyPI package path
    /// Formats:
    ///   simple/<package>/                    - Package index
    ///   simple/                              - Root index
    ///   packages/<package>/<version>/<filename> - Package file
    ///   <package>/<filename>                 - Direct package file
    pub fn parse_path(path: &str) -> Result<PypiPackageInfo> {
        let path = path.trim_start_matches('/');

        // Root simple index
        if path == "simple" || path == "simple/" {
            return Ok(PypiPackageInfo {
                name: None,
                version: None,
                filename: None,
                is_simple_index: true,
                is_package_index: false,
            });
        }

        // Package simple index: simple/<package>/
        if let Some(rest) = path.strip_prefix("simple/") {
            let parts: Vec<&str> = rest.trim_end_matches('/').split('/').collect();
            if parts.len() == 1 && !parts[0].is_empty() {
                return Ok(PypiPackageInfo {
                    name: Some(Self::normalize_name(parts[0])),
                    version: None,
                    filename: None,
                    is_simple_index: false,
                    is_package_index: true,
                });
            }
        }

        // Package file: packages/<package>/<version>/<filename>
        if let Some(rest) = path.strip_prefix("packages/") {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 3 {
                let name = Self::normalize_name(parts[0]);
                let version = parts[1].to_string();
                let filename = parts[2..].join("/");
                return Ok(PypiPackageInfo {
                    name: Some(name),
                    version: Some(version),
                    filename: Some(filename),
                    is_simple_index: false,
                    is_package_index: false,
                });
            }
        }

        // Direct package file with wheel or sdist
        if path.ends_with(".whl") || path.ends_with(".tar.gz") || path.ends_with(".zip") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            let info = Self::parse_filename(filename)?;
            return Ok(info);
        }

        Err(AppError::Validation(format!(
            "Invalid PyPI path format: {}",
            path
        )))
    }

    /// Parse wheel or sdist filename to extract metadata
    pub fn parse_filename(filename: &str) -> Result<PypiPackageInfo> {
        if filename.ends_with(".whl") {
            Self::parse_wheel_filename(filename)
        } else if filename.ends_with(".tar.gz") {
            Self::parse_sdist_filename(filename)
        } else if filename.ends_with(".zip") {
            Self::parse_sdist_zip_filename(filename)
        } else {
            Err(AppError::Validation(format!(
                "Unknown Python package format: {}",
                filename
            )))
        }
    }

    /// Parse wheel filename according to PEP 427
    /// Format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
    fn parse_wheel_filename(filename: &str) -> Result<PypiPackageInfo> {
        let name = filename.trim_end_matches(".whl");
        let parts: Vec<&str> = name.split('-').collect();

        if parts.len() < 5 {
            return Err(AppError::Validation(format!(
                "Invalid wheel filename format: {}",
                filename
            )));
        }

        // First part is distribution name, second is version
        // Then optional build tag, then python tag, abi tag, platform tag
        let distribution = Self::normalize_name(parts[0]);
        let version = parts[1].to_string();

        Ok(PypiPackageInfo {
            name: Some(distribution),
            version: Some(version),
            filename: Some(filename.to_string()),
            is_simple_index: false,
            is_package_index: false,
        })
    }

    /// Parse source distribution filename
    /// Format: {name}-{version}.tar.gz
    fn parse_sdist_filename(filename: &str) -> Result<PypiPackageInfo> {
        let name = filename.trim_end_matches(".tar.gz");
        let parts: Vec<&str> = name.rsplitn(2, '-').collect();

        if parts.len() != 2 {
            return Err(AppError::Validation(format!(
                "Invalid sdist filename format: {}",
                filename
            )));
        }

        let version = parts[0].to_string();
        let distribution = Self::normalize_name(parts[1]);

        Ok(PypiPackageInfo {
            name: Some(distribution),
            version: Some(version),
            filename: Some(filename.to_string()),
            is_simple_index: false,
            is_package_index: false,
        })
    }

    /// Parse zip source distribution filename
    fn parse_sdist_zip_filename(filename: &str) -> Result<PypiPackageInfo> {
        let name = filename.trim_end_matches(".zip");
        let parts: Vec<&str> = name.rsplitn(2, '-').collect();

        if parts.len() != 2 {
            return Err(AppError::Validation(format!(
                "Invalid zip sdist filename format: {}",
                filename
            )));
        }

        let version = parts[0].to_string();
        let distribution = Self::normalize_name(parts[1]);

        Ok(PypiPackageInfo {
            name: Some(distribution),
            version: Some(version),
            filename: Some(filename.to_string()),
            is_simple_index: false,
            is_package_index: false,
        })
    }

    /// Normalize package name according to PEP 503
    /// Replace any runs of non-alphanumeric characters with a single hyphen
    pub fn normalize_name(name: &str) -> String {
        let mut result = String::new();
        let mut last_was_separator = true;

        for c in name.chars() {
            if c.is_ascii_alphanumeric() {
                result.push(c.to_ascii_lowercase());
                last_was_separator = false;
            } else if !last_was_separator {
                result.push('-');
                last_was_separator = true;
            }
        }

        // Remove trailing separator
        if result.ends_with('-') {
            result.pop();
        }

        result
    }

    /// Extract the version from a PyPI filename (wheel or sdist), stripping a
    /// PEP 658 `.metadata` suffix first. Reuses [`Self::parse_filename`] so the
    /// guard and the publish/index paths agree on parsing. Returns `None` for
    /// unparseable names; the version is the one encoded in the filename, which
    /// for PEP 427-escaped versions may differ from the stored metadata version.
    pub fn version_from_filename(filename: &str) -> Option<String> {
        let filename = filename.strip_suffix(".metadata").unwrap_or(filename);
        Self::parse_filename(filename)
            .ok()
            .and_then(|info| info.version)
    }

    /// Canonicalize a PEP 440 version into a comparable string.
    ///
    /// Two versions that PEP 440 considers equal produce the same output, so
    /// `1.0` == `1.0.0`, `1.0a1` == `1.0-alpha-1`, `1.0.post1` == `1.0-1`, and
    /// the local-version separators a PEP 427 filename escapes to `_`
    /// (`1.0+abc.def` vs `1.0_abc_def`) compare equal to the stored metadata
    /// form. Returns `None` for input that is not recognisably PEP 440; callers
    /// fall back to exact matching in that case.
    pub fn canonical_version(version: &str) -> Option<String> {
        let v = version.trim().trim_start_matches(['v', 'V']);
        if v.is_empty() {
            return None;
        }

        // Local segment (everything after the first `+`). A PEP 427 wheel
        // filename escapes `+` and `.` runs in the local part to `_`, so treat
        // `_` as a local separator alongside `.`/`-`.
        let (public, local) = match v.split_once('+') {
            Some((p, l)) => (p, Some(l)),
            None => (v, None),
        };

        let lower = public.to_ascii_lowercase();

        // Epoch: `N!`.
        let (epoch, rest) = match lower.split_once('!') {
            Some((e, r)) => {
                if e.is_empty() || !e.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                (e.trim_start_matches('0'), r)
            }
            None => ("", lower.as_str()),
        };
        let epoch: &str = if epoch.is_empty() { "0" } else { epoch };

        // Greedily take the leading release: `digits(.digits)*`. The remainder
        // holds the optional pre / post / dev / implicit-post qualifiers.
        let (release_str, suffix) = split_release(rest)?;
        let release = canon_release(&release_str);

        // Tokenize the qualifier suffix into alternating digit / alpha runs,
        // treating `.`/`-`/`_` purely as separators (PEP 440 normalisation).
        let tokens = tokenize_version(suffix)?;

        let mut pre: Option<(&'static str, u64)> = None;
        let mut post: Option<u64> = None;
        let mut dev: Option<u64> = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = &tokens[i];
            // A bare number directly after the release is an implicit post
            // release (`1.0-1`).
            if tok.chars().all(|c| c.is_ascii_digit())
                && pre.is_none()
                && post.is_none()
                && dev.is_none()
            {
                post = Some(tok.parse().ok()?);
                i += 1;
                continue;
            }
            let label = match tok.as_str() {
                "a" | "alpha" => Some(("pre", "a")),
                "b" | "beta" => Some(("pre", "b")),
                "c" | "rc" | "pre" | "preview" => Some(("pre", "rc")),
                "post" | "rev" | "r" => Some(("post", "")),
                "dev" => Some(("dev", "")),
                _ => None,
            };
            let (kind, prelabel) = label?;
            // Optional trailing number for this qualifier.
            let n = if i + 1 < tokens.len() && tokens[i + 1].chars().all(|c| c.is_ascii_digit()) {
                let parsed = tokens[i + 1].parse().ok()?;
                i += 2;
                parsed
            } else {
                i += 1;
                0
            };
            match kind {
                "pre" => pre = Some((prelabel, n)),
                "post" => post = Some(n),
                "dev" => dev = Some(n),
                _ => unreachable!(),
            }
        }

        let mut out = format!("{}!{}", epoch, release);
        if let Some((label, n)) = pre {
            out.push_str(&format!("{}{}", label, n));
        }
        if let Some(n) = post {
            out.push_str(&format!(".post{}", n));
        }
        if let Some(n) = dev {
            out.push_str(&format!(".dev{}", n));
        }
        if let Some(local) = local {
            let parts: Vec<&str> = local
                .split(['.', '-', '_'])
                .filter(|s| !s.is_empty())
                .collect();
            if !parts.is_empty() {
                out.push('+');
                out.push_str(&parts.join(".").to_ascii_lowercase());
            }
        }
        Some(out)
    }

    /// Extract metadata from PKG-INFO or METADATA file in sdist
    pub fn extract_sdist_metadata(content: &[u8]) -> Result<PkgInfo> {
        let gz = GzDecoder::new(content);
        let mut archive = Archive::new(gz);

        for entry in archive
            .entries()
            .map_err(|e| AppError::Validation(format!("Invalid tarball: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Validation(format!("Invalid tarball entry: {}", e)))?;

            let path = entry
                .path()
                .map_err(|e| AppError::Validation(format!("Invalid path in tarball: {}", e)))?;

            // Look for PKG-INFO in the root of the package
            if path.ends_with("PKG-INFO") {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read PKG-INFO: {}", e)))?;

                return Self::parse_pkg_info(&content);
            }
        }

        Err(AppError::Validation(
            "PKG-INFO not found in source distribution".to_string(),
        ))
    }

    /// Extract METADATA from wheel file
    pub fn extract_wheel_metadata(content: &[u8]) -> Result<PkgInfo> {
        // Wheels are ZIP files
        let cursor = std::io::Cursor::new(content);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| AppError::Validation(format!("Invalid wheel file: {}", e)))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| AppError::Validation(format!("Failed to read wheel entry: {}", e)))?;

            let name = file.name().to_string();

            // Look for METADATA file in .dist-info directory
            if name.contains(".dist-info/") && name.ends_with("METADATA") {
                let mut content = String::new();
                file.read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read METADATA: {}", e)))?;

                return Self::parse_pkg_info(&content);
            }
        }

        Err(AppError::Validation(
            "METADATA not found in wheel file".to_string(),
        ))
    }

    /// Parse PKG-INFO or METADATA content (RFC 822 format)
    pub fn parse_pkg_info(content: &str) -> Result<PkgInfo> {
        let mut info = PkgInfo::default();
        let mut current_key: Option<String> = None;
        let mut current_value = String::new();

        for line in content.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation line
                if current_key.is_some() {
                    current_value.push('\n');
                    current_value.push_str(line.trim());
                }
            } else if let Some(colon_pos) = line.find(':') {
                // New field - save previous if exists
                if let Some(key) = current_key.take() {
                    Self::set_pkg_info_field(&mut info, &key, &current_value);
                }

                let key = line[..colon_pos].to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                current_key = Some(key);
                current_value = value;
            }
        }

        // Save the last field
        if let Some(key) = current_key {
            Self::set_pkg_info_field(&mut info, &key, &current_value);
        }

        if info.name.is_empty() {
            return Err(AppError::Validation(
                "PKG-INFO missing required Name field".to_string(),
            ));
        }

        Ok(info)
    }

    fn set_pkg_info_field(info: &mut PkgInfo, key: &str, value: &str) {
        match key.to_lowercase().as_str() {
            "metadata-version" => info.metadata_version = Some(value.to_string()),
            "name" => info.name = value.to_string(),
            "version" => info.version = value.to_string(),
            "summary" => info.summary = Some(value.to_string()),
            "description" => info.description = Some(value.to_string()),
            "description-content-type" => info.description_content_type = Some(value.to_string()),
            "keywords" => {
                info.keywords = Some(value.split(',').map(|s| s.trim().to_string()).collect())
            }
            "home-page" => info.home_page = Some(value.to_string()),
            "download-url" => info.download_url = Some(value.to_string()),
            "author" => info.author = Some(value.to_string()),
            "author-email" => info.author_email = Some(value.to_string()),
            "maintainer" => info.maintainer = Some(value.to_string()),
            "maintainer-email" => info.maintainer_email = Some(value.to_string()),
            "license" => info.license = Some(value.to_string()),
            "classifier" => {
                info.classifiers
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
            }
            "platform" => {
                info.platforms
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
            }
            "requires-python" => info.requires_python = Some(value.to_string()),
            "requires-dist" => {
                info.requires_dist
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
            }
            "provides-extra" => {
                info.provides_extra
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
            }
            "project-url" => {
                let parts: Vec<&str> = value.splitn(2, ',').collect();
                if parts.len() == 2 {
                    info.project_urls
                        .get_or_insert_with(HashMap::new)
                        .insert(parts[0].trim().to_string(), parts[1].trim().to_string());
                }
            }
            _ => {}
        }
    }

    /// Render the PEP 503 root simple index (`simple/`) as HTML: one
    /// `<a href="/pypi/<repo_key>/simple/<name>/">name</a>` link per known
    /// project. `repo_key` and every `package` name are HTML-escaped before
    /// interpolation (defense-in-depth; `package` names are already PEP 503
    /// normalised at the call site, but the escape keeps a future regression
    /// from introducing stored XSS).
    ///
    /// Kept pure (returns the body string) so the anchor-rendering rules are
    /// unit-testable without standing up an HTTP handler, a DB, or a storage
    /// backend. The HTTP handler wraps the returned body with the PEP 503
    /// response headers (Content-Type, CSP, nosniff).
    pub fn render_simple_root_html(repo_key: &str, packages: &[String]) -> String {
        let escaped_repo_key = html_escape_pep503(repo_key);
        let mut html = String::from(
            "<!DOCTYPE html>\n<html>\n<head><meta name=\"pypi:repository-version\" \
             content=\"1.0\"/><title>Simple Index</title></head>\n<body>\n\
             <h1>Simple Index</h1>\n",
        );
        for package in packages {
            let escaped = html_escape_pep503(package);
            html.push_str(&format!(
                "<a href=\"/pypi/{}/simple/{}/\">{}</a><br/>\n",
                escaped_repo_key, escaped, escaped
            ));
        }
        html.push_str("</body>\n</html>\n");
        html
    }
}

/// Canonicalize a numeric PEP 440 release segment: drop leading zeros from
/// each component and trailing zero components so `1.0` and `1.0.0` agree.
fn canon_release(release: &str) -> String {
    let parts: Vec<&str> = release.split('.').collect();
    let mut nums: Vec<u64> = parts
        .iter()
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect();
    while nums.len() > 1 && *nums.last().unwrap() == 0 {
        nums.pop();
    }
    nums.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Split the leading `digits(.digits)*` release off a PEP 440 public-version
/// body (epoch already removed). Returns the release and the remaining
/// qualifier suffix (which may start with a separator). `None` if the body
/// does not start with a digit.
fn split_release(body: &str) -> Option<(String, &str)> {
    if !body.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let bytes = body.as_bytes();
    let mut end = 0;
    let mut expect_digit = true;
    while end < bytes.len() {
        let c = bytes[end] as char;
        if c.is_ascii_digit() {
            expect_digit = false;
            end += 1;
        } else if c == '.' && !expect_digit {
            // A `.` continues the release only if another digit follows.
            if bytes
                .get(end + 1)
                .map(|b| b.is_ascii_digit())
                .unwrap_or(false)
            {
                expect_digit = true;
                end += 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    Some((body[..end].to_string(), &body[end..]))
}

/// Split a PEP 440 public-version body into alternating digit / alpha runs,
/// treating `.`/`-`/`_` as separators. Returns `None` on any other character.
fn tokenize_version(body: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut cur_digit = false;
    for c in body.chars() {
        if c == '.' || c == '-' || c == '_' {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
        } else if c.is_ascii_digit() {
            if !cur.is_empty() && !cur_digit {
                tokens.push(std::mem::take(&mut cur));
            }
            cur_digit = true;
            cur.push(c);
        } else if c.is_ascii_alphabetic() {
            if !cur.is_empty() && cur_digit {
                tokens.push(std::mem::take(&mut cur));
            }
            cur_digit = false;
            cur.push(c);
        } else {
            return None;
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    Some(tokens)
}

/// Minimal HTML escaper for the PEP 503 simple-index renderer. Escapes the
/// five characters that are unsafe to interpolate into element text or a
/// double-quoted attribute value.
fn html_escape_pep503(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

impl Default for PypiHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for PypiHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Pypi
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({});

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        if let Some(filename) = &info.filename {
            metadata["filename"] = serde_json::Value::String(filename.clone());
        }

        metadata["is_simple_index"] = serde_json::Value::Bool(info.is_simple_index);
        metadata["is_package_index"] = serde_json::Value::Bool(info.is_package_index);

        // If it's a package file, try to extract metadata
        if let Some(filename) = info.filename.as_ref().filter(|_| !content.is_empty()) {
            let pkg_info_result = if filename.ends_with(".whl") {
                Self::extract_wheel_metadata(content)
            } else if filename.ends_with(".tar.gz") {
                Self::extract_sdist_metadata(content)
            } else {
                Err(AppError::Validation("Unsupported format".to_string()))
            };

            if let Ok(pkg_info) = pkg_info_result {
                metadata["pkg_info"] = serde_json::to_value(&pkg_info)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate package files
        if let Some(filename) = info.filename.as_ref().filter(|_| !content.is_empty()) {
            // Validate wheel files
            if filename.ends_with(".whl") {
                let pkg_info = Self::extract_wheel_metadata(content)?;

                // Verify name matches
                if let Some(path_name) = &info.name {
                    let normalized_pkg_name = Self::normalize_name(&pkg_info.name);
                    if &normalized_pkg_name != path_name {
                        return Err(AppError::Validation(format!(
                            "Package name mismatch: path says '{}' but metadata says '{}'",
                            path_name, pkg_info.name
                        )));
                    }
                }

                // Verify version matches
                if let Some(path_version) = &info.version {
                    if &pkg_info.version != path_version {
                        return Err(AppError::Validation(format!(
                            "Version mismatch: path says '{}' but metadata says '{}'",
                            path_version, pkg_info.version
                        )));
                    }
                }
            }

            // Validate sdist files
            if filename.ends_with(".tar.gz") {
                let pkg_info = Self::extract_sdist_metadata(content)?;

                // Verify name matches
                if let Some(path_name) = &info.name {
                    let normalized_pkg_name = Self::normalize_name(&pkg_info.name);
                    if &normalized_pkg_name != path_name {
                        return Err(AppError::Validation(format!(
                            "Package name mismatch: path says '{}' but metadata says '{}'",
                            path_name, pkg_info.name
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Simple index is generated on demand based on DB state
        Ok(None)
    }
}

/// PyPI package path info
#[derive(Debug)]
pub struct PypiPackageInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub filename: Option<String>,
    pub is_simple_index: bool,
    pub is_package_index: bool,
}

/// PKG-INFO / METADATA structure
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PkgInfo {
    pub metadata_version: Option<String>,
    pub name: String,
    pub version: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub description_content_type: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub home_page: Option<String>,
    pub download_url: Option<String>,
    pub author: Option<String>,
    pub author_email: Option<String>,
    pub maintainer: Option<String>,
    pub maintainer_email: Option<String>,
    pub license: Option<String>,
    pub classifiers: Option<Vec<String>>,
    pub platforms: Option<Vec<String>>,
    pub requires_python: Option<String>,
    pub requires_dist: Option<Vec<String>>,
    pub provides_extra: Option<Vec<String>>,
    pub project_urls: Option<HashMap<String, String>>,
}

/// Generate simple index HTML for root
pub fn generate_simple_root_index(packages: &[String]) -> String {
    let mut html = String::from(
        "<!DOCTYPE html>\n<html>\n<head>\n<title>Simple Index</title>\n</head>\n<body>\n<h1>Simple Index</h1>\n",
    );

    for package in packages {
        let normalized = PypiHandler::normalize_name(package);
        html.push_str(&format!(
            "<a href=\"/simple/{}/\">{}</a><br/>\n",
            normalized, package
        ));
    }

    html.push_str("</body>\n</html>\n");
    html
}

/// Generate simple index HTML for a package
pub fn generate_simple_package_index(
    package_name: &str,
    files: &[(String, String, Option<String>)], // (filename, url, hash)
) -> String {
    let mut html = String::from("<!DOCTYPE html>\n<html>\n<head>\n<meta name=\"pypi:repository-version\" content=\"1.0\"/>\n");
    html.push_str(&format!("<title>Links for {}</title>\n", package_name));
    html.push_str("</head>\n<body>\n");
    html.push_str(&format!("<h1>Links for {}</h1>\n", package_name));

    for (filename, url, hash) in files {
        let hash_attr = hash
            .as_ref()
            .map(|h| format!(" data-dist-info-metadata=\"sha256={}\"", h))
            .unwrap_or_default();

        html.push_str(&format!(
            "<a href=\"{}\"{}>{}</a><br/>\n",
            url, hash_attr, filename
        ));
    }

    html.push_str("</body>\n</html>\n");
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // render_simple_root_html tests (B8): the PEP 503 root index must emit
    // one `<a>` anchor per known project. The regression was a Remote repo
    // returning a non-empty page with ZERO anchors because the package list
    // was empty; here we assert anchors are present for known packages.
    // ========================================================================

    #[test]
    fn test_render_simple_root_html_lists_anchors_for_known_packages() {
        let packages = vec![
            "flask".to_string(),
            "numpy".to_string(),
            "requests".to_string(),
        ];
        let html = PypiHandler::render_simple_root_html("pypi-remote", &packages);

        assert!(html.contains("<h1>Simple Index</h1>"));
        // One anchor per project, pointing at the per-project simple index.
        assert_eq!(html.matches("<a href=").count(), 3);
        assert!(html.contains("<a href=\"/pypi/pypi-remote/simple/flask/\">flask</a>"));
        assert!(html.contains("<a href=\"/pypi/pypi-remote/simple/numpy/\">numpy</a>"));
        assert!(html.contains("<a href=\"/pypi/pypi-remote/simple/requests/\">requests</a>"));
    }

    #[test]
    fn test_render_simple_root_html_empty_has_no_anchors() {
        let html = PypiHandler::render_simple_root_html("pypi-local", &[]);
        assert!(html.contains("<h1>Simple Index</h1>"));
        assert!(!html.contains("<a href="));
    }

    #[test]
    fn test_render_simple_root_html_escapes_inputs() {
        // Defense-in-depth: a stray `<` in either field must be escaped.
        let packages = vec!["a<b".to_string()];
        let html = PypiHandler::render_simple_root_html("re\"po", &packages);
        assert!(!html.contains("a<b"));
        assert!(html.contains("a&lt;b"));
        assert!(html.contains("re&quot;po"));
    }

    // ========================================================================
    // normalize_name tests
    // ========================================================================

    #[test]
    fn test_normalize_name() {
        assert_eq!(PypiHandler::normalize_name("My_Package"), "my-package");
        assert_eq!(PypiHandler::normalize_name("some.package"), "some-package");
        assert_eq!(PypiHandler::normalize_name("Package__Name"), "package-name");
    }

    #[test]
    fn test_normalize_name_empty() {
        assert_eq!(PypiHandler::normalize_name(""), "");
    }

    #[test]
    fn test_normalize_name_already_normalized() {
        assert_eq!(PypiHandler::normalize_name("requests"), "requests");
        assert_eq!(PypiHandler::normalize_name("my-package"), "my-package");
    }

    #[test]
    fn test_normalize_name_uppercase() {
        assert_eq!(PypiHandler::normalize_name("REQUESTS"), "requests");
        assert_eq!(PypiHandler::normalize_name("Flask"), "flask");
    }

    #[test]
    fn test_normalize_name_mixed_separators() {
        assert_eq!(
            PypiHandler::normalize_name("My.Package_Name"),
            "my-package-name"
        );
        assert_eq!(PypiHandler::normalize_name("a__b..c--d"), "a-b-c-d");
    }

    #[test]
    fn test_normalize_name_leading_separator() {
        // Leading non-alphanumeric characters are dropped (last_was_separator starts true)
        assert_eq!(PypiHandler::normalize_name("_package"), "package");
        assert_eq!(PypiHandler::normalize_name(".package"), "package");
    }

    #[test]
    fn test_normalize_name_trailing_separator() {
        assert_eq!(PypiHandler::normalize_name("package_"), "package");
        assert_eq!(PypiHandler::normalize_name("package."), "package");
    }

    #[test]
    fn test_normalize_name_only_separators() {
        assert_eq!(PypiHandler::normalize_name("___"), "");
        assert_eq!(PypiHandler::normalize_name("..."), "");
    }

    #[test]
    fn test_normalize_name_single_char() {
        assert_eq!(PypiHandler::normalize_name("a"), "a");
        assert_eq!(PypiHandler::normalize_name("Z"), "z");
    }

    #[test]
    fn test_normalize_name_digits() {
        assert_eq!(PypiHandler::normalize_name("package2"), "package2");
        assert_eq!(PypiHandler::normalize_name("3to2"), "3to2");
    }

    // ========================================================================
    // parse_filename tests (wheel, sdist, zip)
    // ========================================================================

    #[test]
    fn test_parse_wheel_filename() {
        let info = PypiHandler::parse_filename("requests-2.28.0-py3-none-any.whl").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
        assert_eq!(
            info.filename,
            Some("requests-2.28.0-py3-none-any.whl".to_string())
        );
        assert!(!info.is_simple_index);
        assert!(!info.is_package_index);
    }

    #[test]
    fn test_parse_wheel_filename_with_build_tag() {
        // PEP 427: {dist}-{version}(-{build})?-{python}-{abi}-{platform}.whl
        // 6 parts means there is a build tag
        let info =
            PypiHandler::parse_filename("package-1.0.0-1-cp39-cp39-manylinux1_x86_64.whl").unwrap();
        assert_eq!(info.name, Some("package".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_parse_wheel_filename_too_few_parts() {
        // Less than 5 parts (after removing .whl) should fail
        let result = PypiHandler::parse_filename("invalid-name.whl");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_wheel_filename_normalized_name() {
        let info = PypiHandler::parse_filename("My_Package-1.0.0-py3-none-any.whl").unwrap();
        assert_eq!(info.name, Some("my-package".to_string()));
    }

    #[test]
    fn test_parse_sdist_filename() {
        let info = PypiHandler::parse_filename("requests-2.28.0.tar.gz").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
        assert_eq!(info.filename, Some("requests-2.28.0.tar.gz".to_string()));
    }

    #[test]
    fn test_parse_sdist_filename_with_hyphens_in_name() {
        // rsplitn(2, '-') splits on the LAST hyphen, so name can contain hyphens
        let info = PypiHandler::parse_filename("my-package-1.0.0.tar.gz").unwrap();
        assert_eq!(info.name, Some("my-package".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_parse_sdist_filename_no_version_separator() {
        // No hyphen after removing .tar.gz means rsplitn returns only 1 part
        let result = PypiHandler::parse_filename("package.tar.gz");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_zip_filename() {
        let info = PypiHandler::parse_filename("requests-2.28.0.zip").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
        assert_eq!(info.filename, Some("requests-2.28.0.zip".to_string()));
    }

    #[test]
    fn test_parse_zip_filename_no_version() {
        let result = PypiHandler::parse_filename("package.zip");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_filename_unknown_format() {
        let result = PypiHandler::parse_filename("package-1.0.0.egg");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Unknown Python package format"));
    }

    // ========================================================================
    // parse_path tests
    // ========================================================================

    #[test]
    fn test_parse_simple_path() {
        let info = PypiHandler::parse_path("simple/requests/").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert!(info.is_package_index);
        assert!(!info.is_simple_index);
    }

    #[test]
    fn test_parse_root_index() {
        let info = PypiHandler::parse_path("simple/").unwrap();
        assert!(info.is_simple_index);
        assert!(info.name.is_none());
    }

    #[test]
    fn test_parse_root_index_without_trailing_slash() {
        let info = PypiHandler::parse_path("simple").unwrap();
        assert!(info.is_simple_index);
        assert!(info.name.is_none());
    }

    #[test]
    fn test_parse_path_leading_slash() {
        let info = PypiHandler::parse_path("/simple/requests/").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert!(info.is_package_index);
    }

    #[test]
    fn test_parse_path_simple_package_without_trailing_slash() {
        let info = PypiHandler::parse_path("simple/requests").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert!(info.is_package_index);
    }

    #[test]
    fn test_parse_path_simple_package_normalized() {
        let info = PypiHandler::parse_path("simple/My_Package/").unwrap();
        assert_eq!(info.name, Some("my-package".to_string()));
        assert!(info.is_package_index);
    }

    #[test]
    fn test_parse_path_packages_format() {
        let info =
            PypiHandler::parse_path("packages/requests/2.28.0/requests-2.28.0.tar.gz").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
        assert_eq!(info.filename, Some("requests-2.28.0.tar.gz".to_string()));
        assert!(!info.is_simple_index);
        assert!(!info.is_package_index);
    }

    #[test]
    fn test_parse_path_packages_normalized_name() {
        let info =
            PypiHandler::parse_path("packages/My_Package/1.0.0/My_Package-1.0.0.tar.gz").unwrap();
        assert_eq!(info.name, Some("my-package".to_string()));
    }

    #[test]
    fn test_parse_path_packages_too_few_parts() {
        // packages/ with less than 3 parts after the prefix should fallback
        // "packages/requests/2.28.0" has only 2 parts, no filename
        // This doesn't end with .whl/.tar.gz/.zip so it should error
        let result = PypiHandler::parse_path("packages/requests");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_direct_wheel() {
        let info = PypiHandler::parse_path("requests-2.28.0-py3-none-any.whl").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
    }

    #[test]
    fn test_parse_path_direct_sdist() {
        let info = PypiHandler::parse_path("requests-2.28.0.tar.gz").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
    }

    #[test]
    fn test_parse_path_direct_zip() {
        let info = PypiHandler::parse_path("requests-2.28.0.zip").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
        assert_eq!(info.version, Some("2.28.0".to_string()));
    }

    #[test]
    fn test_parse_path_nested_wheel() {
        let info =
            PypiHandler::parse_path("some/nested/path/requests-2.28.0-py3-none-any.whl").unwrap();
        assert_eq!(info.name, Some("requests".to_string()));
    }

    #[test]
    fn test_parse_path_invalid() {
        let result = PypiHandler::parse_path("invalid/path/no/extension");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_empty_simple_subpath() {
        // "simple/" with nothing after it returns root index
        let info = PypiHandler::parse_path("simple/").unwrap();
        assert!(info.is_simple_index);
    }

    // ========================================================================
    // parse_pkg_info tests
    // ========================================================================

    #[test]
    fn test_parse_pkg_info() {
        let content = r#"Metadata-Version: 2.1
Name: requests
Version: 2.28.0
Summary: Python HTTP for Humans.
Author: Kenneth Reitz
License: Apache 2.0
Requires-Python: >=3.7
Classifier: Development Status :: 5 - Production/Stable
Classifier: Intended Audience :: Developers
Requires-Dist: charset_normalizer (<3,>=2)
Requires-Dist: idna (<4,>=2.5)
"#;
        let info = PypiHandler::parse_pkg_info(content).unwrap();
        assert_eq!(info.name, "requests");
        assert_eq!(info.version, "2.28.0");
        assert_eq!(info.summary, Some("Python HTTP for Humans.".to_string()));
        assert_eq!(info.requires_python, Some(">=3.7".to_string()));
        assert_eq!(info.classifiers.as_ref().map(|c| c.len()), Some(2));
        assert_eq!(info.requires_dist.as_ref().map(|d| d.len()), Some(2));
    }

    #[test]
    fn test_parse_pkg_info_missing_name() {
        let content = "Version: 1.0.0\nSummary: No name\n";
        let result = PypiHandler::parse_pkg_info(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pkg_info_empty() {
        let result = PypiHandler::parse_pkg_info("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pkg_info_all_fields() {
        let content = r#"Metadata-Version: 2.1
Name: my-package
Version: 1.0.0
Summary: A test package
Description: Long description here
Description-Content-Type: text/markdown
Keywords: test,package,rust
Home-Page: https://example.com
Download-URL: https://example.com/download
Author: John Doe
Author-Email: john@example.com
Maintainer: Jane Smith
Maintainer-Email: jane@example.com
License: MIT
Platform: linux
Platform: win32
Requires-Python: >=3.8
Provides-Extra: dev
Provides-Extra: test
Project-URL: Homepage, https://example.com
Project-URL: Documentation, https://docs.example.com
"#;
        let info = PypiHandler::parse_pkg_info(content).unwrap();
        assert_eq!(info.metadata_version, Some("2.1".to_string()));
        assert_eq!(info.name, "my-package");
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.summary, Some("A test package".to_string()));
        assert_eq!(info.description, Some("Long description here".to_string()));
        assert_eq!(
            info.description_content_type,
            Some("text/markdown".to_string())
        );
        assert_eq!(
            info.keywords,
            Some(vec![
                "test".to_string(),
                "package".to_string(),
                "rust".to_string()
            ])
        );
        assert_eq!(info.home_page, Some("https://example.com".to_string()));
        assert_eq!(
            info.download_url,
            Some("https://example.com/download".to_string())
        );
        assert_eq!(info.author, Some("John Doe".to_string()));
        assert_eq!(info.author_email, Some("john@example.com".to_string()));
        assert_eq!(info.maintainer, Some("Jane Smith".to_string()));
        assert_eq!(info.maintainer_email, Some("jane@example.com".to_string()));
        assert_eq!(info.license, Some("MIT".to_string()));
        assert_eq!(
            info.platforms,
            Some(vec!["linux".to_string(), "win32".to_string()])
        );
        assert_eq!(info.requires_python, Some(">=3.8".to_string()));
        assert_eq!(
            info.provides_extra,
            Some(vec!["dev".to_string(), "test".to_string()])
        );
        let urls = info.project_urls.unwrap();
        assert_eq!(urls.len(), 2);
        assert_eq!(
            urls.get("Homepage"),
            Some(&"https://example.com".to_string())
        );
        assert_eq!(
            urls.get("Documentation"),
            Some(&"https://docs.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_pkg_info_continuation_lines() {
        let content =
            "Name: test-pkg\nVersion: 1.0\nDescription: Line one\n  Line two\n  Line three\n";
        let info = PypiHandler::parse_pkg_info(content).unwrap();
        assert_eq!(info.name, "test-pkg");
        // Description should include continuation lines joined with newlines
        assert!(info
            .description
            .as_ref()
            .unwrap()
            .contains("Line one\nLine two\nLine three"));
    }

    #[test]
    fn test_parse_pkg_info_tab_continuation() {
        let content = "Name: test-pkg\nVersion: 1.0\nDescription: First\n\tSecond\n";
        let info = PypiHandler::parse_pkg_info(content).unwrap();
        assert!(info.description.as_ref().unwrap().contains("Second"));
    }

    #[test]
    fn test_parse_pkg_info_project_url_malformed() {
        // project-url without a comma separator: should not add to map
        let content = "Name: test\nVersion: 1.0\nProject-URL: no-comma-here\n";
        let info = PypiHandler::parse_pkg_info(content).unwrap();
        assert!(info.project_urls.is_none());
    }

    #[test]
    fn test_parse_pkg_info_unknown_fields_ignored() {
        let content = "Name: test\nVersion: 1.0\nX-Custom-Header: custom value\n";
        let info = PypiHandler::parse_pkg_info(content).unwrap();
        assert_eq!(info.name, "test");
    }

    #[test]
    fn test_parse_pkg_info_name_only() {
        let content = "Name: minimal\n";
        let info = PypiHandler::parse_pkg_info(content).unwrap();
        assert_eq!(info.name, "minimal");
        assert_eq!(info.version, "");
    }

    // ========================================================================
    // generate_simple_root_index tests
    // ========================================================================

    #[test]
    fn test_generate_simple_root_index_empty() {
        let html = generate_simple_root_index(&[]);
        assert!(html.contains("<h1>Simple Index</h1>"));
        assert!(html.contains("</body>"));
        assert!(!html.contains("<a href="));
    }

    #[test]
    fn test_generate_simple_root_index_with_packages() {
        let packages = vec!["requests".to_string(), "Flask".to_string()];
        let html = generate_simple_root_index(&packages);
        assert!(html.contains("<a href=\"/simple/requests/\">requests</a>"));
        assert!(html.contains("<a href=\"/simple/flask/\">Flask</a>"));
    }

    #[test]
    fn test_generate_simple_root_index_normalizes_names() {
        let packages = vec!["My_Package".to_string()];
        let html = generate_simple_root_index(&packages);
        assert!(html.contains("<a href=\"/simple/my-package/\">My_Package</a>"));
    }

    // ========================================================================
    // generate_simple_package_index tests
    // ========================================================================

    #[test]
    fn test_generate_simple_package_index_empty() {
        let html = generate_simple_package_index("requests", &[]);
        assert!(html.contains("<title>Links for requests</title>"));
        assert!(html.contains("<h1>Links for requests</h1>"));
        assert!(!html.contains("<a href="));
    }

    #[test]
    fn test_generate_simple_package_index_with_files() {
        let files = vec![(
            "requests-2.28.0.tar.gz".to_string(),
            "/packages/requests/2.28.0/requests-2.28.0.tar.gz".to_string(),
            None,
        )];
        let html = generate_simple_package_index("requests", &files);
        assert!(html.contains("requests-2.28.0.tar.gz</a>"));
        assert!(html.contains("href=\"/packages/requests/2.28.0/requests-2.28.0.tar.gz\""));
    }

    #[test]
    fn test_generate_simple_package_index_with_hash() {
        let files = vec![(
            "requests-2.28.0.tar.gz".to_string(),
            "/packages/requests/2.28.0/requests-2.28.0.tar.gz".to_string(),
            Some("abc123def456".to_string()),
        )];
        let html = generate_simple_package_index("requests", &files);
        assert!(html.contains("data-dist-info-metadata=\"sha256=abc123def456\""));
    }

    #[test]
    fn test_generate_simple_package_index_multiple_files() {
        let files = vec![
            ("pkg-1.0.tar.gz".to_string(), "/url1".to_string(), None),
            (
                "pkg-2.0.tar.gz".to_string(),
                "/url2".to_string(),
                Some("hash2".to_string()),
            ),
        ];
        let html = generate_simple_package_index("pkg", &files);
        assert!(html.contains("pkg-1.0.tar.gz</a>"));
        assert!(html.contains("pkg-2.0.tar.gz</a>"));
    }

    #[test]
    fn test_generate_simple_package_index_has_pypi_version() {
        let html = generate_simple_package_index("pkg", &[]);
        assert!(html.contains("pypi:repository-version"));
        assert!(html.contains("content=\"1.0\""));
    }

    // ========================================================================
    // PypiHandler::new / Default tests
    // ========================================================================

    #[test]
    fn test_pypi_handler_new() {
        let _handler = PypiHandler::new();
    }

    #[test]
    fn test_pypi_handler_default() {
        let _handler = PypiHandler;
    }

    #[test]
    fn test_version_from_filename_wheel() {
        assert_eq!(
            PypiHandler::version_from_filename("celery_message_consumer-1.1.1-py3-none-any.whl"),
            Some("1.1.1".to_string())
        );
    }

    #[test]
    fn test_version_from_filename_sdist() {
        assert_eq!(
            PypiHandler::version_from_filename("celery-message-consumer-1.1.1.tar.gz"),
            Some("1.1.1".to_string())
        );
    }

    #[test]
    fn test_version_from_filename_sdist_zip() {
        assert_eq!(
            PypiHandler::version_from_filename("my-pkg-2.0.0.zip"),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn test_version_from_filename_strips_pep658_metadata() {
        assert_eq!(
            PypiHandler::version_from_filename("foo-3.4.0-py3-none-any.whl.metadata"),
            Some("3.4.0".to_string())
        );
        assert_eq!(
            PypiHandler::version_from_filename("foo-3.4.0.tar.gz.metadata"),
            Some("3.4.0".to_string())
        );
    }

    #[test]
    fn test_version_from_filename_unparseable_returns_none() {
        assert_eq!(PypiHandler::version_from_filename("not-a-package"), None);
        assert_eq!(PypiHandler::version_from_filename(""), None);
    }

    // ========================================================================
    // canonical_version tests: two PEP 440-equal versions must canonicalize to
    // the same string so the shadowing guard cannot be bypassed by a release
    // form difference, and cannot 404 a locally-owned version.
    // ========================================================================

    fn canon(v: &str) -> String {
        PypiHandler::canonical_version(v).unwrap_or_else(|| panic!("unparseable: {v}"))
    }

    #[test]
    fn test_canonical_version_release_padding() {
        // 1.0 == 1.0.0 == 1.0.0.0 (trailing-zero release segments).
        assert_eq!(canon("1.0"), canon("1.0.0"));
        assert_eq!(canon("1.0"), canon("1.0.0.0"));
        assert_ne!(canon("1.0"), canon("1.0.1"));
    }

    #[test]
    fn test_canonical_version_leading_zeros_and_v_prefix() {
        assert_eq!(canon("1.01"), canon("1.1"));
        assert_eq!(canon("v1.2.3"), canon("1.2.3"));
    }

    #[test]
    fn test_canonical_version_local_with_plus() {
        // Metadata-form local versions keep the `+` and `.`/`-` separators;
        // within the local segment those separators normalise equal.
        assert_eq!(canon("1.0+abc.def"), canon("1.0+abc-def"));
        assert_eq!(canon("1.0+abc.def"), canon("1.0+abc_def"));
        assert_eq!(canon("1.0+ubuntu-1"), canon("1.0+ubuntu.1"));
        // Local segment still distinguishes different builds.
        assert_ne!(canon("1.0+abc"), canon("1.0+xyz"));
        // Local present vs absent are distinct.
        assert_ne!(canon("1.0"), canon("1.0+abc"));
    }

    #[test]
    fn test_canonical_version_filename_escaped_local_is_unparseable() {
        // A PEP 427 wheel filename escapes the local segment and DROPS the `+`,
        // so `version_from_filename` yields e.g. `1.2.3_gitsha` (no `+`). That
        // form is not recognisably PEP 440, so canonicalization returns None and
        // the guard must fall back to name-only suppression (fail-safe), rather
        // than mistakenly comparing-and-allowing fan-out. See the guard's
        // requested_canon None branch in proxy_helpers.
        assert_eq!(PypiHandler::canonical_version("1.2.3_gitsha"), None);
        assert_eq!(PypiHandler::canonical_version("1.0_abc_def"), None);
    }

    #[test]
    fn test_canonical_version_post() {
        // .post1 spellings and the implicit `1.0-1` post form agree.
        assert_eq!(canon("1.0.post1"), canon("1.0-post1"));
        assert_eq!(canon("1.0.post1"), canon("1.0-1"));
        assert_eq!(canon("1.0.post1"), canon("1.0.rev1"));
        assert_ne!(canon("1.0"), canon("1.0.post1"));
    }

    #[test]
    fn test_canonical_version_epoch() {
        // Epoch dominates: 1!2.0 is not 2.0, and 1!2.0 == 1!2.0.0.
        assert_ne!(canon("1!2.0"), canon("2.0"));
        assert_eq!(canon("1!2.0"), canon("1!2.0.0"));
        // Default epoch is 0.
        assert_eq!(canon("2.0"), canon("0!2.0"));
    }

    #[test]
    fn test_canonical_version_pre_release_spellings() {
        assert_eq!(canon("1.0a1"), canon("1.0-alpha-1"));
        assert_eq!(canon("1.0b2"), canon("1.0beta2"));
        assert_eq!(canon("1.0rc1"), canon("1.0-c-1"));
        assert_eq!(canon("1.0rc1"), canon("1.0preview1"));
        assert_ne!(canon("1.0a1"), canon("1.0b1"));
        assert_ne!(canon("1.0a1"), canon("1.0"));
    }

    #[test]
    fn test_canonical_version_dev() {
        assert_eq!(canon("1.0.dev1"), canon("1.0-dev-1"));
        assert_ne!(canon("1.0.dev1"), canon("1.0"));
    }

    #[test]
    fn test_canonical_version_unparseable_returns_none() {
        assert_eq!(PypiHandler::canonical_version(""), None);
        assert_eq!(PypiHandler::canonical_version("not a version"), None);
        assert_eq!(PypiHandler::canonical_version("1.0!@#"), None);
    }
}
