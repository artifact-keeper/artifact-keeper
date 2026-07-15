//! Upstream metadata sync adapters for curation.
//!
//! Each adapter knows how to fetch and parse a format's upstream package index
//! into a list of CurationPackageEntry records for insertion into curation_packages.

/// A parsed package entry from an upstream index.
#[derive(Debug, Clone)]
pub struct CurationPackageEntry {
    pub format: String,
    pub package_name: String,
    pub version: String,
    pub release: Option<String>,
    pub architecture: Option<String>,
    pub checksum_sha256: Option<String>,
    pub upstream_path: String,
    pub metadata: serde_json::Value,
}

/// Parse RPM primary.xml content into package entries.
/// The primary.xml lists all packages in a yum/dnf repository.
pub fn parse_rpm_primary_xml(xml: &str) -> Vec<CurationPackageEntry> {
    let mut entries = Vec::new();

    for pkg_block in xml.split("<package type=\"rpm\">").skip(1) {
        let pkg_block = match pkg_block.split("</package>").next() {
            Some(b) => b,
            None => continue,
        };

        let name = extract_xml_tag(pkg_block, "name").unwrap_or_default();
        let arch = extract_xml_tag(pkg_block, "arch").unwrap_or_default();
        let checksum = extract_xml_tag(pkg_block, "checksum").unwrap_or_default();
        let description = extract_xml_tag(pkg_block, "description").unwrap_or_default();

        let (ver, rel) = extract_rpm_version(pkg_block);
        let href = extract_xml_attr(pkg_block, "location", "href").unwrap_or_default();

        if name.is_empty() || ver.is_empty() {
            continue;
        }

        entries.push(CurationPackageEntry {
            format: "rpm".to_string(),
            package_name: name.clone(),
            version: ver.clone(),
            release: if rel.is_empty() {
                None
            } else {
                Some(rel.clone())
            },
            architecture: if arch.is_empty() {
                None
            } else {
                Some(arch.clone())
            },
            checksum_sha256: if checksum.is_empty() {
                None
            } else {
                Some(checksum)
            },
            upstream_path: href,
            metadata: serde_json::json!({
                "name": name,
                "version": ver,
                "release": rel,
                "arch": arch,
                "description": description,
            }),
        });
    }

    entries
}

/// Parse Debian Packages index content into package entries.
/// Each package is a block of key-value lines separated by blank lines.
pub fn parse_deb_packages_index(content: &str, component: &str) -> Vec<CurationPackageEntry> {
    let mut entries = Vec::new();

    for block in content.split("\n\n") {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }

        let mut name = String::new();
        let mut version = String::new();
        let mut arch = String::new();
        let mut sha256 = String::new();
        let mut filename = String::new();
        let mut description = String::new();

        for line in block.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Architecture: ") {
                arch = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("SHA256: ") {
                sha256 = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Filename: ") {
                filename = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Description: ") {
                description = v.trim().to_string();
            }
        }

        if name.is_empty() || version.is_empty() {
            continue;
        }

        entries.push(CurationPackageEntry {
            format: "debian".to_string(),
            package_name: name.clone(),
            version: version.clone(),
            release: None,
            architecture: if arch.is_empty() {
                None
            } else {
                Some(arch.clone())
            },
            checksum_sha256: if sha256.is_empty() {
                None
            } else {
                Some(sha256)
            },
            upstream_path: filename,
            metadata: serde_json::json!({
                "name": name,
                "version": version,
                "arch": arch,
                "component": component,
                "description": description,
            }),
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// XML helpers (minimal, no external dependency)
// ---------------------------------------------------------------------------

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)?;
    let after_open = &xml[start..];
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end = content.find(&close)?;
    Some(content[..end].trim().to_string())
}

fn extract_xml_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let start = xml.find(&open)?;
    let tag_text = &xml[start..];
    // Find the attr directly within the tag text, then extract its value.
    // This avoids issues with '/' in attribute values (e.g. href="Packages/foo.rpm").
    let attr_pattern = format!("{}=\"", attr);
    let attr_start = tag_text.find(&attr_pattern)? + attr_pattern.len();
    let attr_value = &tag_text[attr_start..];
    let attr_end = attr_value.find('"')?;
    Some(attr_value[..attr_end].to_string())
}

fn extract_rpm_version(xml: &str) -> (String, String) {
    let ver = extract_xml_attr(xml, "version", "ver").unwrap_or_default();
    let rel = extract_xml_attr(xml, "version", "rel").unwrap_or_default();
    (ver, rel)
}

/// Extract the `primary` data file href from an RPM `repomd.xml`.
///
/// Returns the `<location href="...">` of the `<data type="primary">` block
/// (typically `repodata/…-primary.xml.gz`) so the curation sync knows where to
/// fetch the package index. Kept next to [`parse_rpm_primary_xml`] as a pure,
/// table-testable helper so the sync path and any future consumer share one
/// implementation (#2357 WI-1). Returns `None` when no primary block is present.
pub fn extract_primary_href(repomd: &str) -> Option<String> {
    // Look for: <data type="primary"><location href="repodata/...-primary.xml.gz"/>
    for data_block in repomd.split("<data type=\"primary\">").skip(1) {
        if let Some(block) = data_block.split("</data>").next() {
            let loc_start = block.find("<location href=\"")?;
            let href_start = loc_start + "<location href=\"".len();
            let remaining = &block[href_start..];
            let href_end = remaining.find('"')?;
            return Some(remaining[..href_end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_primary_href_present() {
        let repomd = r#"<?xml version="1.0"?>
<repomd>
  <data type="filelists"><location href="repodata/filelists.xml.gz"/></data>
  <data type="primary"><location href="repodata/1234-primary.xml.gz"/></data>
</repomd>"#;
        assert_eq!(
            extract_primary_href(repomd),
            Some("repodata/1234-primary.xml.gz".to_string())
        );
    }

    #[test]
    fn test_extract_primary_href_absent() {
        let repomd = r#"<repomd>
  <data type="filelists"><location href="repodata/filelists.xml.gz"/></data>
</repomd>"#;
        assert_eq!(extract_primary_href(repomd), None);
        // Empty / malformed input never panics.
        assert_eq!(extract_primary_href(""), None);
        assert_eq!(extract_primary_href("<data type=\"primary\">"), None);
    }

    #[test]
    fn test_parse_rpm_primary_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">
<package type="rpm">
  <name>nginx</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.24.0" rel="1.el9"/>
  <checksum type="sha256">abc123def456</checksum>
  <location href="Packages/nginx-1.24.0-1.el9.x86_64.rpm"/>
  <description>A high performance web server</description>
</package>
<package type="rpm">
  <name>curl</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="8.5.0" rel="1.el9"/>
  <checksum type="sha256">def789ghi012</checksum>
  <location href="Packages/curl-8.5.0-1.el9.x86_64.rpm"/>
  <description>A URL transfer utility</description>
</package>
</metadata>"#;

        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].package_name, "nginx");
        assert_eq!(entries[0].version, "1.24.0");
        assert_eq!(entries[0].release.as_deref(), Some("1.el9"));
        assert_eq!(entries[0].architecture.as_deref(), Some("x86_64"));
        assert_eq!(entries[0].checksum_sha256.as_deref(), Some("abc123def456"));
        assert_eq!(
            entries[0].upstream_path,
            "Packages/nginx-1.24.0-1.el9.x86_64.rpm"
        );

        assert_eq!(entries[1].package_name, "curl");
        assert_eq!(entries[1].version, "8.5.0");
    }

    #[test]
    fn test_parse_deb_packages_index() {
        let content = r#"Package: nginx
Version: 1.24.0-1
Architecture: amd64
SHA256: abc123def456
Filename: pool/main/n/nginx/nginx_1.24.0-1_amd64.deb
Description: High performance web server

Package: curl
Version: 8.5.0-2ubuntu1
Architecture: amd64
SHA256: def789ghi012
Filename: pool/main/c/curl/curl_8.5.0-2ubuntu1_amd64.deb
Description: Command line URL transfer tool
"#;

        let entries = parse_deb_packages_index(content, "main");
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].package_name, "nginx");
        assert_eq!(entries[0].version, "1.24.0-1");
        assert_eq!(entries[0].architecture.as_deref(), Some("amd64"));
        assert_eq!(
            entries[0].upstream_path,
            "pool/main/n/nginx/nginx_1.24.0-1_amd64.deb"
        );

        assert_eq!(entries[1].package_name, "curl");
        assert_eq!(entries[1].version, "8.5.0-2ubuntu1");
    }

    #[test]
    fn test_parse_rpm_skips_incomplete_entries() {
        let xml = r#"<metadata>
<package type="rpm">
  <arch>x86_64</arch>
</package>
</metadata>"#;

        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_deb_skips_incomplete_entries() {
        let content = "Package: incomplete\n\n";
        let entries = parse_deb_packages_index(content, "main");
        assert_eq!(entries.len(), 0);
    }
}
