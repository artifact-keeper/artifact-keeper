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
    /// The VERBATIM `<package type="rpm">…</package>` block this entry was
    /// parsed from, retained so a curated snapshot publish (#2358 RPM Phase-3)
    /// can re-emit an upstream-faithful `primary.xml` — the NEVRA-only fields
    /// above drop the `<rpm:provides>`/`<rpm:requires>`/`<size>` that dnf needs
    /// to resolve dependencies. `None` for formats that do not carry a reusable
    /// XML block (e.g. Debian `Packages` index entries).
    pub primary_xml_snippet: Option<String>,
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

        // Retain the verbatim `<package type="rpm">…</package>` wrapper so a
        // curated snapshot publish can re-emit an upstream-faithful primary.xml
        // (preserves provides/requires/size the NEVRA extraction above drops).
        let primary_xml_snippet = Some(format!("<package type=\"rpm\">{pkg_block}</package>"));

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
            primary_xml_snippet,
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
            // Debian entries carry no reusable RPM XML block.
            primary_xml_snippet: None,
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

/// The `primary` data reference parsed from an RPM `repomd.xml`.
///
/// In the yum/RPM trust model the signature over `repomd.xml` PINS
/// `primary.xml.gz` through repomd's `<checksum>` (over the compressed file)
/// and `<open-checksum>` (over the decompressed file). Verifying the repomd
/// signature is therefore only half the chain — the fetched `primary.xml.gz`
/// must then be digested and compared to these pinned values before it is
/// parsed/ingested, or an attacker who can tamper the mirrored primary (MITM,
/// CDN/cache poisoning, or replaying a valid signed repomd while serving a
/// malicious primary at the href) defeats the signature (#2357).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepomdPrimaryRef {
    pub href: String,
    /// `<checksum type="...">` over the compressed `primary.xml.gz`.
    pub checksum_type: Option<String>,
    pub checksum: Option<String>,
    /// `<open-checksum type="...">` over the decompressed `primary.xml`.
    pub open_checksum_type: Option<String>,
    pub open_checksum: Option<String>,
}

/// Read the attribute value of the first `<tag ... attr="value" ...>` inside
/// `block`. Used to pull `type="sha256"` off a checksum element.
fn tag_attr(block: &str, tag_open: &str, attr: &str) -> Option<String> {
    let start = block.find(tag_open)?;
    let after = &block[start + tag_open.len()..];
    // Bound the attribute search to this tag (up to its closing '>').
    let tag_end = after.find('>')?;
    let tag_text = &after[..tag_end];
    let pat = format!("{}=\"", attr);
    let attr_start = tag_text.find(&pat)? + pat.len();
    let rest = &tag_text[attr_start..];
    let attr_end = rest.find('"')?;
    Some(rest[..attr_end].to_string())
}

/// Read the text content of the first `<tag ...>content</tag>` inside `block`.
fn tag_text_content(block: &str, tag_open: &str, tag_close: &str) -> Option<String> {
    let start = block.find(tag_open)?;
    let after = &block[start..];
    let content_start = after.find('>')? + 1;
    let content = &after[content_start..];
    let end = content.find(tag_close)?;
    Some(content[..end].trim().to_string())
}

/// Extract the full `primary` data reference (href + pinned checksums) from an
/// RPM `repomd.xml`. Returns `None` when no primary `<data>` block is present.
///
/// Kept next to [`parse_rpm_primary_xml`] as a pure, table-testable helper so
/// the sync path single-sources the parse logic (#2357 WI-1).
pub fn extract_primary_data(repomd: &str) -> Option<RepomdPrimaryRef> {
    // Tolerate multiple `<data type="primary">` blocks: return the first that
    // carries a `<location href>` (a block without one has nothing to fetch).
    repomd
        .split("<data type=\"primary\">")
        .skip(1)
        .filter_map(|data_block| {
            let block = data_block.split("</data>").next()?;
            // `href` is required — without a location there is nothing to fetch.
            let loc_start = block.find("<location href=\"")?;
            let href_rest = &block[loc_start + "<location href=\"".len()..];
            let href_end = href_rest.find('"')?;
            let href = href_rest[..href_end].to_string();

            // `<checksum type="...">value</checksum>` over the compressed file.
            // NOTE: search for `<checksum` (not a prefix of `<open-checksum`),
            // so the open-checksum element is not accidentally matched here.
            let (checksum_type, checksum) = if block.contains("<checksum") {
                (
                    tag_attr(block, "<checksum", "type"),
                    tag_text_content(block, "<checksum", "</checksum>"),
                )
            } else {
                (None, None)
            };
            let (open_checksum_type, open_checksum) = if block.contains("<open-checksum") {
                (
                    tag_attr(block, "<open-checksum", "type"),
                    tag_text_content(block, "<open-checksum", "</open-checksum>"),
                )
            } else {
                (None, None)
            };

            Some(RepomdPrimaryRef {
                href,
                checksum_type,
                checksum,
                open_checksum_type,
                open_checksum,
            })
        })
        .next()
}

/// Extract the `primary` data file href from an RPM `repomd.xml`. Thin wrapper
/// over [`extract_primary_data`] for callers that only need the location.
pub fn extract_primary_href(repomd: &str) -> Option<String> {
    extract_primary_data(repomd).map(|d| d.href)
}

/// Compute the lowercase hex digest of `bytes` using the named repodata
/// checksum algorithm (`sha256`, `sha`/`sha1`, `sha512`). Returns `None` for an
/// unsupported/unknown algorithm so the caller can fail closed. `sha` and
/// `sha1` are treated as SHA-1 (repodata historically labels SHA-1 as `sha`).
pub fn repodata_hex_digest(algo: &str, bytes: &[u8]) -> Option<String> {
    use sha2::Digest;
    match algo.trim().to_ascii_lowercase().as_str() {
        "sha256" => Some(hex::encode(sha2::Sha256::digest(bytes))),
        "sha512" => Some(hex::encode(sha2::Sha512::digest(bytes))),
        "sha1" | "sha" => Some(hex::encode(sha1::Sha1::digest(bytes))),
        _ => None,
    }
}

/// Fail-closed check that `bytes` matches the declared `(algo, expected)`
/// checksum from a signed repomd. Returns `false` when the algorithm is
/// unsupported, the expected value is empty, or the digests differ (constant
/// factors aside, a straightforward case-insensitive hex compare).
pub fn repodata_checksum_matches(algo: &str, expected_hex: &str, bytes: &[u8]) -> bool {
    let expected = expected_hex.trim();
    if expected.is_empty() {
        return false;
    }
    match repodata_hex_digest(algo, bytes) {
        Some(actual) => actual.eq_ignore_ascii_case(expected),
        None => false,
    }
}

/// Fail-closed decision for the RPM chain-of-trust (#2357): is the fetched
/// compressed `primary.xml.gz` bound to the (signed) repomd via its primary
/// `<checksum>`? Returns `false` when there is no primary ref, no usable
/// checksum, an unsupported algorithm, or the digests differ — so a
/// signature-verified sync ingests nothing unless `primary.xml.gz` matches the
/// checksum the signed repomd pins. Only consulted on the verified path; the
/// unverified (no-key) path stays backward-compatible.
pub fn primary_gz_pinned_by_repomd(
    primary_ref: Option<&RepomdPrimaryRef>,
    gz_bytes: &[u8],
) -> bool {
    match primary_ref {
        Some(d) => match (d.checksum_type.as_deref(), d.checksum.as_deref()) {
            (Some(ct), Some(cv)) => repodata_checksum_matches(ct, cv, gz_bytes),
            _ => false,
        },
        None => false,
    }
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

    // A realistic repomd primary block carries the compressed <checksum> that
    // PINS primary.xml.gz plus an <open-checksum> over the decompressed form.
    fn repomd_with_checksums(sha_gz: &str, sha_open: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
<repomd>
  <data type="filelists"><location href="repodata/filelists.xml.gz"/></data>
  <data type="primary">
    <checksum type="sha256">{sha_gz}</checksum>
    <open-checksum type="sha256">{sha_open}</open-checksum>
    <location href="repodata/abc-primary.xml.gz"/>
    <size>123</size>
  </data>
</repomd>"#
        )
    }

    #[test]
    fn test_extract_primary_data_reads_href_and_checksums() {
        let repomd = repomd_with_checksums("deadbeef", "cafef00d");
        let d = extract_primary_data(&repomd).expect("primary data present");
        assert_eq!(d.href, "repodata/abc-primary.xml.gz");
        assert_eq!(d.checksum_type.as_deref(), Some("sha256"));
        assert_eq!(d.checksum.as_deref(), Some("deadbeef"));
        // The open-checksum must NOT be confused with the compressed checksum.
        assert_eq!(d.open_checksum_type.as_deref(), Some("sha256"));
        assert_eq!(d.open_checksum.as_deref(), Some("cafef00d"));
    }

    #[test]
    fn test_repodata_hex_digest_algorithms() {
        // Known SHA-256 of the empty input pins the algorithm wiring.
        assert_eq!(
            repodata_hex_digest("sha256", b"").unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(repodata_hex_digest("sha1", b"abc").is_some());
        assert!(repodata_hex_digest("sha512", b"abc").is_some());
        // `sha` is the repodata label for SHA-1.
        assert_eq!(
            repodata_hex_digest("sha", b"abc"),
            repodata_hex_digest("sha1", b"abc")
        );
        // Unknown algorithm -> None (caller fails closed).
        assert!(repodata_hex_digest("md5", b"abc").is_none());
    }

    // The HIGH repro at the unit level: the fetched primary.xml.gz is only
    // trusted when it matches the checksum the signed repomd pins.
    #[test]
    fn test_primary_gz_pinned_by_repomd_match_and_mismatch() {
        let primary_gz = b"\x1f\x8b\x08fake-but-fixed-primary-bytes";
        let good = repodata_hex_digest("sha256", primary_gz).unwrap();
        let repomd = repomd_with_checksums(&good, "unused-open");
        let d = extract_primary_data(&repomd);

        // Matching bytes -> pinned (ingest allowed on the verified path).
        assert!(
            primary_gz_pinned_by_repomd(d.as_ref(), primary_gz),
            "primary.xml.gz matching the signed repomd <checksum> must be accepted"
        );

        // TAMPERED bytes (same href, different content) -> REJECTED. This is the
        // finding: a valid repomd signature must not authenticate a mutated
        // primary.
        let tampered = b"\x1f\x8b\x08EVIL-primary-bytes-swapped-by-attacker";
        assert!(
            !primary_gz_pinned_by_repomd(d.as_ref(), tampered),
            "a tampered primary.xml.gz must be rejected (checksum mismatch)"
        );

        // Signed repomd with NO usable primary <checksum> -> fail closed.
        let no_ck =
            r#"<repomd><data type="primary"><location href="repodata/p.xml.gz"/></data></repomd>"#;
        assert!(!primary_gz_pinned_by_repomd(
            extract_primary_data(no_ck).as_ref(),
            primary_gz
        ));

        // Unsupported checksum algorithm in repomd -> fail closed.
        let md5 = r#"<repomd><data type="primary"><checksum type="md5">00</checksum><location href="repodata/p.xml.gz"/></data></repomd>"#;
        assert!(!primary_gz_pinned_by_repomd(
            extract_primary_data(md5).as_ref(),
            primary_gz
        ));

        // No primary ref at all -> fail closed.
        assert!(!primary_gz_pinned_by_repomd(None, primary_gz));
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

    // #2358 RPM Phase-3: the verbatim `<package type="rpm">…</package>` block —
    // including the `<rpm:provides>`/`<rpm:requires>`/`<size>` the NEVRA-only
    // fields drop — must round-trip into `primary_xml_snippet` so a curated
    // snapshot publish can re-emit an upstream-faithful primary.xml.
    #[test]
    fn test_parse_rpm_primary_xml_retains_verbatim_snippet() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
<package type="rpm">
  <name>nginx</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.24.0" rel="1.el9"/>
  <checksum type="sha256" pkgid="YES">abc123def456</checksum>
  <size package="573440" installed="1048576" archive="1050624"/>
  <location href="Packages/nginx-1.24.0-1.el9.x86_64.rpm"/>
  <format>
    <rpm:provides>
      <rpm:entry name="nginx" flags="EQ" epoch="0" ver="1.24.0" rel="1.el9"/>
      <rpm:entry name="webserver"/>
    </rpm:provides>
    <rpm:requires>
      <rpm:entry name="libc.so.6()(64bit)"/>
      <rpm:entry name="openssl-libs" flags="GE" epoch="0" ver="3.0"/>
    </rpm:requires>
  </format>
</package>
</metadata>"#;

        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 1);

        let snippet = entries[0]
            .primary_xml_snippet
            .as_deref()
            .expect("rpm entry must retain a primary_xml_snippet");

        // The snippet is wrapped by the verbatim `<package type="rpm">` … tags.
        assert!(snippet.starts_with("<package type=\"rpm\">"));
        assert!(snippet.ends_with("</package>"));
        // The provides/requires/size the NEVRA fields drop survive in the snippet.
        assert!(snippet.contains("<rpm:provides>"));
        assert!(snippet.contains("name=\"webserver\""));
        assert!(snippet.contains("<rpm:requires>"));
        assert!(snippet.contains("name=\"openssl-libs\""));
        assert!(snippet.contains("<size package=\"573440\""));
        // The pkgid checksum (used as dnf's pkgid) is preserved verbatim.
        assert!(snippet.contains("pkgid=\"YES\">abc123def456</checksum>"));
    }

    // The Debian parser carries no reusable RPM block.
    #[test]
    fn test_parse_deb_packages_index_has_no_snippet() {
        let content = "Package: nginx\nVersion: 1.24.0-1\nArchitecture: amd64\nFilename: pool/main/n/nginx/nginx_1.24.0-1_amd64.deb\n";
        let entries = parse_deb_packages_index(content, "main");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].primary_xml_snippet.is_none());
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
