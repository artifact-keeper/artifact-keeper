//! Alpine APK format handler.
//!
//! Implements Alpine Linux APK package repository support.
//! APK packages are tar.gz archives containing PKGINFO metadata.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Alpine APK format handler
pub struct AlpineHandler;

impl AlpineHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse APK package path.
    ///
    /// Formats:
    ///   `<arch>/APKINDEX.tar.gz`           - Repository index
    ///   `<arch>/<name>-<version>.apk`      - Package file
    pub fn parse_path(path: &str) -> Result<AlpinePathInfo> {
        let path = path.trim_start_matches('/');
        let parts: Vec<&str> = path.splitn(2, '/').collect();

        match parts.as_slice() {
            [arch, filename] if *filename == "APKINDEX.tar.gz" => Ok(AlpinePathInfo {
                arch: arch.to_string(),
                name: None,
                version: None,
                is_index: true,
            }),
            [arch, filename] if filename.ends_with(".apk") => {
                let stem = filename.trim_end_matches(".apk");
                // APK filename: <name>-<version>-r<revision>.apk
                // Version can contain dots and hyphens; find the pattern
                let (name, version) = Self::parse_apk_filename(stem)?;
                Ok(AlpinePathInfo {
                    arch: arch.to_string(),
                    name: Some(name),
                    version: Some(version),
                    is_index: false,
                })
            }
            _ => Err(AppError::Validation(format!("Invalid APK path: {}", path))),
        }
    }

    /// Parse APK filename to extract name and version.
    /// Format: `<name>-<version>-r<revision>`
    fn parse_apk_filename(stem: &str) -> Result<(String, String)> {
        // Find version boundary: first hyphen followed by a digit
        let mut split_idx = None;
        let chars: Vec<char> = stem.chars().collect();
        for i in 1..chars.len() {
            if chars[i - 1] == '-' && chars[i].is_ascii_digit() {
                split_idx = Some(i - 1);
                break;
            }
        }

        match split_idx {
            Some(idx) => {
                let name = &stem[..idx];
                let version = &stem[idx + 1..];
                Ok((name.to_string(), version.to_string()))
            }
            None => Err(AppError::Validation(format!(
                "Cannot parse APK filename: {}",
                stem
            ))),
        }
    }

    /// Extract PKGINFO from an APK package, signed or not (#5170): the gzip
    /// members are read by the same reader the proxy scan gate uses.
    pub fn extract_pkginfo(content: &[u8]) -> Result<PkgInfo> {
        let text = crate::api::handlers::proxy_scan_archive::read_apk_pkginfo_for_metadata(content)
            .map_err(|e| AppError::Validation(format!("Invalid APK package: {e}")))?;
        Self::parse_pkginfo(&text)
    }

    /// Parse PKGINFO key=value format.
    fn parse_pkginfo(content: &str) -> Result<PkgInfo> {
        let mut info = PkgInfo::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(" = ") {
                match key {
                    "pkgname" => info.pkgname = value.to_string(),
                    "pkgver" => info.pkgver = value.to_string(),
                    "pkgdesc" => info.pkgdesc = Some(value.to_string()),
                    "url" => info.url = Some(value.to_string()),
                    "size" => info.size = value.parse().ok(),
                    "arch" => info.arch = value.to_string(),
                    "license" => info.license = Some(value.to_string()),
                    "origin" => info.origin = Some(value.to_string()),
                    "depend" => info.depends.push(value.to_string()),
                    "provides" => info.provides.push(value.to_string()),
                    _ => {}
                }
            }
        }

        if info.pkgname.is_empty() {
            return Err(AppError::Validation("PKGINFO missing pkgname".to_string()));
        }

        Ok(info)
    }
}

impl Default for AlpineHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for AlpineHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Alpine
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "arch": info.arch,
            "is_index": info.is_index,
        });

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }
        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        if !content.is_empty() && !info.is_index {
            if let Ok(pkginfo) = Self::extract_pkginfo(content) {
                metadata["pkginfo"] = serde_json::to_value(&pkginfo)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // APKINDEX is generated on demand from DB state
        Ok(None)
    }
}

/// Alpine package path info
#[derive(Debug)]
pub struct AlpinePathInfo {
    pub arch: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub is_index: bool,
}

/// Parsed .PKGINFO content
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PkgInfo {
    pub pkgname: String,
    pub pkgver: String,
    pub pkgdesc: Option<String>,
    pub url: Option<String>,
    pub size: Option<u64>,
    pub arch: String,
    pub license: Option<String>,
    pub origin: Option<String>,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_apk_path() {
        let info = AlpineHandler::parse_path("x86_64/curl-8.5.0-r0.apk").unwrap();
        assert_eq!(info.arch, "x86_64");
        assert_eq!(info.name, Some("curl".to_string()));
        assert_eq!(info.version, Some("8.5.0-r0".to_string()));
        assert!(!info.is_index);
    }

    #[test]
    fn test_parse_apk_index_path() {
        let info = AlpineHandler::parse_path("x86_64/APKINDEX.tar.gz").unwrap();
        assert_eq!(info.arch, "x86_64");
        assert!(info.is_index);
    }

    #[test]
    fn test_parse_pkginfo() {
        let content = r#"pkgname = curl
pkgver = 8.5.0-r0
pkgdesc = URL retrieval utility and library
url = https://curl.se/
arch = x86_64
license = MIT
depend = libcurl
depend = ca-certificates
provides = cmd:curl"#;
        let info = AlpineHandler::parse_pkginfo(content).unwrap();
        assert_eq!(info.pkgname, "curl");
        assert_eq!(info.pkgver, "8.5.0-r0");
        assert_eq!(info.depends.len(), 2);
        assert_eq!(info.provides.len(), 1);
    }

    // ========================================================================
    // #3672: `tar` inflates GNU LongName (`L`) / LongLink (`K`) / PAX (`x`)
    // extension records inside `entries().next()`, before any per-entry bound
    // can run, so the ingest budget has to wrap the decoded stream itself.
    // Fixtures go through the `tar::Header` API because `tar::Builder` never
    // emits an extension record on request.
    // ========================================================================

    /// Write one tar member: a header declaring `size` bytes of `kind`, then
    /// `prefix` padded out with `b'a'` to `size`, then block padding. The body
    /// is streamed so a record declaring hundreds of MiB costs no memory to
    /// build.
    fn write_member(
        out: &mut impl std::io::Write,
        name: &str,
        kind: tar::EntryType,
        prefix: &[u8],
        size: u64,
    ) {
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_entry_type(kind);
        header.set_mode(0o644);
        header.set_size(size);
        header.set_cksum();
        out.write_all(header.as_bytes()).unwrap();
        out.write_all(prefix).unwrap();
        let fill = [b'a'; 64 * 1024];
        let mut remaining = size - prefix.len() as u64;
        while remaining > 0 {
            let n = remaining.min(fill.len() as u64) as usize;
            out.write_all(&fill[..n]).unwrap();
            remaining -= n as u64;
        }
        out.write_all(&vec![0u8; (512 - (size % 512) as usize) % 512])
            .unwrap();
    }

    /// A gzip'd tar whose first member is an extension record of `kind`
    /// declaring `size` bytes, followed by the regular file `target`.
    fn extension_record_tgz(
        kind: tar::EntryType,
        size: u64,
        target: (&str, &[u8]),
        level: flate2::Compression,
    ) -> Vec<u8> {
        use std::io::Write;
        let (name, prefix) = match kind {
            // `<len> <key>=<value>\n`: the value is the fill and is never
            // reached, so only the length/key prefix has to be well-formed.
            tar::EntryType::XHeader => ("PaxHeader/x", format!("{size} comment=").into_bytes()),
            tar::EntryType::GNULongLink => ("././@LongLink", Vec::new()),
            _ => ("././@LongName", Vec::new()),
        };
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), level);
        write_member(&mut gz, name, kind, &prefix, size);
        write_member(
            &mut gz,
            target.0,
            tar::EntryType::Regular,
            target.1,
            target.1.len() as u64,
        );
        gz.write_all(&[0u8; 1024]).unwrap();
        gz.finish().unwrap()
    }

    /// A gzip'd tar of regular files built with `tar::Builder`, which writes a
    /// *legitimate* GNU LongName record for any path over 100 characters.
    fn build_tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (path, body) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_buf).unwrap();
        gz.finish().unwrap()
    }

    /// A record just past the shared ingest budget: enough to trip it, small
    /// enough that a build which does *not* bound the reader still finishes.
    fn over_budget() -> u64 {
        crate::util::bounded_archive::max_ingest_decompressed_bytes() + 1024 * 1024
    }

    fn assert_budget_refused(label: &str, err: AppError) {
        match err {
            AppError::Validation(msg) => assert!(
                msg.contains("decompression budget exceeded"),
                "{label}: unexpected error: {msg}"
            ),
            other => panic!("{label}: expected Validation error, got {other:?}"),
        }
    }

    const PKGINFO: &[u8] = b"pkgname = curl\npkgver = 8.5.0-r0\narch = x86_64\n";

    /// #3672: a GNU LongName record declaring more than the ingest budget is
    /// refused at the budget, not inflated in full inside `entries().next()`.
    #[test]
    fn test_extract_pkginfo_extension_record_bounded_3672() {
        let size = over_budget();
        let apk = extension_record_tgz(
            tar::EntryType::GNULongName,
            size,
            (".PKGINFO", PKGINFO),
            flate2::Compression::fast(),
        );
        // Compresses to a sliver of what it declares: the upload-size limit is
        // no defence.
        assert!(
            (apk.len() as u64) * 32 < size,
            "{} bytes on the wire",
            apk.len()
        );
        let err = AlpineHandler::extract_pkginfo(&apk).unwrap_err();
        assert_budget_refused("GNU LongName", err);
    }

    /// Control: a legitimate LongName (a path over 100 characters) ahead of
    /// `.PKGINFO` still parses.
    #[test]
    fn test_extract_pkginfo_long_path_parses_3672() {
        let long_dir = "a".repeat(120);
        let apk = build_tgz(&[
            (&format!("usr/share/{long_dir}/doc"), b"doc"),
            (".PKGINFO", PKGINFO),
        ]);
        let info = AlpineHandler::extract_pkginfo(&apk).unwrap();
        assert_eq!(info.pkgname, "curl");
        assert_eq!(info.pkgver, "8.5.0-r0");
    }

    // ========================================================================
    // #5170: a signed `.apk` is a run of gzip members, signature first.
    // ========================================================================

    const RICH_PKGINFO: &[u8] = b"# Generated by abuild 3.13\npkgname = curl\npkgver = 8.5.0-r0\n\
        pkgdesc = URL retrieval\nurl = https://curl.se/\nsize = 42\narch = x86_64\n\
        license = curl\norigin = curl\ndepend = so:libc.musl-x86_64.so.1\nprovides = cmd:curl\n";

    /// `(signature, control with `pkginfo`, data)`, as `abuild-sign` lays one out.
    fn signed_apk(pkginfo: &[u8], data: &[u8]) -> Vec<u8> {
        let mut apk = build_tgz(&[(".SIGN.RSA.alpine-devel.rsa.pub", b"signature")]);
        apk.extend(build_tgz(&[(".PKGINFO", pkginfo)]));
        apk.extend(build_tgz(&[("usr/bin/curl", data)]));
        apk
    }

    #[test]
    fn test_extract_pkginfo_reads_a_signed_apk_5170() {
        let info = AlpineHandler::extract_pkginfo(&signed_apk(RICH_PKGINFO, b"elf")).unwrap();
        assert_eq!(info.pkgname, "curl");
        assert_eq!(info.pkgver, "8.5.0-r0");
        assert_eq!(info.arch, "x86_64");
        assert_eq!(info.pkgdesc.as_deref(), Some("URL retrieval"));
        assert_eq!(info.license.as_deref(), Some("curl"));
        assert_eq!(info.origin.as_deref(), Some("curl"));
        assert_eq!(info.size, Some(42));
        assert_eq!(info.depends, vec!["so:libc.musl-x86_64.so.1".to_string()]);
        assert_eq!(info.provides, vec!["cmd:curl".to_string()]);
    }

    /// The reported bug: `parse_metadata` silently dropped it.
    #[tokio::test]
    async fn test_parse_metadata_keeps_a_signed_apks_pkginfo_5170() {
        let apk = Bytes::from(signed_apk(RICH_PKGINFO, b"elf"));
        let metadata = AlpineHandler::new()
            .parse_metadata("x86_64/curl-8.5.0-r0.apk", &apk)
            .await
            .unwrap();
        assert_eq!(metadata["pkginfo"]["pkgname"], "curl");
        assert_eq!(metadata["pkginfo"]["license"], "curl");
        // What callers read from the document before is unchanged.
        assert_eq!(metadata["name"], "curl");
        assert_eq!(metadata["version"], "8.5.0-r0");
        assert_eq!(metadata["arch"], "x86_64");
        assert_eq!(metadata["is_index"], false);
    }

    /// A package whose data segment alone exceeds the ingest budget keeps its
    /// metadata: `.PKGINFO` comes first, so the data segment is never decoded.
    #[test]
    fn test_extract_pkginfo_does_not_decode_the_data_segment_5170() {
        let data = vec![b'a'; over_budget() as usize];
        let info = AlpineHandler::extract_pkginfo(&signed_apk(RICH_PKGINFO, &data)).unwrap();
        assert_eq!(info.pkgname, "curl");
    }

    /// #3672 still holds across members: a bomb in the segment after the
    /// signature is refused at the ingest budget, not the gate's larger one.
    #[test]
    fn test_extract_pkginfo_bomb_behind_the_signature_is_bounded_5170() {
        let mut apk = build_tgz(&[(".SIGN.RSA.alpine-devel.rsa.pub", b"signature")]);
        apk.extend(extension_record_tgz(
            tar::EntryType::GNULongName,
            over_budget(),
            (".PKGINFO", PKGINFO),
            flate2::Compression::fast(),
        ));
        assert_budget_refused(
            "behind the signature",
            AlpineHandler::extract_pkginfo(&apk).unwrap_err(),
        );
    }

    /// A signed package with no `.PKGINFO` is still an error to the reader and
    /// still no `pkginfo` to `parse_metadata`, which does not fail the package.
    #[tokio::test]
    async fn test_a_signed_apk_without_pkginfo_has_no_pkginfo_metadata_5170() {
        let mut apk = build_tgz(&[(".SIGN.RSA.alpine-devel.rsa.pub", b"signature")]);
        apk.extend(build_tgz(&[("usr/bin/curl", b"elf")]));
        assert!(AlpineHandler::extract_pkginfo(&apk).is_err());
        let metadata = AlpineHandler::new()
            .parse_metadata("x86_64/curl-8.5.0-r0.apk", &Bytes::from(apk))
            .await
            .unwrap();
        assert!(metadata.get("pkginfo").is_none());
        assert_eq!(metadata["name"], "curl");
    }
}
