//! Homebrew bottle repository format (#5985).
//!
//! A bottle is the pre-built binary archive `brew` pours into the Cellar. It
//! is a gzip-compressed tar whose single top-level directory is the formula
//! name, holding the version directory, which in turn holds
//! `INSTALL_RECEIPT.json`:
//!
//! ```text
//! jq/1.7.1/INSTALL_RECEIPT.json
//! jq/1.7.1/bin/jq
//! ```
//!
//! `brew bottle` names the file `{name}--{version}.{tag}.bottle[.{rebuild}].tar.gz`
//! (double dash); the download URL a bottle host serves uses a single dash,
//! `{name}-{version}.{tag}.bottle[.{rebuild}].tar.gz`. Both spellings parse to
//! the same [`BottleName`], and [`BottleName::filename`] is the single
//! canonical spelling Artifact Keeper stores and serves.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Homebrew bottle format handler.
pub struct HomebrewHandler;

/// The coordinates a bottle filename carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BottleName {
    /// Formula name, e.g. `jq`, `python@3.12`, `gtk+3`.
    pub name: String,
    /// Formula version including any `_N` revision, e.g. `1.7.1`, `1.7.1_1`.
    pub version: String,
    /// Platform tag, e.g. `arm64_sonoma`, `x86_64_linux`, `all`.
    pub tag: String,
    /// Bottle rebuild number; 0 when the filename carries none.
    pub rebuild: u32,
}

const BOTTLE_SUFFIX: &str = ".tar.gz";

/// Cellar values `brew` accepts in a bottle's `cellar` field besides an
/// absolute path.
const SYMBOLIC_CELLARS: [&str; 2] = [":any", ":any_skip_relocation"];

impl BottleName {
    /// The canonical single-dash filename, as a bottle host serves it.
    pub fn filename(&self) -> String {
        if self.rebuild == 0 {
            format!(
                "{}-{}.{}.bottle{}",
                self.name, self.version, self.tag, BOTTLE_SUFFIX
            )
        } else {
            format!(
                "{}-{}.{}.bottle.{}{}",
                self.name, self.version, self.tag, self.rebuild, BOTTLE_SUFFIX
            )
        }
    }

    /// The path an artifact is stored under: `{name}/{version}/{filename}`.
    pub fn artifact_path(&self) -> String {
        format!("{}/{}/{}", self.name, self.version, self.filename())
    }
}

/// A formula name: lowercase letters, digits and `@ + . _ -`, as in homebrew-core.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"@+._-".contains(&b))
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && version.starts_with(|c: char| c.is_ascii_alphanumeric())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag.starts_with(|c: char| c.is_ascii_lowercase())
        && tag
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Split `{name}-{version}` where the separator is a single dash. A formula
/// name may itself contain dashes (`openssl-utils`), so the separator is the
/// first dash followed by a digit: versions start with one, and a name segment
/// that does is rare enough that the `--` spelling is the unambiguous escape.
fn split_single_dash(stem: &str) -> Option<(&str, &str)> {
    let bytes = stem.as_bytes();
    (1..bytes.len().saturating_sub(1))
        .find(|&i| bytes[i] == b'-' && bytes[i + 1].is_ascii_digit())
        .map(|i| (&stem[..i], &stem[i + 1..]))
}

impl HomebrewHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a bottle filename in either the `--` or the `-` spelling.
    pub fn parse_bottle_filename(filename: &str) -> Result<BottleName> {
        let invalid = |why: &str| {
            AppError::Validation(format!(
                "Invalid Homebrew bottle filename '{filename}': {why}"
            ))
        };

        let stem = filename
            .strip_suffix(BOTTLE_SUFFIX)
            .ok_or_else(|| invalid("expected a .tar.gz bottle"))?;

        // `.bottle` or `.bottle.{rebuild}`.
        let (stem, rebuild) = match stem.rsplit_once(".bottle") {
            Some((rest, "")) => (rest, 0),
            Some((rest, n)) => {
                let n = n
                    .strip_prefix('.')
                    .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|n| n.parse::<u32>().ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| invalid("bad rebuild number"))?;
                (rest, n)
            }
            None => return Err(invalid("missing .bottle")),
        };

        let (stem, tag) = stem
            .rsplit_once('.')
            .ok_or_else(|| invalid("missing platform tag"))?;
        let (name, version) = match stem.split_once("--") {
            Some(pair) => pair,
            None => split_single_dash(stem).ok_or_else(|| invalid("missing version"))?,
        };

        if !valid_name(name) {
            return Err(invalid("bad formula name"));
        }
        if !valid_version(version) {
            return Err(invalid("bad version"));
        }
        if !valid_tag(tag) {
            return Err(invalid("bad platform tag"));
        }

        Ok(BottleName {
            name: name.to_string(),
            version: version.to_string(),
            tag: tag.to_string(),
            rebuild,
        })
    }

    /// Validate the `cellar` value an uploader supplies: `:any`,
    /// `:any_skip_relocation`, or an absolute path.
    pub fn validate_cellar(cellar: &str) -> Result<()> {
        let ok = SYMBOLIC_CELLARS.contains(&cellar)
            || (cellar.starts_with('/')
                && cellar.len() <= 256
                && !cellar.contains("..")
                && cellar.bytes().all(|b| b.is_ascii_graphic()));
        if ok {
            Ok(())
        } else {
            Err(AppError::Validation(format!(
                "Invalid cellar '{cellar}': use :any, :any_skip_relocation or an absolute path"
            )))
        }
    }

    /// Check that an uploaded archive is a bottle for `bottle`: its
    /// `{name}/{version}/INSTALL_RECEIPT.json` must exist. A filename that
    /// disagrees with the archive contents would publish one formula's bytes
    /// under another's name.
    ///
    /// Blocking and decompression-bounded; callers run it inside
    /// `bounded_archive::with_ingest_extraction`.
    pub fn verify_bottle_contents(bottle: &BottleName, archive: &[u8]) -> Result<()> {
        let expected = format!("{}/{}/INSTALL_RECEIPT.json", bottle.name, bottle.version);
        let found = crate::util::bounded_archive::read_metadata_from_tar_gz(archive, |path| {
            path.to_string_lossy().trim_start_matches("./") == expected
        })?;
        match found {
            Some(receipt) => {
                serde_json::from_slice::<serde_json::Value>(&receipt).map_err(|e| {
                    AppError::Validation(format!("Invalid INSTALL_RECEIPT.json: {e}"))
                })?;
                Ok(())
            }
            None => Err(AppError::Validation(format!(
                "Not a bottle for {} {}: {expected} not found in the archive",
                bottle.name, bottle.version
            ))),
        }
    }
}

impl Default for HomebrewHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the bottle filename from a stored artifact path
/// (`{name}/{version}/{filename}`) or a bare filename.
fn filename_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[async_trait]
impl FormatHandler for HomebrewHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Homebrew
    }

    fn format_key(&self) -> &str {
        "homebrew"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let bottle = Self::parse_bottle_filename(filename_of(path))?;
        Ok(serde_json::to_value(bottle).unwrap_or_else(|_| serde_json::json!({})))
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_bottle_filename(filename_of(path))?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // The formula JSON is rendered on demand from live rows.
        Ok(None)
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn parse(f: &str) -> BottleName {
        HomebrewHandler::parse_bottle_filename(f).unwrap()
    }

    fn bottle_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (path, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn parses_the_double_dash_brew_bottle_spelling() {
        let b = parse("jq--1.7.1.arm64_sonoma.bottle.tar.gz");
        assert_eq!(
            b,
            BottleName {
                name: "jq".into(),
                version: "1.7.1".into(),
                tag: "arm64_sonoma".into(),
                rebuild: 0,
            }
        );
    }

    #[test]
    fn parses_the_single_dash_download_spelling_and_rebuild() {
        let b = parse("jq-1.7.1_1.x86_64_linux.bottle.2.tar.gz");
        assert_eq!(b.name, "jq");
        assert_eq!(b.version, "1.7.1_1");
        assert_eq!(b.tag, "x86_64_linux");
        assert_eq!(b.rebuild, 2);
    }

    #[test]
    fn both_spellings_canonicalise_to_the_single_dash_filename() {
        let a = parse("jq--1.7.1.all.bottle.tar.gz");
        let b = parse("jq-1.7.1.all.bottle.tar.gz");
        assert_eq!(a, b);
        assert_eq!(a.filename(), "jq-1.7.1.all.bottle.tar.gz");
        assert_eq!(a.artifact_path(), "jq/1.7.1/jq-1.7.1.all.bottle.tar.gz");
    }

    #[test]
    fn names_with_dashes_and_symbols_parse() {
        let b = parse("openssl-utils-3.3.0.arm64_sonoma.bottle.tar.gz");
        assert_eq!(
            (b.name.as_str(), b.version.as_str()),
            ("openssl-utils", "3.3.0")
        );
        let b = parse("python@3.12--3.12.4.arm64_sonoma.bottle.tar.gz");
        assert_eq!(
            (b.name.as_str(), b.version.as_str()),
            ("python@3.12", "3.12.4")
        );
        let b = parse("gtk+3-3.24.43.x86_64_linux.bottle.tar.gz");
        assert_eq!((b.name.as_str(), b.version.as_str()), ("gtk+3", "3.24.43"));
    }

    #[test]
    fn double_dash_resolves_a_name_that_has_a_dash_before_a_digit() {
        let b = parse("lib-2to3--1.0.all.bottle.tar.gz");
        assert_eq!((b.name.as_str(), b.version.as_str()), ("lib-2to3", "1.0"));
    }

    #[test]
    fn rejects_malformed_filenames() {
        for bad in [
            "jq-1.7.1.arm64_sonoma.bottle.zip",
            "jq-1.7.1.arm64_sonoma.tar.gz",
            "jq-1.7.1.arm64_sonoma.bottle.0.tar.gz",
            "jq-1.7.1.arm64_sonoma.bottle.x.tar.gz",
            "jq-1.7.1.arm64_sonoma.bottle.-1.tar.gz",
            "jq.bottle.tar.gz",
            "jq.arm64_sonoma.bottle.tar.gz",
            "--1.0.all.bottle.tar.gz",
            "JQ--1.0.all.bottle.tar.gz",
            "../jq--1.0.all.bottle.tar.gz",
            "jq--1.0.ARM.bottle.tar.gz",
            "jq--.all.bottle.tar.gz",
            "jq--1.0.bottle.tar.gz",
        ] {
            assert!(
                HomebrewHandler::parse_bottle_filename(bad).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn rebuild_filename_round_trips() {
        let b = parse("jq--1.7.1.all.bottle.3.tar.gz");
        assert_eq!(b.filename(), "jq-1.7.1.all.bottle.3.tar.gz");
        assert_eq!(parse(&b.filename()), b);
    }

    #[test]
    fn cellar_accepts_symbols_and_absolute_paths_only() {
        for ok in [
            ":any",
            ":any_skip_relocation",
            "/opt/homebrew/Cellar",
            "/usr/local/Cellar",
        ] {
            assert!(HomebrewHandler::validate_cellar(ok).is_ok(), "{ok}");
        }
        for bad in ["", "any", "Cellar", "/opt/../etc", "/a b", ":other"] {
            assert!(HomebrewHandler::validate_cellar(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn verifies_a_bottle_whose_contents_match_its_name() {
        let b = parse("jq--1.7.1.all.bottle.tar.gz");
        let archive = bottle_archive(&[
            (
                "jq/1.7.1/INSTALL_RECEIPT.json",
                br#"{"built_as_bottle":true}"#,
            ),
            ("jq/1.7.1/bin/jq", b"#!/bin/sh\n"),
        ]);
        HomebrewHandler::verify_bottle_contents(&b, &archive).unwrap();
    }

    #[test]
    fn rejects_a_bottle_for_a_different_formula_or_version() {
        let archive = bottle_archive(&[("jq/1.7.1/INSTALL_RECEIPT.json", b"{}")]);
        for name in ["yq--1.7.1.all.bottle.tar.gz", "jq--1.7.2.all.bottle.tar.gz"] {
            let err = HomebrewHandler::verify_bottle_contents(&parse(name), &archive)
                .unwrap_err()
                .to_string();
            assert!(err.contains("INSTALL_RECEIPT.json not found"), "{err}");
        }
    }

    #[test]
    fn rejects_non_json_receipt_and_non_archives() {
        let b = parse("jq--1.7.1.all.bottle.tar.gz");
        let archive = bottle_archive(&[("jq/1.7.1/INSTALL_RECEIPT.json", b"not json")]);
        assert!(HomebrewHandler::verify_bottle_contents(&b, &archive).is_err());
        assert!(HomebrewHandler::verify_bottle_contents(&b, b"plain text").is_err());
    }

    #[tokio::test]
    async fn format_handler_reports_homebrew() {
        let h = HomebrewHandler::new();
        assert_eq!(h.format_key(), "homebrew");
        assert_eq!(h.format(), RepositoryFormat::Homebrew);
        let meta = h
            .parse_metadata("jq/1.7.1/jq-1.7.1.all.bottle.tar.gz", &Bytes::new())
            .await
            .unwrap();
        assert_eq!(meta["name"], "jq");
        assert_eq!(meta["tag"], "all");
        assert!(h
            .validate("jq/1.7.1/not-a-bottle.zip", &Bytes::new())
            .await
            .is_err());
        assert!(h.generate_index().await.unwrap().is_none());
    }
}
