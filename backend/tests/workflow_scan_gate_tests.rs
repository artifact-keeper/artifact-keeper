//! Contract tests for the container-scan publication gate (#2609).
//!
//! `.github/workflows/docker-publish.yml` states a policy: CRITICAL/HIGH
//! CVEs with an available fix block image publication, with `.trivyignore`
//! as the documented exception path. These tests pin the wiring that makes
//! that claim true, so none of it can be loosened silently:
//!
//!   1. every scanned image is covered by BOTH Trivy passes — a visibility
//!      pass and an enforcement pass (see below),
//!   2. the enforcement pass actually enforces the stated policy
//!      (`exit-code: '1'`, `CRITICAL,HIGH`, `ignore-unfixed`, `.trivyignore`,
//!      and a non-SARIF format so the severity filter survives), and
//!   3. every `merge-*` job `needs: scan-containers` (a failing scan stops
//!      tag publication, not just the scan job itself).
//!
//! # Why two passes, and why this file used to be wrong (#3437)
//!
//! Until #3122 the workflow ran ONE Trivy step per image: SARIF format,
//! `severity: CRITICAL,HIGH`, `exit-code: '1'`. `aquasecurity/trivy-action`
//! runs `unset TRIVY_SEVERITY` whenever the format is SARIF and
//! `limit-severities-for-sarif` is not exactly `true`, so that step discarded
//! its own filter and blocked publication on a fixable CVE of ANY severity —
//! a LOW stopped every publish from `main` for days (#3121).
//!
//! #3122 split it in two, per image:
//!
//!   * a VISIBILITY pass (`format: sarif`, `exit-code: '0'`, no `severity:`)
//!     that feeds the Security tab at every severity and never blocks, and
//!   * an ENFORCEMENT pass (`format: table`, `severity: CRITICAL,HIGH`,
//!     `exit-code: '1'`) that is the control the merge jobs depend on.
//!
//! The #2609 guard here predated that split and asserted that EVERY Trivy
//! step carries `exit-code: '1'`, so from #3122 onward it failed on the
//! visibility pass — reporting the gate as disabled while it was in fact
//! working. Three of its four assertions only ever made sense on the
//! enforcement pass. The guard now models the pair, which is stronger than
//! filtering to the enforcement pass alone: a workflow that quietly dropped
//! its enforcement pass entirely would satisfy a filter-based check
//! vacuously, and fails this one.
//!
//! `scripts/ci/check-trivy-gate-severity.sh` is the sibling of these tests
//! and covers the same policy from the other side (every GATING step in every
//! workflow applies the severity filter it declares). It is deliberately kept
//! separate: it runs in `shell-tests` with no Rust compile, and it is
//! repo-wide rather than docker-publish-specific.
//!
//! They parse the workflow YAML directly; no network, no Docker, no DB.
//! CI runs this target explicitly from the Tier 1 `test-backend-unit` job —
//! see the comment there for why it cannot live in the Tier 2 `--test`
//! allowlist.

use serde_yaml::Value;
use std::collections::BTreeMap;
use std::path::Path;

fn load_docker_publish_workflow() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".github")
        .join("workflows")
        .join("docker-publish.yml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_yaml::from_str(&raw).expect("docker-publish.yml is not valid YAML")
}

fn jobs(workflow: &Value) -> &serde_yaml::Mapping {
    workflow
        .get("jobs")
        .and_then(Value::as_mapping)
        .expect("workflow has a `jobs` mapping")
}

/// A Trivy step, reduced to what the policy is stated in terms of.
struct TrivyStep {
    job: String,
    name: String,
    /// The `with.image-ref` value, e.g. `${{ steps.refs.outputs.backend }}`.
    /// Two steps that scan the same image share this string exactly.
    image_ref: String,
    format: String,
    exit_code: String,
    severity: Option<String>,
    ignore_unfixed: Option<bool>,
    trivyignores: Option<String>,
}

impl TrivyStep {
    /// The enforcement pass is the one that can fail the job. `exit-code` is
    /// the whole definition: it is what the merge jobs' `needs:` edge reacts
    /// to, and what #2609 exists to keep non-zero.
    fn is_enforcement(&self) -> bool {
        self.exit_code != "0"
    }

    fn where_(&self) -> String {
        format!("{} / {}", self.job, self.name)
    }
}

/// All steps across all jobs that invoke the aquasecurity/trivy-action.
fn trivy_scan_steps(workflow: &Value) -> Vec<TrivyStep> {
    let mut found = Vec::new();
    for (job_name, job) in jobs(workflow) {
        let Some(steps) = job.get("steps").and_then(Value::as_sequence) else {
            continue;
        };
        for step in steps {
            let uses = step.get("uses").and_then(Value::as_str).unwrap_or("");
            if !uses.starts_with("aquasecurity/trivy-action@") {
                continue;
            }
            let with = step
                .get("with")
                .unwrap_or_else(|| panic!("trivy step in {job_name:?} has no `with`"));
            let str_input = |key: &str| with.get(key).and_then(Value::as_str).map(str::to_string);
            found.push(TrivyStep {
                job: job_name.as_str().unwrap_or("<job>").to_string(),
                name: step
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>")
                    .to_string(),
                image_ref: str_input("image-ref").unwrap_or_else(|| {
                    panic!("trivy step in {job_name:?} declares no `image-ref`")
                }),
                // trivy-action's own default when the input is omitted.
                format: str_input("format").unwrap_or_else(|| "table".to_string()),
                // Likewise: an omitted `exit-code` means "report only".
                exit_code: str_input("exit-code").unwrap_or_else(|| "0".to_string()),
                severity: str_input("severity"),
                ignore_unfixed: with.get("ignore-unfixed").and_then(Value::as_bool),
                trivyignores: str_input("trivyignores"),
            });
        }
    }
    found
}

/// Group the Trivy steps by the image they scan, preserving nothing else.
fn steps_by_image(steps: Vec<TrivyStep>) -> BTreeMap<String, Vec<TrivyStep>> {
    let mut by_image: BTreeMap<String, Vec<TrivyStep>> = BTreeMap::new();
    for step in steps {
        by_image
            .entry(step.image_ref.clone())
            .or_default()
            .push(step);
    }
    by_image
}

/// Wiring half 1a: every scanned image gets BOTH passes, exactly once each.
///
/// This is the assertion that makes the guard non-vacuous. Filtering to
/// enforcement-pass steps and checking those would pass a workflow that had
/// silently lost its enforcement pass altogether — precisely the regression
/// #2609 exists to catch. Requiring the pair also pins that no image is
/// scanned for visibility alone, and that nobody adds a third pass whose role
/// is ambiguous.
#[test]
fn every_scanned_image_is_covered_by_both_trivy_passes() {
    let workflow = load_docker_publish_workflow();
    let by_image = steps_by_image(trivy_scan_steps(&workflow));

    assert!(
        by_image.len() >= 3,
        "expected the backend/openscap/scanner-adapter images to be scanned in \
         docker-publish.yml; found {} distinct image-refs. If the scanner moved \
         or the images were renamed, move this contract test with them",
        by_image.len()
    );

    for (image, steps) in &by_image {
        let enforcement: Vec<&TrivyStep> = steps.iter().filter(|s| s.is_enforcement()).collect();
        let visibility: Vec<&TrivyStep> = steps.iter().filter(|s| !s.is_enforcement()).collect();
        let listing: Vec<String> = steps
            .iter()
            .map(|s| {
                format!(
                    "{} (exit-code {}, format {})",
                    s.where_(),
                    s.exit_code,
                    s.format
                )
            })
            .collect();

        assert_eq!(
            enforcement.len(),
            1,
            "{image}: expected exactly ONE enforcement Trivy pass (non-zero \
             exit-code) — that is the step the merge jobs' `needs:` edge reacts \
             to (#2609). Found {}: {listing:?}",
            enforcement.len()
        );
        assert_eq!(
            visibility.len(),
            1,
            "{image}: expected exactly ONE visibility Trivy pass (exit-code \
             '0', SARIF to the Security tab) alongside the enforcement pass \
             (#3122). Found {}: {listing:?}",
            visibility.len()
        );
    }
}

/// Wiring half 1b: the enforcement pass must enforce the policy as stated.
/// `exit-code: '0'` on this pass is exactly the report-but-don't-enforce
/// regression #2609 closed; if a scan needs to be unblocked, the exception
/// path is a justified `.trivyignore` entry, not an exit-code downgrade.
#[test]
fn trivy_enforcement_pass_gates_on_the_stated_policy() {
    let workflow = load_docker_publish_workflow();
    let steps = trivy_scan_steps(&workflow);
    let enforcement: Vec<&TrivyStep> = steps.iter().filter(|s| s.is_enforcement()).collect();
    assert!(
        !enforcement.is_empty(),
        "docker-publish.yml has no ENFORCING Trivy step (none with a non-zero \
         `exit-code`), so a CRITICAL/HIGH finding blocks nothing (#2609)"
    );

    for step in enforcement {
        let at = step.where_();
        assert_eq!(
            step.exit_code, "1",
            "{at}: the enforcing Trivy pass must use exit-code '1'; \
             use .trivyignore for exceptions (#2609)"
        );
        // The stated scope of the policy: fixable CRITICAL/HIGH only.
        assert_eq!(
            step.severity.as_deref(),
            Some("CRITICAL,HIGH"),
            "{at}: severity scope drifted from the stated policy"
        );
        // ...and the filter has to survive the action. trivy-action does
        // `unset TRIVY_SEVERITY` for SARIF unless `limit-severities-for-sarif`
        // is exactly "true", which is what made a LOW block every publish from
        // main for days (#3121/#3122). A gating pass must not be SARIF.
        assert_ne!(
            step.format, "sarif",
            "{at}: a gating Trivy pass must not use `format: sarif` — \
             trivy-action discards `severity:` for SARIF, so the step would \
             block on a fixable CVE of ANY severity (#3122)"
        );
        assert_eq!(
            step.ignore_unfixed,
            Some(true),
            "{at}: ignore-unfixed keeps unfixable base-image CVEs \
             report-only; removing it changes the stated policy"
        );
        assert_eq!(
            step.trivyignores.as_deref(),
            Some(".trivyignore"),
            "{at}: .trivyignore is the documented exception path"
        );
    }
}

/// Wiring half 1c: the visibility pass must not block, and must not pretend
/// to filter. It exists to feed the Security tab at ALL severities; declaring
/// a `severity:` there only creates the illusion of a filter, because
/// trivy-action throws that input away for SARIF (#3122). It shares the
/// enforcement pass's `.trivyignore` so the Security tab and the gate agree
/// on what has been accepted.
#[test]
fn trivy_visibility_pass_never_blocks_and_never_claims_a_filter() {
    let workflow = load_docker_publish_workflow();
    let steps = trivy_scan_steps(&workflow);
    let visibility: Vec<&TrivyStep> = steps.iter().filter(|s| !s.is_enforcement()).collect();
    assert!(
        !visibility.is_empty(),
        "docker-publish.yml has no VISIBILITY Trivy pass (none with \
         `exit-code: '0'`), so nothing reaches the Security tab (#3122)"
    );

    for step in visibility {
        let at = step.where_();
        assert_eq!(
            step.format, "sarif",
            "{at}: a non-blocking Trivy pass is only useful as SARIF for the \
             Security tab; a non-SARIF pass that cannot fail reports nowhere"
        );
        assert_eq!(
            step.severity, None,
            "{at}: the SARIF pass must NOT declare a `severity:` — \
             trivy-action unsets it for SARIF, so writing one there documents \
             a filter that does not exist (#3122)"
        );
        assert_eq!(
            step.trivyignores.as_deref(),
            Some(".trivyignore"),
            "{at}: both passes apply .trivyignore so the Security tab and the \
             gate agree on which findings have been accepted"
        );
        assert_eq!(
            step.ignore_unfixed,
            Some(true),
            "{at}: the two passes must agree on ignore-unfixed, or the \
             Security tab and the gate describe different scans"
        );
    }
}

/// Wiring half 2: publication must DEPEND on the scan. Without this edge a
/// red Security Scan job is a bystander — the merge jobs still push tags.
#[test]
fn merge_jobs_depend_on_container_scan() {
    let workflow = load_docker_publish_workflow();
    let mut merge_jobs = 0;
    for (job_name, job) in jobs(&workflow) {
        let job_name = job_name.as_str().unwrap_or("<job>");
        if !job_name.starts_with("merge-") {
            continue;
        }
        merge_jobs += 1;
        let needs: Vec<&str> = job
            .get("needs")
            .and_then(Value::as_sequence)
            .map(|s| s.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert!(
            needs.contains(&"scan-containers"),
            "{job_name}: must `need` scan-containers so a policy-violating \
             image is never published (#2609); needs = {needs:?}"
        );
    }
    assert!(
        merge_jobs >= 3,
        "expected the backend/openscap/scanner-adapter merge jobs; \
         if publication jobs were renamed, move this contract test with them"
    );
}

/// The scan job itself must cover every image the merge jobs publish: each
/// active (non-`if: false`) merge job's build dependency is also a dependency
/// of scan-containers, so nothing is published unscanned.
#[test]
fn scan_job_covers_all_actively_published_builds() {
    let workflow = load_docker_publish_workflow();
    let all_jobs = jobs(&workflow);
    let scan_needs: Vec<&str> = all_jobs
        .get(Value::from("scan-containers"))
        .and_then(|j| j.get("needs"))
        .and_then(Value::as_sequence)
        .map(|s| s.iter().filter_map(Value::as_str).collect())
        .expect("scan-containers job with `needs` exists");

    for (job_name, job) in all_jobs {
        let job_name = job_name.as_str().unwrap_or("<job>");
        if !job_name.starts_with("merge-") {
            continue;
        }
        // Suspended jobs (`if: false`, e.g. the alpine variant) publish
        // nothing, so their build inputs need no scan coverage yet.
        if job.get("if").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let needs: Vec<&str> = job
            .get("needs")
            .and_then(Value::as_sequence)
            .map(|s| s.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for dep in needs {
            if dep.starts_with("build-") {
                assert!(
                    scan_needs.contains(&dep),
                    "{job_name} publishes {dep} output, but scan-containers \
                     does not scan it (needs = {scan_needs:?})"
                );
            }
        }
    }
}
