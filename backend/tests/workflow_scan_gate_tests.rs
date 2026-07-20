//! Contract tests for the container-scan publication gate (#2609).
//!
//! `.github/workflows/docker-publish.yml` states a policy: CRITICAL/HIGH
//! CVEs with an available fix block image publication, with `.trivyignore`
//! as the documented exception path. These tests pin the two pieces of
//! wiring that make that claim true, so neither can be loosened silently:
//!
//!   1. every Trivy scan step runs with `exit-code: '1'` (findings fail the
//!      Security Scan job instead of being informational), and
//!   2. every `merge-*` job `needs: scan-containers` (a failing scan stops
//!      tag publication, not just the scan job itself).
//!
//! They parse the workflow YAML directly; no network, no Docker, no DB.

use serde_yaml::Value;
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

/// All steps across all jobs that invoke the aquasecurity/trivy-action,
/// keyed as (job name, step name).
fn trivy_scan_steps(workflow: &Value) -> Vec<(String, String, Value)> {
    let mut found = Vec::new();
    for (job_name, job) in jobs(workflow) {
        let Some(steps) = job.get("steps").and_then(Value::as_sequence) else {
            continue;
        };
        for step in steps {
            let uses = step.get("uses").and_then(Value::as_str).unwrap_or("");
            if uses.starts_with("aquasecurity/trivy-action@") {
                let step_name = step
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>")
                    .to_string();
                found.push((
                    job_name.as_str().unwrap_or("<job>").to_string(),
                    step_name,
                    step.clone(),
                ));
            }
        }
    }
    found
}

/// Wiring half 1: a CRITICAL/HIGH fixable finding must FAIL the scan step.
/// `exit-code: '0'` is exactly the report-but-don't-enforce regression #2609
/// closed; if a scan needs to be unblocked, the exception path is a justified
/// `.trivyignore` entry, not a global exit-code downgrade.
#[test]
fn trivy_scan_steps_enforce_via_exit_code() {
    let workflow = load_docker_publish_workflow();
    let steps = trivy_scan_steps(&workflow);
    assert!(
        !steps.is_empty(),
        "expected trivy-action scan steps in docker-publish.yml; \
         if the scanner moved, move this contract test with it"
    );
    for (job, name, step) in &steps {
        let with = step.get("with").expect("trivy step has `with`");
        let exit_code = with.get("exit-code").and_then(Value::as_str);
        assert_eq!(
            exit_code,
            Some("1"),
            "{job} / {name}: Trivy must run with exit-code '1' so policy \
             violations fail the scan (#2609); use .trivyignore for exceptions"
        );
        // The stated scope of the policy: fixable CRITICAL/HIGH only.
        assert_eq!(
            with.get("severity").and_then(Value::as_str),
            Some("CRITICAL,HIGH"),
            "{job} / {name}: severity scope drifted from the stated policy"
        );
        assert_eq!(
            with.get("ignore-unfixed").and_then(Value::as_bool),
            Some(true),
            "{job} / {name}: ignore-unfixed keeps unfixable base-image CVEs \
             report-only; removing it changes the stated policy"
        );
        assert_eq!(
            with.get("trivyignores").and_then(Value::as_str),
            Some(".trivyignore"),
            "{job} / {name}: .trivyignore is the documented exception path"
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
