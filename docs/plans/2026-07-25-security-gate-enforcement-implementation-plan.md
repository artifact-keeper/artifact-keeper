# Security Gate Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make scan policies, the quarantine state machine, and curation rules actually enforce: policy violations quarantine artifacts at scan completion, admins can quarantine flagged artifacts, and curation block rules gate PyPI proxy traffic; all covered by DTF release-gate tests.

**Architecture:** Three surgical completions of half-wired features, hooked into existing enforcement points: scan completion (`update_quarantine_status`), the quarantine router, and the PyPI proxy paths where the age gate already intercepts. One new migration (quarantine_reason). DTF tests in artifact-keeper-test, version-gated.

**Tech Stack:** Rust (Axum, SQLx offline, utoipa), PostgreSQL, bash DTF suite (curl/jq, JUnit helpers).

## Global Constraints

- Spec: `docs/plans/2026-07-25-security-gate-enforcement-design.md` in this worktree. Read it before starting any task.
- Backend work happens ONLY in the worktree `/tmp/D1D8DEA9-BB0B-4381-953B-39F87F687E26-ak` (branch `fix/scan-policy-enforcement`, based on origin/main c88fc0ae). NEVER touch `/Users/khan/ak/artifact-keeper` (it has another session's uncommitted work on `feat/repo-export-import`). Never remove the worktree.
- DTF work happens ONLY in a new worktree of `/Users/khan/ak/artifact-keeper-test` created in Task 7 (branch `feat/security-gate-enforcement-tests`).
- The demo stack (repo `/Users/khan/ak/artifact-keeper-ml-demo`, compose project `akdemo`) is running on localhost:8080 with image 1.5.8 until Task 6 swaps in the locally built image. Demo admin credentials: `stack/.env.demo` (admin / DemoAdmin-2026-throwaway).
- Rust checks that must be green before any push: `cargo fmt --check`, `cargo clippy --workspace`, `cargo test --workspace --lib` (no DB), and DB-bound tests via `DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo test --workspace`.
- SQLx offline: any new/changed query needs `cargo sqlx prepare` regenerated against the migrated dev DB (localhost:30432) and the `.sqlx/` delta committed. Note: sqlx offline artifacts only matter for `query!` macros; runtime `sqlx::query`/`query_as` strings (which this codebase mostly uses) need no prepare step — check which form you touched.
- Commit style: match repo history (imperative, scoped, references issue numbers when they exist). No Co-Authored-By, no AI attribution, no em-dashes or emoji anywhere.
- Migration number: next free is `178` (last is `177_maven_packages_grouped_name_backfill.sql`). If another 178 appeared upstream meanwhile, renumber to the next free.
- Feature-flag names for DTF gating: `scan_policy_enforcement`, `quarantine_admin_transition`, `curation_proxy_block`, all min version `1.7.0` (adjust in one place if the next release turns out to be numbered differently).
- Do NOT push, create issues, or open PRs until Task 8. Everything before that is local.

## Verified code facts (from the worktree, trust these over memory)

- `update_quarantine_status(&self, artifact_id: Uuid, findings_count: i32)` at `backend/src/services/scanner_service.rs:4668`; two callers (lines ~3802, ~3972). Match arm `Some("quarantined")` handles the quarantine-period flow via `status_after_scan`; the `_ =>` arm sets `flagged`/`clean` (this is where policy enforcement hooks in).
- `PolicyService::new(db: PgPool)`; `evaluate_artifact(&self, artifact_id: Uuid, repository_id: Uuid) -> Result<PolicyResult>` (`policy_service.rs:77`); `PolicyResult { allowed: bool, violations: Vec<String> }` (`models/security.rs:281`).
- `quarantine_service::check_download_allowed(quarantine_status: Option<&str>, quarantine_until_ts: Option<DateTime<Utc>>, now) -> Result<()>` at `quarantine_service.rs:153`: blocks `quarantined` (409, honoring expired `quarantine_until`) and `rejected` (403). `quarantined` with `quarantine_until = NULL` blocks indefinitely (exactly what policy quarantine wants).
- `quarantine_service::transition(db, artifact_id, new_status)` at line 360 only allows quarantined -> released/rejected, 409 otherwise. `fetch_quarantine_fields` (line 398) selects `quarantine_status, quarantine_until`.
- Quarantine handler pattern (`api/handlers/quarantine.rs:109-163`): utoipa path with `context_path = "/api/v1/quarantine"`, `auth.require_admin()?`, `state.event_bus.emit(...)`, returns `QuarantineActionResponse { artifact_id, new_status, message }`.
- `CurationService::evaluate_package(&self, staging_repo_id: Uuid, default_action: &str, package_name: &str, version: &str, architecture: Option<&str>) -> Result<RuleEvaluation, sqlx::Error>` (`curation_service.rs:69`) already fetches repo-scoped + global enabled rules by priority; `RuleEvaluation { action: String, reason: String, rule_id: Option<Uuid> }`. `pattern_matches` is the glob matcher.
- `RepoInfo` (`api/handlers/proxy_helpers.rs:150`) fields end at `age_gate_enabled, age_gate_min_age_days`; it does NOT yet carry curation fields.
- PyPI handlers: `simple_project` at `pypi.rs:606`, `download_or_metadata` at `pypi.rs:~1337`; age-gate enforcement helpers around lines 1300-1540 show the interception style; `proxy_helpers::age_gate_blocked_response` (line 4657) shows the blocked-response helper style.
- `UpdateRepositoryRequest` at `api/handlers/repositories.rs:677` has no curation_enabled/curation_default_action.
- `artifacts.quarantine_status` CHECK allows `unscanned, clean, flagged, quarantined, released, rejected` (migration 075). There is no `quarantine_reason` column yet.
- DTF (`/Users/khan/ak/artifact-keeper-test`): tests source `tests/lib/common.sh`; helpers `begin_suite`, `begin_test`, `pass`, `fail`, `auth_admin`, `setup_workdir`, `add_exit_handler`, `create_repo`, `create_local_repo`, `api_get/api_post/api_delete/api_upload`, `require_feature "<flag>" || { end_suite; exit 0; }`; version map `_feature_min_version()` in `tests/lib/common.sh:214`; RUN_ID-scoped resource names; model file `tests/security/test-auto-scan-on-upload.sh`.

---

### Task 1: quarantine_reason column and reason-bearing download blocks

**Files:**
- Create: `backend/migrations/178_artifact_quarantine_reason.sql`
- Modify: `backend/src/services/quarantine_service.rs` (fetch_quarantine_fields, check_download_allowed, check_artifact_download, transition)

**Interfaces:**
- Produces: `check_download_allowed(status, until, reason: Option<&str>, now) -> Result<()>` (new `reason` parameter, threaded into the error messages); `fetch_quarantine_fields` returns the reason as a third tuple element; `transition` clears `quarantine_reason` on release and keeps it on reject. Tasks 2 and 3 write this column.

- [ ] **Step 1: Write the migration**

```sql
-- 178_artifact_quarantine_reason.sql
-- Record WHY an artifact is quarantined or rejected (policy violations,
-- admin action) so download-block errors can carry an actionable message.
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS quarantine_reason TEXT;
```

- [ ] **Step 2: Write failing unit tests for the reason-bearing messages**

In `quarantine_service.rs` tests module, following the existing `check_download_allowed` test style:

```rust
#[test]
fn test_blocked_message_includes_reason() {
    let err = check_download_allowed(
        Some("quarantined"),
        None,
        Some("Policy 'demo-cve-gate': 2 findings at or above high"),
        Utc::now(),
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("demo-cve-gate"), "reason must surface: {msg}");
}

#[test]
fn test_blocked_message_without_reason_unchanged() {
    let err = check_download_allowed(Some("quarantined"), None, None, Utc::now()).unwrap_err();
    assert!(format!("{err}").contains("pending security review"));
}
```

- [ ] **Step 3: Run to verify failure**

Run (in the worktree): `cargo test -p backend --lib quarantine_service -- --nocapture 2>&1 | tail -20`
Expected: compile error (wrong arity) — that is the failing state for a signature change.

- [ ] **Step 4: Implement**

Add `reason: Option<&str>` as third parameter of `check_download_allowed` (before `now`). When blocking `quarantined`: if reason is Some, message becomes `format!("Artifact is quarantined and pending security review: {reason}")`; None keeps the current text. Same pattern for `rejected` ("Artifact was rejected during security review: {reason}"). Extend `fetch_quarantine_fields`'s Row and SELECT with `quarantine_reason`, return the triple, and update `get_status` / `check_artifact_download` call sites (`check_artifact_download` passes the fetched reason through). In `transition`, the release UPDATE also sets `quarantine_reason = NULL`; the reject UPDATE leaves it. Fix every `check_download_allowed` caller and existing test for the new arity (pass `None`).

- [ ] **Step 5: Apply the migration to the dev DB and run tests**

Run: `DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo sqlx migrate run 2>&1 | tail -3` (or start the backend once against the dev DB if the repo applies migrations at boot — check how migrations are applied in this repo first: `grep -rn "migrate" backend/src/main.rs | head`).
Then: `cargo test -p backend --lib quarantine_service`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/migrations/178_artifact_quarantine_reason.sql backend/src/services/quarantine_service.rs
git commit -m "Add quarantine_reason column and surface it in download-block errors"
```

---

### Task 2: enforce scan policies at scan completion

**Files:**
- Modify: `backend/src/services/scanner_service.rs` (`update_quarantine_status` and a new pure decision fn)

**Interfaces:**
- Consumes: `PolicyService::evaluate_artifact`, `PolicyResult`, Task 1's `quarantine_reason` column.
- Produces: legacy-branch behavior: violations => `quarantine_status='quarantined'`, `quarantine_until=NULL`, `quarantine_reason=<violations joined "; ">`. Tasks 6-8 and the DTF tests rely on exactly this observable behavior.

- [ ] **Step 1: Write the failing unit test for the pure decision**

In `scanner_service.rs` tests module:

```rust
#[test]
fn test_post_scan_status_policy_violation_quarantines() {
    let d = post_scan_status_decision(
        Some("flagged"),
        3,
        Some(&crate::models::security::PolicyResult {
            allowed: false,
            violations: vec!["Policy 'demo-cve-gate': severity over threshold".into()],
        }),
    );
    assert_eq!(d.status, "quarantined");
    assert_eq!(
        d.reason.as_deref(),
        Some("Policy 'demo-cve-gate': severity over threshold")
    );
}

#[test]
fn test_post_scan_status_no_policy_keeps_flagged_clean() {
    assert_eq!(post_scan_status_decision(Some("clean"), 2, None).status, "flagged");
    assert_eq!(post_scan_status_decision(None, 0, None).status, "clean");
    assert!(post_scan_status_decision(None, 0, None).reason.is_none());
}

#[test]
fn test_post_scan_status_quarantine_period_branch_untouched() {
    // current status 'quarantined' (quarantine-period flow) must keep using
    // status_after_scan regardless of policy result
    let d = post_scan_status_decision(Some("quarantined"), 0, None);
    assert_eq!(d.status, "released");
    let d = post_scan_status_decision(Some("quarantined"), 1, None);
    assert_eq!(d.status, "rejected");
}

#[test]
fn test_post_scan_status_policy_allowed_is_not_quarantine() {
    let ok = crate::models::security::PolicyResult { allowed: true, violations: vec![] };
    assert_eq!(post_scan_status_decision(None, 1, Some(&ok)).status, "flagged");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p backend --lib post_scan_status -- --nocapture 2>&1 | tail -10`
Expected: FAIL, `post_scan_status_decision` not found.

- [ ] **Step 3: Implement the pure function**

```rust
/// Outcome of the post-scan quarantine decision. Pure; see
/// update_quarantine_status for the impure wrapper.
pub(crate) struct PostScanDecision {
    pub status: String,
    /// true when the quarantine-period branch must clear quarantine_until
    pub clear_until: bool,
    pub reason: Option<String>,
}

pub(crate) fn post_scan_status_decision(
    current_status: Option<&str>,
    findings_count: i32,
    policy: Option<&crate::models::security::PolicyResult>,
) -> PostScanDecision {
    if let Some("quarantined") = current_status {
        let state = crate::services::quarantine_service::status_after_scan(findings_count > 0);
        return PostScanDecision {
            status: state.as_str().to_string(),
            clear_until: true,
            reason: None,
        };
    }
    if let Some(p) = policy {
        if !p.allowed {
            return PostScanDecision {
                status: "quarantined".to_string(),
                clear_until: false,
                reason: Some(p.violations.join("; ")),
            };
        }
    }
    PostScanDecision {
        status: if findings_count > 0 { "flagged" } else { "clean" }.to_string(),
        clear_until: false,
        reason: None,
    }
}
```

- [ ] **Step 4: Wire it into `update_quarantine_status`**

Inside `update_quarantine_status`, after fetching `current_status`: fetch `repository_id` (`SELECT repository_id FROM artifacts WHERE id = $1`), then evaluate policies fail-open:

```rust
let policy_result = match current_status.as_deref() {
    Some("quarantined") => None, // quarantine-period branch does not consult policies
    _ => {
        let svc = crate::services::policy_service::PolicyService::new(self.db.clone());
        match svc.evaluate_artifact(artifact_id, repository_id).await {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(artifact_id = %artifact_id, error = %e,
                    "Policy evaluation failed; falling back to flagged/clean");
                None
            }
        }
    }
};
let decision = post_scan_status_decision(current_status.as_deref(), findings_count, policy_result.as_ref());
```

Replace the old `(new_status, clear_until)` computation with the decision struct. The `clear_until` branch keeps its existing conditional UPDATE verbatim. The non-clear_until branch's UPDATE becomes:

```sql
UPDATE artifacts SET quarantine_status = $2,
       quarantine_until = CASE WHEN $2 = 'quarantined' THEN NULL ELSE quarantine_until END,
       quarantine_reason = $3
 WHERE id = $1 AND quarantine_status IS DISTINCT FROM 'quarantined'
```

binding `decision.status` and `decision.reason` (the `IS DISTINCT FROM` guard preserves the existing do-not-stomp-admin-state semantics; read the current code's guard behavior and keep whatever it does today for the legacy branch, adding only the reason write and the policy path). Log at info when a policy quarantine happens, naming the policy violations.

- [ ] **Step 5: Run tests**

Run: `cargo test -p backend --lib scanner_service 2>&1 | tail -5` then `cargo test -p backend --lib post_scan_status 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/services/scanner_service.rs
git commit -m "Enforce scan policies at scan completion via quarantine status"
```

---

### Task 3: admin quarantine-now endpoint

**Files:**
- Modify: `backend/src/services/quarantine_service.rs` (new `quarantine_now` + pure legality fn)
- Modify: `backend/src/api/handlers/quarantine.rs` (new POST route, request/response DTOs, ApiDoc registration)

**Interfaces:**
- Consumes: Task 1's reason column.
- Produces: `POST /api/v1/quarantine/{artifact_id}` admin endpoint, body `{"reason": "..."}` (optional), 200 with `QuarantineActionResponse { new_status: "quarantined", ... }`; 200 no-op when already quarantined; 409 when status is `rejected`. Service fn `quarantine_service::quarantine_now(db, artifact_id, reason: Option<String>) -> Result<&'static str>` returning the resulting status. DTF Task 7 exercises this path.

- [ ] **Step 1: Write failing unit tests for the legality decision**

```rust
#[test]
fn test_admin_quarantine_legality() {
    assert!(admin_quarantine_allowed(None));
    assert!(admin_quarantine_allowed(Some("clean")));
    assert!(admin_quarantine_allowed(Some("flagged")));
    assert!(admin_quarantine_allowed(Some("unscanned")));
    assert!(admin_quarantine_allowed(Some("released")));
    assert!(!admin_quarantine_allowed(Some("rejected")));
    // already quarantined is a no-op handled by the caller, not an error
    assert!(admin_quarantine_allowed(Some("quarantined")));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p backend --lib admin_quarantine 2>&1 | tail -5`
Expected: FAIL, function not found.

- [ ] **Step 3: Implement service half**

```rust
/// Pure legality check for the admin quarantine-now action (#<backend issue>).
pub fn admin_quarantine_allowed(current: Option<&str>) -> bool {
    !matches!(current, Some("rejected"))
}

/// Admin-initiated quarantine. Idempotent: already-quarantined returns Ok("quarantined").
pub async fn quarantine_now(
    db: &PgPool,
    artifact_id: Uuid,
    reason: Option<String>,
) -> Result<&'static str> {
    let Some((status, _until, _reason)) = fetch_quarantine_fields(db, artifact_id).await? else {
        return Err(AppError::NotFound(format!("Artifact {artifact_id} not found")));
    };
    if status.as_deref() == Some("quarantined") {
        return Ok("quarantined");
    }
    if !admin_quarantine_allowed(status.as_deref()) {
        return Err(AppError::Conflict(
            "Artifact was rejected during security review; cannot re-quarantine".to_string(),
        ));
    }
    let reason = reason.unwrap_or_else(|| "Quarantined by administrator".to_string());
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_until = NULL, \
         quarantine_reason = $2 WHERE id = $1",
    )
    .bind(artifact_id)
    .bind(reason)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok("quarantined")
}
```

- [ ] **Step 4: Implement handler**

In `quarantine.rs`, mirroring `release_artifact` exactly (auth.require_admin, tracing, event_bus emit `"artifact.quarantine.quarantined"`):

```rust
#[derive(Debug, Deserialize, ToSchema)]
pub struct QuarantineNowRequest {
    /// Reason shown to developers whose downloads are blocked.
    pub reason: Option<String>,
}
```

Route: `.route("/:artifact_id", get(get_quarantine_status).post(quarantine_artifact))` (merge with the existing GET registration for the same path). utoipa: `post, path = "/{artifact_id}", context_path = "/api/v1/quarantine"`, request_body = QuarantineNowRequest, responses 200/401/403/404/409. Register the new operation fn and QuarantineNowRequest in the module's ApiDoc (`paths(...)` and `components(schemas(...))`). Body is `Option<Json<QuarantineNowRequest>>` so an empty POST works.

- [ ] **Step 5: Run tests and the OpenAPI count guard**

Run: `cargo test -p backend --lib quarantine 2>&1 | tail -5` and `cargo test --lib test_openapi_spec_is_valid 2>&1 | tail -5`
Expected: PASS (the openapi test asserts minimum path/operation counts; adding an operation cannot lower them).

- [ ] **Step 6: Commit**

```bash
git add backend/src/services/quarantine_service.rs backend/src/api/handlers/quarantine.rs
git commit -m "Add admin quarantine-now endpoint completing the flagged-to-blocked transition"
```

---

### Task 4: curation gating on the PyPI proxy

**Files:**
- Modify: `backend/src/api/handlers/proxy_helpers.rs` (RepoInfo fields + SELECTs, `curation_blocked_response`)
- Modify: `backend/src/api/handlers/pypi.rs` (gate calls in `simple_project` and `download_or_metadata`, handler tests)
- Modify: `backend/src/api/handlers/repositories.rs` (UpdateRepositoryRequest + UPDATE wiring)

**Interfaces:**
- Consumes: `CurationService::evaluate_package(repo_id, default_action, package_name, version, None)`.
- Produces: 403 JSON `{"error": "curation_blocked", "package": ..., "reason": ...}` from PyPI simple-index project pages and file downloads on curation-enabled repos when the winning rule action is `block`; `PATCH/PUT /api/v1/repositories/{key}` accepts `curation_enabled: bool` and `curation_default_action: String`. Task 6's act1 script change and Task 7's DTF test rely on both.

- [ ] **Step 1: Extend RepoInfo**

Add `pub curation_enabled: bool` and `pub curation_default_action: String` to `RepoInfo` (proxy_helpers.rs:150). Find every place RepoInfo is populated: `grep -n "RepoInfo {" backend/src/api/handlers/proxy_helpers.rs backend/src/api/handlers/*.rs | head -30` and `grep -n "age_gate_enabled" backend/src/api/handlers/proxy_helpers.rs | head` (the SELECTs that feed it select age_gate columns; add `curation_enabled, curation_default_action` beside them). Update all construction sites including test fixtures (`curation_enabled: false, curation_default_action: "allow".to_string()`).

- [ ] **Step 2: Add the blocked-response helper**

In proxy_helpers.rs beside `age_gate_blocked_response`:

```rust
/// 403 response for a curation-rule block on a proxy request.
pub fn curation_blocked_response(package: &str, reason: &str) -> Response {
    let body = serde_json::json!({
        "error": "curation_blocked",
        "package": package,
        "reason": reason,
    });
    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
}
```

- [ ] **Step 3: Write failing handler tests**

In pypi.rs tests, copying the age-gate test setup style (same fixtures/helpers used by the tests around line 4964; they create repos in the test DB and drive the router via tdh helpers):

```rust
#[sqlx::test(migrations = "./migrations")] // match the exact attribute style of the age-gate tests
async fn test_curation_block_rule_403s_simple_index(pool: sqlx::PgPool) {
    // create remote pypi repo with curation_enabled = true, default 'allow'
    // insert curation_rules row: package_pattern 'evilpkg*', action 'block',
    //   reason 'blocked by test rule', enabled, priority 10, staging_repo_id NULL
    // GET /pypi/{key}/simple/evilpkg/ through the router
    // assert status 403 and body contains "blocked by test rule"
    // GET /pypi/{key}/simple/goodpkg/ must NOT be 403 (upstream failure/404 acceptable)
}

#[sqlx::test(migrations = "./migrations")]
async fn test_curation_disabled_repo_unaffected(pool: sqlx::PgPool) {
    // same rule present, repo curation_enabled = false -> no 403
}
```

Write them as real tests by copying the nearest age-gate test's scaffolding verbatim (repo creation SQL/helpers, router construction); the comments above are the required assertions, not the implementation.

- [ ] **Step 4: Run to verify failure**

Run: `DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo test -p backend curation_block_rule 2>&1 | tail -10`
Expected: FAIL (no 403; gate not implemented yet).

- [ ] **Step 5: Implement the gate**

In pypi.rs, a helper mirroring the age-gate helpers' shape:

```rust
/// Curation gate for PyPI proxy requests (#<backend issue>). Returns
/// Err(403 response) when a block rule matches. Name matching is done on the
/// PEP 503 normalized project name; version "*" on index requests.
async fn enforce_pypi_curation(
    state: &SharedState,
    repo: &proxy_helpers::RepoInfo,
    project: &str,
    version: &str,
) -> Result<(), Response> {
    if !repo.curation_enabled {
        return Ok(());
    }
    let svc = crate::services::curation_service::CurationService::new(state.db.clone());
    let eval = svc
        .evaluate_package(repo.id, &repo.curation_default_action, project, version, None)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "curation evaluation failed; failing open");
            e
        })
        .ok();
    if let Some(eval) = eval {
        if eval.action == "block" {
            return Err(proxy_helpers::curation_blocked_response(project, &eval.reason));
        }
    }
    Ok(())
}
```

Call it in `simple_project` right after the repo is resolved and shown to be a remote/virtual proxy path (immediately before any upstream fetch), with `version = "*"`; and in `download_or_metadata` after `resolve_pypi_repo`, with `version = "*"` (name-level check; the filename's version is not parsed here, and a name-blocked package must never serve any version). On evaluation error, fail open (proxy availability wins; the rule engine erroring must not take the index down) — the `.ok()` above does that; keep the warn log.

- [ ] **Step 6: Wire repository update support**

In `UpdateRepositoryRequest` (repositories.rs:677) add:

```rust
    /// Enable curation-rule enforcement on this repository's proxy paths.
    pub curation_enabled: Option<bool>,
    /// Default curation action when no rule matches: allow, block, or review.
    pub curation_default_action: Option<String>,
```

Wire both into the update handler's UPDATE statement the same way neighboring optional fields are wired (find the dynamic SET construction and follow it exactly). Validate `curation_default_action` against `["allow", "block", "review"]`, 400 otherwise.

- [ ] **Step 7: Run the tests**

Run: `DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo test -p backend curation 2>&1 | tail -10`
Expected: new tests PASS, existing curation tests PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/src/api/handlers/proxy_helpers.rs backend/src/api/handlers/pypi.rs backend/src/api/handlers/repositories.rs
git commit -m "Enforce curation block rules on PyPI proxy index and download paths"
```

---

### Task 5: full backend verification sweep and CHANGELOG

**Files:**
- Modify: `CHANGELOG.md` (worktree root)
- Modify: `.sqlx/` only if `cargo sqlx prepare` produces a delta

**Interfaces:**
- Consumes: Tasks 1-4 complete.
- Produces: a branch that passes every repo check; Task 6 builds its image from this commit.

- [ ] **Step 1: Format and lint**

Run: `cargo fmt --all` then `cargo fmt --check` then `cargo clippy --workspace 2>&1 | tail -15`
Expected: no diffs, no warnings-as-errors failures. Fix anything that appears.

- [ ] **Step 2: Unit suite (no DB)**

Run: `SQLX_OFFLINE=true cargo test --workspace --lib 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 3: DB-bound suite**

Run: `DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" cargo test --workspace 2>&1 | tail -15`
Expected: PASS (age-gate, curation, quarantine, openapi tests included).

- [ ] **Step 4: SQLx offline check**

Run: `cargo sqlx prepare --check --workspace -D "postgresql://registry:registry@localhost:30432/artifact_registry" 2>&1 | tail -5` (use the repo's documented prepare invocation if it differs — check `.sqlx/README` or CI workflow for the exact command).
If it reports drift: run prepare, `git add .sqlx`, include in this task's commit.

- [ ] **Step 5: CHANGELOG entry**

Add under the Unreleased/next-version section, matching the file's existing entry style:

```markdown
- Scan policies are now enforced: a completed scan that violates an enabled
  scan policy quarantines the artifact (download-blocked with the policy
  reason) instead of only flagging it.
- New admin endpoint POST /api/v1/quarantine/{artifact_id} to quarantine a
  flagged or clean artifact manually.
- Curation block rules now gate PyPI proxy index and download requests on
  curation-enabled repositories (403 with the rule reason).
- Artifacts carry a quarantine_reason surfaced in blocked-download errors.
```

- [ ] **Step 6: Commit**

```bash
git add CHANGELOG.md .sqlx 2>/dev/null; git add CHANGELOG.md
git commit -m "Update CHANGELOG and sqlx metadata for security gate enforcement"
```

---

### Task 6: local image build and demo-stack swap

**Files:**
- Modify (demo repo): `/Users/khan/ak/artifact-keeper-ml-demo/stack/.env.demo` (ARTIFACT_KEEPER_VERSION only)
- Modify (demo repo): `/Users/khan/ak/artifact-keeper-ml-demo/setup/act1-admin-setup.sh` (enable curation on pypi-proxy)

**Interfaces:**
- Consumes: Task 5's verified branch; demo repo scripts (lib.sh, act1).
- Produces: demo stack on localhost:8080 running image `artifact-keeper-backend:demo-fix` with migrations applied; pypi-proxy has `curation_enabled=true`. Task 7's DTF run and the demo rework target this stack.

- [ ] **Step 1: Build the backend image from the worktree**

Find the Dockerfile: `ls /tmp/D1D8DEA9-BB0B-4381-953B-39F87F687E26-ak/Dockerfile* /tmp/D1D8DEA9-BB0B-4381-953B-39F87F687E26-ak/backend/Dockerfile* 2>/dev/null` and check how CI builds it (`grep -n "docker/build-push\|dockerfile" /tmp/D1D8DEA9-BB0B-4381-953B-39F87F687E26-ak/.github/workflows/*.yml | head -5`). Then:

Run: `docker build -t ghcr.io/artifact-keeper/artifact-keeper-backend:demo-fix -f <dockerfile> /tmp/D1D8DEA9-BB0B-4381-953B-39F87F687E26-ak` (local build is allowed; only cloud builds are forbidden). This is a Rust release build; expect 10-30 minutes. Run it in the background and monitor.

- [ ] **Step 2: Swap the demo stack's backend**

The compose file uses `ghcr.io/artifact-keeper/artifact-keeper-backend:${ARTIFACT_KEEPER_VERSION:-latest}` for backend AND `...-web:${ARTIFACT_KEEPER_VERSION}` for web, so a plain version bump would break web. Set backend-only override: add `AK_BACKEND_VERSION=demo-fix` to `stack/.env.demo`, change the backend image line in `stack/docker-compose.demo.yml` to `ghcr.io/artifact-keeper/artifact-keeper-backend:${AK_BACKEND_VERSION:-${ARTIFACT_KEEPER_VERSION:-latest}}`, leave web on `${ARTIFACT_KEEPER_VERSION}`. Then:

Run: `cd /Users/khan/ak/artifact-keeper-ml-demo && docker compose --env-file stack/.env.demo -f stack/docker-compose.demo.yml up -d backend && sleep 5 && curl -fsS localhost:8080/api/v1/health | jq .status`
Expected: healthy; migrations (including 178) applied at boot — verify with `docker compose ... logs backend | grep -i migrat | tail -3`.

- [ ] **Step 3: Enable curation on pypi-proxy in act1**

In `setup/act1-admin-setup.sh`, after the age-gate section, add (using the repository update endpoint from Task 4; check the exact method PUT vs PATCH via `curl -fsS localhost:8080/api/v1/openapi.json | jq '.paths."/api/v1/repositories/{key}" | keys'`):

```bash
echo "== Curation enforcement on pypi-proxy =="
ak_api PUT /api/v1/repositories/pypi-proxy \
  '{"curation_enabled": true, "curation_default_action": "allow"}' | jq -c '{key, curation_enabled}' 2>/dev/null \
  || ak_api PATCH /api/v1/repositories/pypi-proxy \
  '{"curation_enabled": true, "curation_default_action": "allow"}' | jq -c .
```

(Resolve to the single correct method once checked; do not leave both.) Run `bash setup/act1-admin-setup.sh` twice; verify idempotency and that `curl -s -H "Authorization: Bearer $AK_TOKEN" localhost:8080/api/v1/repositories/pypi-proxy | jq .curation_enabled` is true.

- [ ] **Step 4: Manual gate probes (the three fixes, live)**

```bash
cd /Users/khan/ak/artifact-keeper-ml-demo && source setup/lib.sh && ak_login
D=$(mktemp -d)
# curation block: requessts* rule exists from act1
pip download requessts --index-url "${AK_URL}/pypi/pypi-proxy/simple" --no-deps -d "$D"; echo "exit=$? (expect nonzero, output must show curation reason)"
# scan-policy quarantine: re-run the moment-3 flow from attack/act3-attack.sh (publish pyyaml 5.3 wheel to team-packages, trigger scan, wait)
# then: the artifact must be quarantined (not flagged) and download blocked with 'demo-cve-gate' in the message
# admin quarantine-now: pick any clean artifact id from team-packages; POST /api/v1/quarantine/{id} with {"reason":"manual demo"}; GET its status; expect quarantined
```

Record actual outputs in the task report. All three must behave as described before this task completes.

- [ ] **Step 5: Commit (demo repo)**

```bash
cd /Users/khan/ak/artifact-keeper-ml-demo
git add stack/.env.demo stack/docker-compose.demo.yml setup/act1-admin-setup.sh
git commit -m "Run demo stack on locally built backend with curation enabled"
```

---

### Task 7: DTF release-gate tests

**Files (in a NEW worktree of artifact-keeper-test):**
- Create: `tests/security/test-scan-policy-enforcement.sh`
- Create: `tests/security/test-quarantine-admin-transition.sh`
- Create: `tests/pullthrough/test-curation-proxy-block.sh`
- Modify: `tests/lib/common.sh` (`_feature_min_version` map: three new flags -> "1.7.0")

**Interfaces:**
- Consumes: the running demo stack (Task 6) as the local test target; DTF helpers listed in Verified code facts.
- Produces: three release-gate tests, green locally, on branch `feat/security-gate-enforcement-tests`.

- [ ] **Step 1: Create the test-repo worktree**

```bash
cd /Users/khan/ak/artifact-keeper-test && git fetch origin
WT2="/tmp/$(uuidgen)-ak-test"; echo "$WT2" >> /Users/khan/ak/artifact-keeper-ml-demo/.superpowers/sdd/2026-07-24-ak-client-demo/backend-worktree-path.txt
git worktree add -b feat/security-gate-enforcement-tests "$WT2" origin/main
```

- [ ] **Step 2: Add the feature flags**

In `$WT2/tests/lib/common.sh` `_feature_min_version()` case, following the existing comment style (each flag gets a short why-comment naming the backend behavior and issue):

```bash
    # scan_policy_enforcement: completed scans that violate an enabled scan
    # policy set quarantine_status='quarantined' and block downloads with the
    # policy reason (artifact-keeper#<issue>). Pre-1.7.0 backends only flag.
    "scan_policy_enforcement")        echo "1.7.0" ;;
    "quarantine_admin_transition")    echo "1.7.0" ;;
    "curation_proxy_block")           echo "1.7.0" ;;
```

- [ ] **Step 3: Write the three tests**

Model: `tests/security/test-auto-scan-on-upload.sh` (structure, helpers, cleanup, skip semantics). Contract for each: `set -euo pipefail`, source common.sh, `require_feature "<flag>" || { end_suite; exit 0; }`, RUN_ID-scoped repo names, `begin_test`/`pass`/`fail` sections, cleanup via `add_exit_handler`, JUnit via the shared helpers, exit nonzero on any FAIL.

`test-scan-policy-enforcement.sh` sections: create hosted repo `polgate-${RUN_ID}`; POST /api/v1/security/policies `{name: "polgate-${RUN_ID}", repository_id: <id>, max_severity: "high", block_unscanned: false, block_on_fail: true}`; upload an artifact fixture with known-vulnerable content (reuse the auto-scan test's fixture approach: a package.json depending on lodash 4.17.4 in a tgz — same trick that repo already uses to produce findings); trigger or await scan; poll artifact status until `quarantine_status == "quarantined"` (timeout 120s, FAIL on timeout); GET the artifact download URL and assert HTTP 409 with body containing the policy name; POST /api/v1/quarantine/{id}/release; assert download now 200; delete policy in cleanup.

`test-quarantine-admin-transition.sh` sections: create hosted repo `qadmin-${RUN_ID}`; upload a clean fixture; POST /api/v1/quarantine/{artifact_id} with `{"reason": "dtf-${RUN_ID}"}`; assert 200 and status quarantined; assert download blocked 409 with reason in body; POST release; assert download 200; also POST reject on the released artifact and assert 409 (regression guard for the unchanged transition rule).

`test-curation-proxy-block.sh` sections: create remote pypi repo `curgate-${RUN_ID}` with upstream https://pypi.org; PUT/PATCH the repo with `{"curation_enabled": true, "curation_default_action": "allow"}` (use the method verified in Task 6); POST /api/v1/curation/rules `{package_pattern: "curgate-blocked-${RUN_ID}*", action: "block", priority: 5, reason: "dtf curation ${RUN_ID}"}`; GET `/pypi/curgate-${RUN_ID}/simple/curgate-blocked-${RUN_ID}pkg/` and assert 403 with the reason in the body; GET `/pypi/curgate-${RUN_ID}/simple/requests/` and assert NOT 403; delete the rule in cleanup (rules are global; leaving one behind pollutes other suites).

- [ ] **Step 4: Run all three locally against the demo stack**

```bash
cd "$WT2"
export BASE_URL="http://localhost:8080" ADMIN_USER="admin" ADMIN_PASS="DemoAdmin-2026-throwaway" RUN_ID="local-$(date +%s)"
export AK_FEATURES="scan_policy_enforcement,quarantine_admin_transition,curation_proxy_block"
export JUNIT_OUTPUT_DIR="$(mktemp -d)"
bash tests/security/test-scan-policy-enforcement.sh
bash tests/security/test-quarantine-admin-transition.sh
bash tests/pullthrough/test-curation-proxy-block.sh
```

Expected: every section PASS, all exit 0. (AK_FEATURES is required because the local image's reported version predates 1.7.0.) Also run one unmodified existing test (`bash tests/security/test-finding-acknowledge.sh`) to prove the common.sh edit broke nothing.

- [ ] **Step 5: Commit (test-repo worktree)**

```bash
cd "$WT2"
git add tests/lib/common.sh tests/security/test-scan-policy-enforcement.sh tests/security/test-quarantine-admin-transition.sh tests/pullthrough/test-curation-proxy-block.sh
git commit -m "Add release-gate tests for scan policy, quarantine transition, and curation proxy enforcement"
```

---

### Task 8: issues and PRs (both repos)

**Files:** none (gh CLI work)

**Interfaces:**
- Consumes: everything green from Tasks 5-7.
- Produces: pushed branches, one issue + PR per repo, PR bodies matching each repo's PULL_REQUEST_TEMPLATE.md with `Closes #N`.

- [ ] **Step 1: File the backend issue**

`gh issue create --repo artifact-keeper/artifact-keeper` titled "Security gates do not enforce: scan policies, admin quarantine transition, curation on proxies". Body: the three gaps with the file:line evidence from the spec's Context section, expected vs actual behavior, and a one-line fix summary per gap. Plain prose, no em-dashes, no emoji, no AI attribution.

- [ ] **Step 2: Backfill the issue number**

Replace `#<backend issue>` / `#<issue>` placeholders left in code comments and the DTF flag comments (Tasks 3, 4, 7) with the real number; amend or add a small commit in each worktree.

- [ ] **Step 3: Push and open the backend PR**

```bash
cd /tmp/D1D8DEA9-BB0B-4381-953B-39F87F687E26-ak
git push -u origin fix/scan-policy-enforcement
```

Read `.github/PULL_REQUEST_TEMPLATE.md`, structure `--body` to match its sections, include `Closes #N`, describe the three fixes and the verification performed (unit + DB suites, DTF locally, live demo-stack probes). `gh pr create --repo artifact-keeper/artifact-keeper --base main --head fix/scan-policy-enforcement ...`.

- [ ] **Step 4: File the test-repo issue and PR**

Same pattern in artifact-keeper-test: issue "Release-gate coverage for security gate enforcement" referencing the backend issue URL; push `feat/security-gate-enforcement-tests` from the test worktree; PR with `Closes #N` (test repo's own issue), noting the tests are version-gated to 1.7.0 and the flags list.

- [ ] **Step 5: Report PR URLs**

Return both PR URLs and both issue URLs.

---

## Execution notes

- Tasks 1-5 are strictly sequential in the backend worktree. Task 6 depends on 5; Task 7 depends on 6; Task 8 depends on 5-7 all green.
- The demo repo's remaining SDD tasks (reset script, dev-env, warm-cache, deck, runbook, attack Moments 1/3 rework) resume AFTER this plan completes, against the demo-fix backend.
- If Tuesday pressure forces a cut: Tasks 1-3 (scan enforcement + admin transition) are independently shippable without Task 4 (curation); the spec's risk table sanctions that split. Flag it rather than rushing Task 4.
