# Proxy Scan Message Fix (#3344) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop telling users that security scanning is unavailable for proxy-cached artifacts, because it has been available since #2954.

**Architecture:** One shared constant, `ARTIFACT_NOT_ANALYZABLE_MSG`, currently serves four semantically different endpoints (SBOM generation, on-demand scan, signing, SBOM/CVE-history visibility) and asserts a blanket claim that is false for scanning. Replace it with one message per capability, each accurate for its own endpoint. Mirror the same narrowing in the two web copy sites. No behaviour changes, no schema changes, no new endpoints.

**Tech Stack:** Rust (axum handlers, `cargo test --workspace --lib`), TypeScript/React (`artifact-keeper-web`, vitest).

**Spec:** `docs/plans/2026-08-13-proxy-scan-visibility-design.md` (v4) — see the Problem section and the "Web" bullet on narrowing the SBOM copy.

## Global Constraints

- Do NOT add AI attribution or `Co-Authored-By` lines to commits (CLAUDE.md).
- Branch is `feat/proxy-scan-visibility`; never push to `main`.
- Pre-push: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --lib`.
- Changed lines need >= 70% coverage and <= 3% duplication.
- Every new message MUST remain accurate for its own endpoint. Scanning of proxy-cached artifacts **is** available via the repository's scan-on-proxy policy; only SBOM generation, on-demand per-artifact scanning, and signing are hosted-only.
- Do not touch the gate's block/serve behaviour, `scan_configs` semantics, or the `analyzable` field.

---

### Task 1: Split the backend message by capability

**Files:**
- Modify: `backend/src/api/handlers/sbom.rs` (constant at :30, use at :373, use at :1741, test at :2491-2510)
- Modify: `backend/src/api/handlers/security.rs:761`
- Modify: `backend/src/api/handlers/signing.rs:549`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: three `pub(crate) const &str` in `sbom.rs` — `SBOM_NOT_AVAILABLE_MSG`, `ON_DEMAND_SCAN_NOT_AVAILABLE_MSG`, `SIGNING_NOT_AVAILABLE_MSG`. `ARTIFACT_NOT_ANALYZABLE_MSG` is removed; no other module may reference it after this task.

- [ ] **Step 1: Write the failing test**

Replace the existing `test_artifact_analysis_missing_uses_honest_not_analyzable_message` in `backend/src/api/handlers/sbom.rs` (around line 2491) with:

```rust
    #[test]
    fn test_capability_messages_do_not_claim_scanning_is_unavailable() {
        // #3344: the single shared message claimed "SBOM generation and
        // security scanning are available only for artifacts hosted in this
        // registry". The scanning half has been false since #2954: proxy-cached
        // artifacts are scanned at download time when scan-on-proxy is enabled.
        // Each endpoint now states only its own limitation.
        for msg in [
            SBOM_NOT_AVAILABLE_MSG,
            ON_DEMAND_SCAN_NOT_AVAILABLE_MSG,
            SIGNING_NOT_AVAILABLE_MSG,
        ] {
            assert!(
                !msg.contains("SBOM generation and security scanning"),
                "message still makes the blanket claim: {msg}"
            );
            assert_ne!(msg, "Artifact not found");
            assert!(
                msg.contains("proxy-cached remote artifacts")
                    || msg.contains("proxy-cached"),
                "message should still name the proxy-cached case: {msg}"
            );
        }

        // The two messages for capabilities that DO have a proxy equivalent
        // must point the caller at it rather than dead-ending.
        assert!(SBOM_NOT_AVAILABLE_MSG.contains("scan-on-proxy"));
        assert!(ON_DEMAND_SCAN_NOT_AVAILABLE_MSG.contains("scan-on-proxy"));

        // Signing has no proxy equivalent, so it must not imply one.
        assert!(!SIGNING_NOT_AVAILABLE_MSG.contains("scan-on-proxy"));
    }

    #[test]
    fn test_sbom_visibility_denial_uses_the_sbom_message() {
        // `ensure_artifact_repo_access` guards the SBOM and CVE-history
        // endpoints, so its denial must be the SBOM-specific message.
        let auth = make_auth(None, false);
        let err = require_repo_access(&auth, None, SBOM_NOT_AVAILABLE_MSG).unwrap_err();
        match err {
            AppError::NotFound(msg) => assert_eq!(msg, SBOM_NOT_AVAILABLE_MSG),
            other => panic!("expected NotFound with the SBOM message, got {:?}", other),
        }
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib -p artifact-keeper-backend capability_messages sbom_visibility_denial 2>&1 | tail -20`

Expected: FAIL to compile — `cannot find value SBOM_NOT_AVAILABLE_MSG in this scope` (and the other two).

- [ ] **Step 3: Replace the constant with three capability-specific ones**

In `backend/src/api/handlers/sbom.rs`, replace the `ARTIFACT_NOT_ANALYZABLE_MSG` declaration and its doc comment (lines ~23-30) with:

```rust
/// Not-found messages for artifact-scoped endpoints. Proxy-cached (Remote)
/// objects are listed with a synthetic, SHA-256-derived id and have no row in
/// the `artifacts` table (#1278/#1280), so lookups by `artifacts.id` cannot
/// resolve them even though the object is visible in the listing. (#2227)
///
/// One message per capability (#3344). The previous single constant claimed
/// "SBOM generation and security scanning" were both hosted-only; the scanning
/// half has been false since #2954, where proxy-cached artifacts began being
/// scanned and blocked at download time under the repository's scan-on-proxy
/// policy. Messages that describe a capability with a proxy equivalent must
/// point the caller at it.
pub(crate) const SBOM_NOT_AVAILABLE_MSG: &str = "Artifact not found or not eligible for SBOM generation: SBOM generation is available only for artifacts hosted in this registry, not proxy-cached remote artifacts. Proxy-cached artifacts are still scanned for vulnerabilities at download time when scan-on-proxy is enabled for the repository.";

pub(crate) const ON_DEMAND_SCAN_NOT_AVAILABLE_MSG: &str = "Artifact not found or not eligible for on-demand scanning: on-demand scans are available only for artifacts hosted in this registry. Proxy-cached remote artifacts are scanned automatically at download time when scan-on-proxy is enabled for the repository.";

pub(crate) const SIGNING_NOT_AVAILABLE_MSG: &str = "Artifact not found or not eligible for signing: signing is available only for artifacts hosted in this registry, not proxy-cached remote artifacts.";
```

- [ ] **Step 4: Point each call site at its own message**

`backend/src/api/handlers/sbom.rs:373` — change `ARTIFACT_NOT_ANALYZABLE_MSG` to `SBOM_NOT_AVAILABLE_MSG`:

```rust
            .ok_or_else(|| AppError::NotFound(SBOM_NOT_AVAILABLE_MSG.into()))?;
```

`backend/src/api/handlers/sbom.rs:1741` — same substitution:

```rust
    require_repo_visibility(db, auth, repo, SBOM_NOT_AVAILABLE_MSG).await
```

`backend/src/api/handlers/security.rs:761`:

```rust
            return Err(AppError::NotFound(
                crate::api::handlers::sbom::ON_DEMAND_SCAN_NOT_AVAILABLE_MSG.into(),
            ));
```

`backend/src/api/handlers/signing.rs:549`:

```rust
        AppError::NotFound(crate::api::handlers::sbom::SIGNING_NOT_AVAILABLE_MSG.to_string())
    })?;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib -p artifact-keeper-backend capability_messages sbom_visibility_denial 2>&1 | tail -20`

Expected: PASS, 2 tests.

- [ ] **Step 6: Verify no stale references remain and the suite is green**

Run:
```bash
grep -rn "ARTIFACT_NOT_ANALYZABLE_MSG" backend/src/ || echo "OK: no references remain"
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
```

Expected: the grep prints `OK: no references remain`; fmt, clippy, and the full lib suite pass.

- [ ] **Step 7: Commit**

```bash
git add backend/src/api/handlers/sbom.rs backend/src/api/handlers/security.rs backend/src/api/handlers/signing.rs
git commit -m "fix(api): stop claiming scanning is unavailable for proxy-cached artifacts

One shared not-found message told callers that 'SBOM generation and
security scanning are available only for artifacts hosted in this
registry'. The scanning half has been false since #2954: proxy-cached
artifacts are scanned and blocked at download time when scan-on-proxy is
enabled for the repository.

Split the constant into one message per capability - SBOM generation,
on-demand scanning, and signing - so each states only its own limitation,
and point the two with a proxy equivalent at scan-on-proxy instead of
dead-ending.

Refs #3344"
```

---

### Task 2: Narrow the web copy

**Files:**
- Modify: `artifact-keeper-web/src/lib/artifact-analyzable.ts` (`ANALYZABLE_DISABLED_REASON`)
- Modify: `artifact-keeper-web/src/app/(app)/repositories/_components/security-tab-content.tsx:527-538`
- Test: `artifact-keeper-web/src/lib/__tests__/artifact-analyzable.test.ts`

**Interfaces:**
- Consumes: nothing from Task 1 (the web copy is independent of the backend strings).
- Produces: `ANALYZABLE_DISABLED_REASON` keeps its name and export; only its value changes. `isArtifactAnalyzable` is unchanged.

- [ ] **Step 1: Write the failing test**

Append to `artifact-keeper-web/src/lib/__tests__/artifact-analyzable.test.ts`:

```typescript
describe("ANALYZABLE_DISABLED_REASON", () => {
  it("does not claim scanning is unavailable for proxy-cached artifacts", () => {
    // #3344: proxy-cached artifacts ARE scanned at download time when
    // scan-on-proxy is enabled. Only SBOM generation and on-demand scans
    // are hosted-only.
    expect(ANALYZABLE_DISABLED_REASON).not.toMatch(/SBOM and scanning are available only/);
    expect(ANALYZABLE_DISABLED_REASON).toMatch(/scan-on-proxy/);
    expect(ANALYZABLE_DISABLED_REASON).toMatch(/proxy-cached/);
  });
});
```

Ensure the import at the top of that file includes the constant:

```typescript
import { ANALYZABLE_DISABLED_REASON, isArtifactAnalyzable } from "@/lib/artifact-analyzable";
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/khan/artifact-keeper-web && npx vitest run src/lib/__tests__/artifact-analyzable.test.ts`

Expected: FAIL — the current string matches `/SBOM and scanning are available only/` and does not contain `scan-on-proxy`.

- [ ] **Step 3: Narrow the constant**

In `artifact-keeper-web/src/lib/artifact-analyzable.ts`, replace the `ANALYZABLE_DISABLED_REASON` value and update its doc comment:

```typescript
/**
 * User-facing explanation shown when SBOM generation / on-demand scanning is
 * offered for an artifact the backend cannot analyze. Proxy-cached remote
 * artifacts have synthetic ids and no `artifacts` row, so the backend returns
 * 404 for those requests (artifact-keeper#2292, backend PR #2291).
 *
 * #3344: this previously said "SBOM and scanning are available only for
 * artifacts hosted in this registry", which is false for scanning - proxy-cached
 * artifacts are scanned at download time when scan-on-proxy is enabled.
 */
export const ANALYZABLE_DISABLED_REASON =
  "SBOM generation and on-demand scans are available only for artifacts hosted in this registry. Proxy-cached remote artifacts are scanned automatically at download time when scan-on-proxy is enabled for the repository.";
```

- [ ] **Step 4: Fix the inline copy in the Security tab**

In `security-tab-content.tsx`, replace the `total === 0` block (lines ~527-538) so a non-analyzable artifact no longer gets a green all-clear headline:

```tsx
      {total === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-center">
          {analyzable ? (
            <>
              <ShieldCheck className="size-12 text-green-500/50 mb-4" />
              <p className="text-sm text-muted-foreground">
                No vulnerabilities detected for this artifact.
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                Generate an SBOM and run a security scan to check for CVEs.
              </p>
            </>
          ) : (
            <>
              <ShieldQuestion className="size-12 text-muted-foreground/50 mb-4" />
              <p className="text-sm text-muted-foreground">
                CVE history is not available for this artifact.
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                {ANALYZABLE_DISABLED_REASON}
              </p>
            </>
          )}
        </div>
      ) : (
```

Add `ShieldQuestion` to the existing `lucide-react` import in that file, and import the constant:

```tsx
import { ANALYZABLE_DISABLED_REASON } from "@/lib/artifact-analyzable";
```

Note: this removes the green all-clear for proxy artifacts. It does **not** yet show a verdict — that requires the endpoint from the visibility design and is out of scope here.

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
cd /Users/khan/artifact-keeper-web
npx vitest run src/lib/__tests__/artifact-analyzable.test.ts \
  'src/app/(app)/repositories/_components/__tests__/sbom-tab-content.test.tsx' \
  'src/app/(app)/repositories/_components/__tests__/artifact-scans-section.test.tsx'
```

Expected: PASS. If either component test asserts the old wording verbatim, update that assertion to the new copy — those tests pin copy, not behaviour.

- [ ] **Step 6: Typecheck and lint**

Run: `cd /Users/khan/artifact-keeper-web && npx tsc --noEmit && npm run lint`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
cd /Users/khan/artifact-keeper-web
git add src/lib/artifact-analyzable.ts src/lib/__tests__/artifact-analyzable.test.ts 'src/app/(app)/repositories/_components/security-tab-content.tsx'
git commit -m "fix(ui): stop showing a green all-clear for proxy-cached artifacts

The Security tab rendered a green shield reading 'No vulnerabilities
detected for this artifact' whenever the CVE-history total was zero. For
proxy-cached artifacts that total is structurally always zero, because
CVE history is keyed on artifacts.id and those objects have none - so an
artifact the download gate had blocked displayed an all-clear.

Render a neutral 'CVE history is not available' state instead, and narrow
the disabled reason: proxy-cached artifacts are scanned at download time
when scan-on-proxy is enabled, so only SBOM generation and on-demand
scans are hosted-only.

Refs #3344"
```

---

## Self-Review

**Spec coverage.** This plan implements the #3344 slice of the v4 design: the Problem section's "the user-facing string claims security scanning is unavailable" and the Web bullet "narrow the SBOM tab copy to SBOM specifically". It deliberately does **not** implement the verdict panel, the endpoint, the summary, or the anonymous state — those need the endpoint and are the Issue 1 plan.

**Placeholders.** None. Every step carries the literal string, code block, and command.

**Type consistency.** Three new constants are declared in Task 1 Step 3 and referenced by the exact same names in Step 4 and in the Task 1 Step 1 test. `ANALYZABLE_DISABLED_REASON` keeps its existing name and export signature, so Task 2's component import is valid. `isArtifactAnalyzable` is untouched.

**Known follow-on.** Task 2 Step 5 may require updating copy assertions in two existing component tests; that is called out inline rather than left as a surprise.
