# Conda supply-chain epic (#4033) — handoff

**Date**: 2026-09-20
**Epic**: artifact-keeper/artifact-keeper#4033
**Status**: 8 of 26 children closed. All work to date is merged to `main`.

---

## Where the code is

| Path | Repo | Branch | State |
|---|---|---|---|
| `/private/tmp/ak/artifact-keeper` | backend | `epic/conda-supply-chain` | merged to `main` as `a91704f5a`; **branch is stale, re-clone from `main`** |
| `/private/tmp/ak/artifact-keeper-web` | web | `epic/conda-supply-chain` | merged to `main` as `d9b4dba3a`; same |
| `/tmp/ak-4042` | backend | `feat/4042-conda-alias-advisory-matching` | **UNCOMMITTED WORK — see below** |
| `/tmp/ak-fix-format` | backend | `release-1.10-hotfix` | merged, can be deleted |

Both epic branches are merged. **Start new work from a fresh shallow clone of
`main`**, per CLAUDE.md:

```bash
WORK=/tmp/$(uuidgen)-artifact-keeper
git clone --depth 50 --branch main git@github.com:artifact-keeper/artifact-keeper.git "$WORK"
cd "$WORK" && git checkout -b feat/<issue>-<slug>
```

### Test environment (DB-backed tests skip SILENTLY without this)

```bash
export DATABASE_URL=postgresql://registry:registry@localhost:5432/artifact_registry
export AK_TESTS_REQUIRE_DB=1     # a DB test that cannot connect FAILS instead of skipping
export SQLX_OFFLINE=true
export JWT_SECRET=test-secret-at-least-32-bytes-long-ok
```

Use `cargo nextest run`, never plain `cargo test` (#3479 — tests depend on
per-process isolation). A sub-0.1s "pass" on a DB suite means it did not run.

**Two test failures are pre-existing macOS artifacts. Do not chase them:**

- `api::handlers::hex::tests::test_hex_same_version_case_variants_advertise_one_downloadable_release_db`
  — the fixture writes `foo/` and `Foo/`, which are the same file on
  case-insensitive APFS. Passes on Linux/CI.
- `services::trivy_fs_scanner::tests::test_trivy_scan_target_materializes_the_component_pin`
  — asserts no `trivy` binary is present; this machine has one from Homebrew.

---

## IMMEDIATE: uncommitted work in `/tmp/ak-4042`

`+903/-9` in `backend/src/services/scanner_service.rs`, rebased onto the epic
head, **never committed**. It implements #4042 and it is good work — do not
redo it. Recover it before starting anything else:

```bash
cd /tmp/ak-4042 && git diff > /tmp/4042.patch
```

It was reviewed and the core requirement verified: an unmapped conda package
degrades the scan to `Partial` rather than reporting a false `Complete`.
Its rebase onto the current epic head is done. What remains: rebase onto
current `main` (the epic branch has since merged), re-run gates, open a PR.

**Do not lose this.** It is the only copy.

---

## What closed, and the one invariant that matters

Closed: #4035, #4037, #4045, #4047, #4048, #4052, #4056, #4057.

The design principle the whole epic is built on, and which every future change
must preserve:

> **"We found nothing" and "we never looked" must never render alike.**

It is enforced at four independent layers (DB CHECK, a `Completeness` enum with
no `Default`, the API never defaulting it, and a UI that narrows an unknown
status to `not_read` rather than `complete`). If a change makes an unchecked
thing look clean, it is wrong regardless of what the tests say — see #4088.

### #4088 — read this before touching `scanner_service.rs`

`analysis_degraded` can be deleted from the `feeds_degraded` disjunction and
**all 17,212 tests still pass**. Verified by mutation. There are two call sites
for `completeness_for_feeds` and only the early-return one is exercised, so the
invariant is unprotected on the path every artifact with dependencies takes.

The lesson generalises: **aggregate green is weak evidence for an invariant.**
Mutate the line and re-run before believing a test protects it.

---

## Open work, in the order I would do it

### 1. #4042 — conda ↔ PyPI alias graph (P1) — WORK EXISTS, FINISH IT
Recover `/tmp/4042.patch`, rebase onto `main`, gates, PR.
Conda dependencies currently get **zero** advisory coverage that looks
identical to a clean scan: OSV has no `conda` ecosystem, and GitHub's
ecosystem `match` drops conda to `_ => continue`. The patch resolves conda
names to PyPI aliases and branches on the three `AliasCoverage` states —
`Mapped` (query as PyPI), `NotPythonPackage` (query unscoped), `Unmapped`
(**degrade the scan**, never report clean). Findings name the conda package
the user installed (`py-opencv`), not the alias queried (`opencv-python`).

### 2. #4036 — hosted path discards the fail-closed signal (**P0**, the only P0)
Highest-priority open issue in the epic. Same bug class as #4035: a scan that
cataloged nothing must not grade clean.

### 3. #4039 — `handler_key()` aliases Conda to pypi (P1)
Related trap, already confirmed: `formats/mod.rs:110` maps
`"poetry" | "conda" | "jupyter" => PypiHandler`, while `conda_native` is the
real handler. The conda *routes* accept both (`conda.rs:1058`), which is why
this has not broken visibly — but anything going through the format-handler
dispatch treats a `conda` repo as PyPI.

### 4. #4041 — correct purl emission for conda (P1)
Channel/subdir/build in the artifact's own purl. Partially advanced by the
merged work (vendored components already emit purls).

### 5. #4053 → #4054 → #4055 — environment SBOM chain (P1/P2/P2)
Do in order; each builds on the last. `environment_lock.rs` (merged) already
parses six lockfile formats into a resolved set with per-platform scoping and
an `explain()` reverse-BFS — #4053 builds the SBOM on top of that, #4054 the
reverse index, #4055 the re-evaluation on new advisories.

### 6. #4046 — binary content cataloging (P2)
Closes the biggest honest gap in what shipped: recipe-derived components only
cover packages that ship a recipe. A statically linked blob with no published
recipe is invisible today. Carries a real false-positive rate; deliberately
excluded from the first pass.

### 7. #4040 — adopt rattler crates (P1)
Strategic: prefix.dev/pixi tooling rather than hand-rolled conda semantics.
Large, and best done when the surface is stable.

### Remaining
#4038, #4043, #4044, #4049, #4050, #4051, #4058, #4059, #4067.

---

## Non-epic follow-ups filed today

- **#4082** — every PyPI attestation published before ~2026-05 fails a Rekor
  `envelopeHash` check and is reported as a `signature/certificate chain`
  error. Evidence: 193 attestations classified, clean cutover, zero
  unexplained. Affects production now. Includes a policy question that needs a
  human decision.
- **#4088** — the mutation-testing gap above.

Shipped today: **#4083** (repository format round-trip) and **#4084** (OSV
batch attribution, closing #4079/#4080/#4081), both cherry-picked onto
`release/1.10.x` for a 1.10.1 that has not been tagged yet.

---

## Deployment (grace)

Running at `https://artifacts.100-89-230-107.sslip.io` (self-signed
`nebari-dev-ca`; `curl -k`). MicroK8s, `microk8s kubectl`, ssh as
`geraci@100.89.230.107`. Images build on grace itself (x86_64) and push to the
local registry at `localhost:32000`.

**The deployed images predate the merge.** Rebuild from `main` and redeploy so
what is tested is what shipped.

Test data already there: `conda-demo` (real conda-forge libwebp, libpng,
openssl, xz `.tar.bz2`, zlib), `npm-demo` (real `core-js` and a synthetic
`ak-rule-engine-probe`), plus `conda-e2e` / `conda-native-e2e`.

Credentials: `local-admin` (NOT `admin`, which is OIDC-backed and correctly
refuses password auth); password in the `ak-admin-credentials` secret.

**Verify through the client's own parser, not by reading JSON.** A contract bug
survived API-level testing because the UI's zod schema required a `path` field
the backend never sends; only a browser exposed it.

### Known good demo

Upload a real conda package and read
`GET /api/v1/artifacts/{id}/package-analysis`. libwebp yields one vendored
component from `recipe:meta.yaml` with the upstream tarball URL and sha256;
libpng comes from `rendered_recipe.yaml` (rattler-build v2) with 2 patches; xz
exercises the legacy `.tar.bz2` codec.

### Known blind spots — demonstrate these honestly

- **Nested interpreters evade the script rules.** Real `core-js` has
  `postinstall: node -e "..."` and produces **zero findings**. Documented
  limit, not a bug.
- **Indirection evades entirely** (`bash $PREFIX/real.sh`).
- **No recipe, no vendored components.**

A clean Analysis tab is not a safety certificate. Say so when demoing.

### Untested, worth doing

Findings include a `snippet` field echoing attacker-controlled script text.
React escapes by default, but nobody has published a package with
`<img src=x onerror=alert(1)>` in a `postinstall` and confirmed it renders
inert. Do that.

---

## Working agreements that earned their keep today

- **Isolated shallow clones per agent**, never a shared checkout. A shared tree
  meant one agent's red TDD state blocked everyone, and `git add` before a
  later edit produced a pushed merge commit that did not compile.
- **Verify after the last change, not before it.** Two failures today came from
  running a gate, then editing, then not re-running: a `tsc` error that broke a
  Docker build, and a `fmt` failure that misdiagnosed a compile error.
- **A test that passes before the fix is not a regression test.** Get a genuine
  red and paste it.
- **Mutate to check an invariant.** See #4088.
- **Two call sites for one decision is a smell.** The covered one hides the
  uncovered one.
