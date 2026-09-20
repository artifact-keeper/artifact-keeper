# Package Content Analysis — Design

**Date**: 2026-09-19
**Status**: Implemented (conda, npm verified end to end; PyPI, RPM, Debian in review)
**Branch**: `feat/conda-supply-chain-security`
**Epic**: #4033

## The problem

A package manager's metadata describes what a package *claims* to be. Our
scanners have always read that claim and reported on it. For most formats that
is nearly adequate, because the claim and the contents mostly agree.

For a compiled package they do not agree at all.

A conda package is a pre-built binary. `info/index.json` lists the recipe's
conda-level dependencies and says nothing about the C and C++ libraries linked
into the payload — which is where the CVEs are. When libwebp had
CVE-2023-4863, a conda `pillow` still declared `pillow 10.2.0`, every scanner
agreed it was clean, and the vulnerable code was in the artifact the whole
time.

Two further facts, neither visible to any scanner:

1. **Packages execute code at install time.** conda `post-link`, npm
   `postinstall`, RPM `%post`, Debian `postinst`. The RPM and Debian ones run
   as **root** during an ordinary `dnf install`. Nothing in this codebase
   looked at any of them; `postinstall` appeared exactly once in the backend,
   in a test fixture written to describe the attack.

2. **A scan that never opened the archive is indistinguishable from a clean
   one.** `ScanWorkspace::is_archive` recognised 11 extensions against 53
   repository formats. Everything outside those 11 was staged as an opaque
   blob, cataloged nothing, and was scored **grade A** (#4035, #4036).

## What this adds

Content analysis at **ingest**, from the bytes the registry already holds,
independent of any scanner engine.

- **Vendored components.** For conda, parsed out of `info/recipe/`. The
  recipe declares the upstream source URL, version and applied patches, which
  is a statement of what was actually built in.
- **Install scripts.** Detected, stored, and statically analysed for a small
  set of behaviours: remote code execution, network egress, credential access,
  writes outside the install prefix, privilege change, obfuscation,
  persistence.
- **Completeness.** Whether we read the package at all, and if not, why.

## Design decisions

### Completeness is a required argument, not a derived one

`record_analysis` takes `Completeness` from the caller. It is deliberately
*not* inferred from whether the findings list came back empty.

If it were inferred, a failed extraction would produce zero components and be
recorded as `Complete` — reintroducing #4035 one layer up. Only the caller
knows whether it looked.

The invariant is enforced four times independently, so that no single edit by
someone who does not know the history can remove it:

| Layer | Mechanism |
|---|---|
| Database | `status NOT NULL` with no default, plus `CHECK (status = 'complete' OR reason IS NOT NULL)` |
| Service | `Completeness` enum has no `Default`; a caller that has not decided cannot compile |
| API | never defaulted, never omitted from the response |
| UI | an unknown status narrows to `not_read`, never to `complete` |

The UI rule is the one that matters most in practice: a future backend sending
a status this client does not know **cannot** render as clean.

### Storage is format-neutral from the first commit

Tables are `package_analysis`, `package_vendored_components`,
`package_install_scripts` — not `conda_*` — each carrying a `format` column.
`PackageAnalysisInput` takes `Vec<(String, Vec<u8>)>`, raw bytes, not conda
types.

This was speculative when written and paid off immediately: adding npm cost
four enum variants, one constructor and one call site. No new table, no new
endpoint, no new rules, no UI rework. RPM, Debian and PyPI followed the same
path.

### Ingest-scoped, not scan-scoped

`scan_packages` (085) records what a scanner engine reported on a given run.
These tables record what we learned by reading the artifact's own bytes. They
are valid until the bytes change and readable without a scan having run;
folding them into `scan_packages` would tie facts about the artifact to the
lifecycle of a scan row and lose them on rescan.

### The rule engine is format-agnostic; only the extractors are not

`analyze_script` operates on shell text. conda scripts are files in the
payload; npm scripts are `scripts.*` strings in `package.json`; RPM scriptlets
are header tags. All three end up executing on the installing machine, which
is the only property the analysis depends on — so they share one type and one
engine.

Install hooks whose body lives in a manifest are passed as `inline_scripts`
rather than being synthesised into fake file paths. Inventing
`bin/.pkg-postinstall.sh` to satisfy a path regex would be a lie stored in a
column a user later reads; npm rows say `package.json#scripts.postinstall`.

### False positives are the binding constraint

Most install scripts are a `mkdir -p $PREFIX/...` and a symlink. A script
scanner that fires on those gets muted, and a muted scanner is worse than none
because people believe they have coverage.

The analyser therefore carries two zero-findings assertions as regression
tests: 15 complete benign scripts and 59 individual lines modelled on real
feedstock hooks. Three genuine false positives surfaced during development
(`gzip -d`, `command -v sudo`, `reg query`) and were fixed narrowly rather than
by loosening the tests.

Defences: `echo`/`printf` arguments are blanked before matching (so
`echo "run: curl … | sh"` does not fire, but `echo "$TOKEN" > x` does);
comments are stripped quote-aware; here-doc bodies are skipped unless piped
into an interpreter; write targets are classified so anything under `$PREFIX`,
any unknown `$VAR`, and temp locations stay silent.

### Privilege is reported as a fact, not a severity

RPM and Debian hooks run as root; conda, npm and Python hooks do not.
`ScriptKind::runs_as_root()` exposes this, and the UI renders it as a neutral
outline badge independent of the findings state. A root hook with no findings
is still just a root hook — colouring it red would train reviewers to ignore
it, which is the same failure as a noisy rule.

### Auth precedes visibility on the read path

`GET /api/v1/artifacts/{id}/package-analysis` authenticates before calling
`check_artifact_visibility`, which returns `Ok` early for a public repository.
Checking visibility first would make the endpoint anonymously readable on
exactly the repositories with the widest audience — the shape behind
GHSA-ww52-pmcg-f53c.

It matters more here than elsewhere: the response covers install-script
content from untrusted packages. Script **bodies are not serialised at all**;
the response carries `content_available: bool`. Shipping untrusted shell source
into a browser should be an explicit decision, not a default.

## Honest limits

- **Recipe-derived components only cover packages that ship a recipe.**
  Statically linked code with no published recipe is not covered. Binary
  content analysis would narrow this and carries a real false-positive rate;
  it is deliberately not in this change.
- **Nested interpreters evade the script rules.** `node -e "..."`,
  `python -c "..."` and friends carry code the shell-oriented rules do not
  read. This was demonstrated live, not theorised: an npm `preinstall`
  performing token exfiltration via `node -e` produced zero findings.
- **Indirection evades entirely.** `bash "$PREFIX/share/foo/real.sh"` moves the
  payload into another file. The fix is to follow interpreter-invoked package
  paths, which belongs on the extraction side.
- **Multi-line staging is not correlated.** `curl -o /tmp/x` on one line and
  `/tmp/x` on the next yields only the egress finding; there is no cross-line
  dataflow.
- **Version recovery from a URL basename is heuristic.** Unresolvable template
  expressions yield `Unresolved` with no version rather than a guess, because
  a wrong version silently matches the wrong CVEs.

## Not in this change

Identity mapping to PyPI/CPE, KEV ingestion, attestation verification,
lockfile and environment SBOMs, name-imitation detection, patch lineage and
retirement, upstream-version observation. Each is tracked separately under
#4033.
