#!/usr/bin/env python3
"""Every bug fix comes with an end-to-end proof, or says why it cannot.

WHY
---
A fix whose only test is a unit test proves the function, not the deployment.
The 1.12.0 triage found bug after bug whose unit test was green while the
deployed system, driven by a native client, still misbehaved, and the release
gate in artifact-keeper-test (the DTF tiers and the k8s suites) only enforces
what someone wired into it. So a bug PR now names its end-to-end proof in its
body, and the release backstop checks that every closed bug in the milestone
has one before the cut.

SUBCOMMANDS (exit 0 ok, 1 missing or invalid proof, 2 usage/infra)
  pr [--event F | --pr N] [--repo R] [--test-repo R] [--no-write]
      Check one pull request. --event reads the pull_request event payload
      (the workflow's GITHUB_EVENT_PATH); --pr N reads the PR from the API.
      With a deferred proof (label needs-e2e-test, no proof line) the label is
      copied to the linked issues unless --no-write.
  milestone --milestone X (--tests-ref REF | --tests-dir D) [--repo R]
            [--test-repo R] [--exemptions F]
      The release backstop: every closed type:bug issue in milestone X needs
      a tier that covers it (manifest COVERS) and is wired into the release
      gate at REF, a suite the closing PR names, a ledger row in
      scripts/ci/e2e-exemptions.tsv, or an exemption on its closing PR.

WHAT COUNTS AS A BUG PR
  A linked (Closes/Fixes/Resolves #N) issue labelled type:bug, a title of
  type `fix`, or a head branch `fix/*`.

HOW A PR DECLARES ITS PROOF (one line each, in the body, outside comments
and code blocks)
  E2E: artifact-keeper-test#N          a test PR adding or extending a tier
                                       or suite; it must be open or merged,
                                       touch deploy-test/harness/tiers/** or
                                       tests/**, name the backend issue, and
                                       carry a `## Validation` section with a
                                       RED line and a GREEN line
  E2E: tier <name>                     an existing tier whose manifest COVERS
                                       the issue or whose oracle has a
                                       `FIX #N` case
  E2E: suite tests/<area>/<file>.sh    an existing suite that names the issue
  E2E-Exempt: <category>: <reason>     plus the label no-e2e-required
  (no line) + label needs-e2e-test     deferred: passes, the label is copied
                                       to the issue, the backstop blocks

  Exemption categories: test-only, build-ci, deps, docs,
  internal-unreachable (name the unit/integration test), race-window (name
  the barrier/failpoint/stress test), embargoed (`embargoed: GHSA-...:
  reason`; the public tier asserts a harmless facet until disclosure).

  Automatic exemptions: title type test/ci/docs/chore/build; a diff only in
  docs, .github, scripts, changes, Cargo.lock or audit config. Both apply
  ONLY when no linked issue is type:bug: a type:bug issue needs a proof line
  or an explicit exemption whatever the PR's title or diff (and so at the
  release backstop, where every issue is type:bug, they never apply). Flake fixes:
  the ci or testing label plus `Flake-Proof: <how reproduced>; <N>
  consecutive passes under <load>`.

RELEASE LINES
  A PR into release/X must cite a test PR whose base is the test repo's
  release/X (and tiers/suites are read from that branch). A backport inherits
  its original PR's exemption through the `(cherry picked from commit <sha>)`
  trailer.

All GitHub access goes through `gh api`, so the self-test
(scripts/ci/test-check-e2e-proof.sh) replays canned answers with a stub gh.
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile

BUG_LABEL = "type:bug"
EXEMPT_LABEL = "no-e2e-required"
DEFER_LABEL = "needs-e2e-test"
FLAKE_LABELS = ("ci", "testing")
AUTO_EXEMPT_TITLE_TYPES = ("test", "ci", "docs", "chore", "build")
CATEGORIES = (
    "test-only",
    "build-ci",
    "deps",
    "docs",
    "internal-unreachable",
    "race-window",
    "embargoed",
)
# The ledger also records backfill decisions that are not PR exemptions.
LEDGER_CATEGORIES = CATEGORIES + ("not-planned",)
NAMES_A_TEST = ("internal-unreachable", "race-window")

DEFAULT_REPO = "artifact-keeper/artifact-keeper"
DEFAULT_TEST_REPO = "artifact-keeper/artifact-keeper-test"
TIERS_DIR = "deploy-test/harness/tiers"
GATE_WORKFLOW = ".github/workflows/release-gate.yml"
GATE_JOBS = ("dtf-gate", "dtf-advisory")


class Infra(Exception):
    """Could not measure: a retryable failure, never a verdict."""


class NotFound(Infra):
    pass


# --- GitHub access -----------------------------------------------------------


def gh_api(endpoint, method="GET", payload=None):
    # The endpoint comes straight after `api` so a stub can dispatch on $2.
    cmd = ["gh", "api", endpoint, "-H", "Accept: application/vnd.github+json"]
    if method != "GET":
        cmd += ["-X", method]
    if payload is not None:
        cmd += ["--input", "-"]
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as e:
        raise Infra("gh is not on PATH") from e
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip()
        if "HTTP 404" in err or "Not Found" in err:
            raise NotFound(f"{endpoint}: not found")
        raise Infra(f"gh api {endpoint} failed: {err[:300]}")
    out = proc.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise Infra(f"gh api {endpoint}: unparseable answer") from e


def gh_list(endpoint):
    """GET a list endpoint page by page (100 per page) until a short page."""
    sep = "&" if "?" in endpoint else "?"
    items, page = [], 1
    while True:
        got = gh_api(f"{endpoint}{sep}per_page=100&page={page}") or []
        if not isinstance(got, list):
            raise Infra(f"{endpoint}: expected a list")
        items.extend(got)
        if len(got) < 100:
            return items
        page += 1


def gh_graphql(query, variables):
    cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
    for k, v in variables.items():
        cmd += ["-F" if isinstance(v, int) else "-f", f"{k}={v}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise Infra(f"gh api graphql failed: {(proc.stderr or proc.stdout).strip()[:300]}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise Infra("gh api graphql: unparseable answer") from e
    if data.get("errors"):
        raise Infra(f"gh api graphql: {data['errors']}")
    return data["data"]


def file_at(repo, path, ref):
    """Text of `path` in `repo` at `ref`, or None when absent."""
    try:
        got = gh_api(f"repos/{repo}/contents/{path}?ref={ref}")
    except NotFound:
        return None
    if not isinstance(got, dict) or "content" not in got:
        return None
    return base64.b64decode(got["content"]).decode("utf-8", "replace")


# --- body parsing ------------------------------------------------------------


def sanitize(body):
    """Same stripping as require-linked-issue.yml: HTML comments, fenced code
    blocks and inline code spans cannot satisfy (or trip) the check."""
    body = body or ""
    body = re.sub(r"<!--[\s\S]*?-->", "", body)
    body = re.sub(r"```[\s\S]*?```", "", body)
    body = re.sub(r"`[^`\n]*`", "", body)
    return body


LINK_RE = re.compile(
    r"\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b\s*:?\s*"
    r"(?:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+))?#(\d+)",
    re.IGNORECASE,
)


def linked_issues(body, repo):
    owner, name = repo.lower().split("/")
    found = []
    for m in LINK_RE.finditer(body):
        if (m.group(2) or owner).lower() == owner and (m.group(3) or name).lower() == name:
            n = int(m.group(4))
            if n not in found:
                found.append(n)
    return found


TITLE_TYPE_RE = re.compile(r"^\s*([a-z]+)(?:\([^)]*\))?!?:")


def title_type(title):
    m = TITLE_TYPE_RE.match(title or "")
    return m.group(1) if m else ""


PROOF_RE = re.compile(r"^\s*(?:[-*]\s+)?E2E\s*:\s*(.+?)\s*$", re.MULTILINE)
EXEMPT_RE = re.compile(r"^\s*(?:[-*]\s+)?E2E-Exempt\s*:\s*(.+?)\s*$", re.MULTILINE)
FLAKE_RE = re.compile(r"^\s*(?:[-*]\s+)?Flake-Proof\s*:\s*(.+?)\s*$", re.MULTILINE)
FLAKE_SHAPE_RE = re.compile(r".{8,};\s*(\d+)\s+consecutive\s+passes\s+under\s+\S.*", re.IGNORECASE)
TEST_PR_RE = re.compile(r"^(?:artifact-keeper/)?artifact-keeper-test#(\d+)$")
TIER_RE = re.compile(r"^tier\s+([a-z0-9][a-z0-9._-]*)$")
SUITE_RE = re.compile(r"^suite\s+(tests/[A-Za-z0-9._/-]+\.sh)$")
GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
# A test name: a Rust path (module::test), a snake_case identifier with at
# least three words, or a test file.
TEST_NAME_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*::[A-Za-z0-9_:]+"
    r"|\b[a-z][a-z0-9]*(?:_[a-z0-9]+){2,}\b"
    r"|\S+\.(?:rs|sh|py)\b"
)
CHERRY_RE = re.compile(r"\(cherry picked from commit ([0-9a-f]{7,40})\)")


def parse_exemption(text):
    """`<category>: <reason>` -> (category, reason, error)."""
    cat, _, reason = text.partition(":")
    cat, reason = cat.strip().lower(), reason.strip()
    if cat not in CATEGORIES:
        return cat, reason, f"unknown exemption category '{cat}' (one of: {', '.join(CATEGORIES)})"
    if cat == "embargoed":
        ghsa, _, rest = reason.partition(":")
        if not GHSA_RE.match(ghsa.strip()):
            return cat, reason, "embargoed needs `embargoed: GHSA-xxxx-xxxx-xxxx: <reason>`"
        reason = rest.strip() or ghsa.strip()
    if len(reason) < 10:
        return cat, reason, f"exemption '{cat}' needs a reason (10+ characters)"
    if cat in NAMES_A_TEST and not TEST_NAME_RE.search(reason):
        what = "unit/integration" if cat == "internal-unreachable" else "barrier/failpoint/stress"
        return cat, reason, f"'{cat}' must name the {what} test that covers the bug"
    return cat, reason, None


def names_issue(text, issue):
    """Does a test-repo PR title/body name backend issue N?"""
    n = str(issue)
    if re.search(rf"artifact-keeper(?:/artifact-keeper)?#{n}\b", text):
        return True
    if re.search(rf"github\.com/artifact-keeper/artifact-keeper/(?:issues|pull)/{n}\b", text):
        return True
    # Title convention: `(artifact-keeper#N[, #M])`.
    for grp in re.findall(r"\(artifact-keeper#[0-9#, ]+\)", text):
        if re.search(rf"#{n}\b", grp):
            return True
    return False


def validation_section(body):
    """Lines of the `## Validation` section (any heading level >= 2)."""
    lines = (body or "").splitlines()
    out, level = None, None
    for line in lines:
        m = re.match(r"^(#{2,6})\s+(.*?)\s*$", line)
        if m:
            if out is not None and len(m.group(1)) <= level:
                break
            if out is None and m.group(2).lower().startswith("validation"):
                out, level = [], len(m.group(1))
                continue
        if out is not None:
            out.append(line)
    return out


def covers_of(manifest):
    m = re.search(r'^COVERS=["\']?([0-9 ]*)["\']?\s*$', manifest or "", re.MULTILINE)
    return [int(x) for x in m.group(1).split()] if m else []


def fix_cases(oracle):
    return {int(n) for n in re.findall(r'begin_test\s+["\']FIX #(\d+)\b', oracle or "")}


# --- auto-exemption by paths -------------------------------------------------

EXEMPT_PATH_RES = [
    re.compile(p)
    for p in (
        r"^docs/",
        r"\.md$",
        r"^\.github/",
        r"^scripts/",
        r"^changes/",
        r"^Cargo\.lock$",
        r"^\.cargo/audit\.toml$",
        r"^\.trivyignore$",
        r"^\.vex/",
    )
]


def paths_exempt(paths):
    return bool(paths) and all(any(r.search(p) for r in EXEMPT_PATH_RES) for p in paths)


# --- the pr subcommand -------------------------------------------------------


class Verdict:
    def __init__(self):
        self.ok = []
        self.problems = []
        self.notes = []

    def good(self, msg):
        self.ok.append(msg)

    def bad(self, msg):
        self.problems.append(msg)

    def note(self, msg):
        self.notes.append(msg)


def label_names(obj):
    return [lbl["name"] if isinstance(lbl, dict) else lbl for lbl in (obj.get("labels") or [])]


def automatic_exemption(pr, repo, files=None):
    """Reason string when the PR is exempt without saying so, else None."""
    t = title_type(pr.get("title"))
    if t in AUTO_EXEMPT_TITLE_TYPES:
        return f"title type '{t}' is exempt"
    if files is None:
        files = [f["filename"] for f in gh_list(f"repos/{repo}/pulls/{pr['number']}/files")]
    if paths_exempt(files):
        return "the diff touches only docs, .github, scripts, changes, Cargo.lock or audit config"
    return None


def declared_exemption(pr, body):
    """(category, reason, error) from an E2E-Exempt line, or None."""
    m = EXEMPT_RE.search(body)
    if not m:
        return None
    cat, reason, err = parse_exemption(m.group(1))
    if err is None and EXEMPT_LABEL not in label_names(pr):
        err = f"`E2E-Exempt: {cat}` also needs the label {EXEMPT_LABEL}"
    return cat, reason, err


def check_test_pr(num, issues, base, test_repo, v):
    """Validate `E2E: artifact-keeper-test#N`; returns the issues it names."""
    try:
        tpr = gh_api(f"repos/{test_repo}/pulls/{num}")
    except NotFound:
        v.bad(f"{test_repo}#{num} is not a pull request in {test_repo}")
        return set()
    ok = True
    if tpr.get("state") != "open" and not tpr.get("merged"):
        v.bad(f"{test_repo}#{num} was closed without merging")
        ok = False
    want_base = base
    if (tpr.get("base") or {}).get("ref") != want_base:
        v.bad(
            f"{test_repo}#{num} targets '{(tpr.get('base') or {}).get('ref')}', "
            f"but this PR targets '{base}': the test PR must target the same-named branch"
        )
        ok = False
    files = [f["filename"] for f in gh_list(f"repos/{test_repo}/pulls/{num}/files")]
    if not any(p.startswith(TIERS_DIR + "/") or p.startswith("tests/") for p in files):
        v.bad(f"{test_repo}#{num} touches neither {TIERS_DIR}/** nor tests/**")
        ok = False
    text = f"{tpr.get('title') or ''}\n{tpr.get('body') or ''}"
    named = {i for i in issues if names_issue(text, i)}
    if not named:
        v.bad(
            f"{test_repo}#{num} does not name "
            + " or ".join(f"artifact-keeper#{i}" for i in issues)
        )
        ok = False
    val = validation_section(tpr.get("body"))
    if val is None:
        v.bad(f"{test_repo}#{num} has no `## Validation` section")
        ok = False
    else:
        if not any(re.search(r"\bRED\b", ln) for ln in val):
            v.bad(f"{test_repo}#{num}'s Validation section has no RED line (the pre-fix image)")
            ok = False
        if not any(re.search(r"\bGREEN\b", ln) for ln in val):
            v.bad(f"{test_repo}#{num}'s Validation section has no GREEN line (the fixed image)")
            ok = False
    if ok:
        v.good(f"{test_repo}#{num} ({tpr.get('state')}{', merged' if tpr.get('merged') else ''}) proves " + ", ".join(f"#{i}" for i in sorted(named)))
        return named
    return set()


def check_tier(name, issues, ref, test_repo, v):
    manifest = file_at(test_repo, f"{TIERS_DIR}/{name}/manifest", ref)
    if manifest is None:
        v.bad(f"tier '{name}' does not exist on {test_repo}@{ref}")
        return set()
    oracle = file_at(test_repo, f"{TIERS_DIR}/{name}/oracle.sh", ref) or ""
    named = {i for i in issues if i in covers_of(manifest) or i in fix_cases(oracle)}
    if not named:
        v.bad(
            f"tier '{name}' neither COVERS nor has a `FIX #N` case for "
            + ", ".join(f"#{i}" for i in issues)
        )
        return set()
    v.good(f"tier '{name}' on {ref} covers " + ", ".join(f"#{i}" for i in sorted(named)))
    return named


def check_suite(path, issues, ref, test_repo, v):
    text = file_at(test_repo, path, ref)
    if text is None:
        v.bad(f"suite {path} does not exist on {test_repo}@{ref}")
        return set()
    named = {i for i in issues if re.search(rf"#{i}\b", text)}
    if not named:
        v.bad(f"suite {path} does not name " + ", ".join(f"#{i}" for i in issues))
        return set()
    v.good(f"suite {path} on {ref} names " + ", ".join(f"#{i}" for i in sorted(named)))
    return named


def inherited_exemption(pr, repo, allow_automatic=True):
    """For a backport: the exemption of the main PR it was cherry-picked from.
    An automatic (title/paths) exemption is inherited only when the backport's
    own linked issues are not type:bug, the same rule run_pr applies."""
    commits = gh_list(f"repos/{repo}/pulls/{pr['number']}/commits")
    shas = []
    for c in commits:
        for sha in CHERRY_RE.findall((c.get("commit") or {}).get("message") or ""):
            if sha not in shas:
                shas.append(sha)
    for sha in CHERRY_RE.findall(pr.get("body") or ""):
        if sha not in shas:
            shas.append(sha)
    for sha in shas:
        try:
            origins = gh_api(f"repos/{repo}/commits/{sha}/pulls") or []
        except NotFound:
            continue
        for o in origins:
            if (o.get("base") or {}).get("ref") == pr["base"]["ref"]:
                continue
            body = sanitize(o.get("body"))
            ex = declared_exemption(o, body)
            if ex and ex[2] is None:
                return f"inherited from #{o['number']} (cherry-picked {sha[:8]}): E2E-Exempt {ex[0]}"
            auto = automatic_exemption(o, repo) if allow_automatic else None
            if auto:
                return f"inherited from #{o['number']} (cherry-picked {sha[:8]}): {auto}"
    return None


def run_pr(args):
    repo, test_repo = args.repo, args.test_repo
    if args.event:
        with open(args.event, encoding="utf-8") as fh:
            pr = json.load(fh).get("pull_request")
        if not pr:
            print("usage: the event has no pull_request", file=sys.stderr)
            return 2
    elif args.pr:
        pr = gh_api(f"repos/{repo}/pulls/{args.pr}")
    else:
        print("usage: pr needs --event or --pr", file=sys.stderr)
        return 2

    v = Verdict()
    body = sanitize(pr.get("body"))
    labels = label_names(pr)
    base = (pr.get("base") or {}).get("ref") or "main"
    head = (pr.get("head") or {}).get("ref") or ""
    title = pr.get("title") or ""
    print(f"PR #{pr['number']}: {title}")
    print(f"  base {base}, head {head}, labels: {', '.join(labels) or '(none)'}")

    issue_nums = linked_issues(body, repo)
    issues = {}
    for n in issue_nums:
        try:
            issues[n] = gh_api(f"repos/{repo}/issues/{n}")
        except NotFound:
            v.note(f"linked #{n} does not exist (require-linked-issue reports it)")
    bug_issues = [n for n, i in issues.items() if BUG_LABEL in label_names(i)]

    reasons = []
    if bug_issues:
        reasons.append("linked " + ", ".join(f"#{n}" for n in bug_issues) + f" {'is' if len(bug_issues) == 1 else 'are'} {BUG_LABEL}")
    if title_type(title) == "fix":
        reasons.append("the title type is fix")
    if head.startswith("fix/"):
        reasons.append("the head branch is fix/*")
    if not reasons:
        return finish(v, "not a bug PR (no type:bug issue, fix title or fix/* branch): no proof needed", 0)
    print("  bug PR: " + "; ".join(reasons))

    # A non-fix title type or a confined diff exempts a PR only when no linked
    # issue is type:bug. A type:bug issue needs a proof line or an explicit
    # exemption whatever the title says: otherwise `test: ...` or `chore: ...`
    # on a real fix would walk past the check (#5713 was closed by #5719, a
    # `test(...)` PR).
    if bug_issues:
        v.note(
            "a type:bug issue is linked, so the title type and the diff's paths do not exempt this PR"
        )
    else:
        auto = automatic_exemption(pr, repo)
        if auto:
            return finish(v, f"exempt automatically: {auto}", 0)

    targets = bug_issues or list(issues) or []
    all_labels = set(labels)
    for i in issues.values():
        all_labels.update(label_names(i))

    ex = declared_exemption(pr, body)
    if ex:
        cat, reason, err = ex
        if err:
            v.bad(err)
            return finish(v, "the exemption line is not valid", 1)
        return finish(v, f"exempt ({cat}): {reason}", 0)

    flake = FLAKE_RE.search(body)
    if flake:
        if not all_labels.intersection(FLAKE_LABELS):
            v.bad("a Flake-Proof line needs the ci or testing label on the PR or its issue")
        elif not FLAKE_SHAPE_RE.match(flake.group(1)):
            v.bad("Flake-Proof must read `Flake-Proof: <how reproduced>; <N> consecutive passes under <load>`")
        else:
            return finish(v, f"flake fix: {flake.group(1)}", 0)
        return finish(v, "the Flake-Proof line is not valid", 1)

    if base.startswith("release/"):
        inh = inherited_exemption(pr, repo, allow_automatic=not bug_issues)
        if inh:
            return finish(v, f"exempt: {inh}", 0)

    proofs = PROOF_RE.findall(body)
    if not proofs:
        if DEFER_LABEL in labels:
            for n in targets:
                if DEFER_LABEL in label_names(issues[n]):
                    v.note(f"#{n} already carries {DEFER_LABEL}")
                elif args.no_write:
                    v.note(f"would copy {DEFER_LABEL} to #{n} (--no-write)")
                else:
                    gh_api(f"repos/{repo}/issues/{n}/labels", "POST", {"labels": [DEFER_LABEL]})
                    v.note(f"copied {DEFER_LABEL} to #{n}")
            return finish(v, f"deferred ({DEFER_LABEL}): passes now; the release backstop blocks until a tier covers it", 0)
        if all_labels.intersection(FLAKE_LABELS):
            v.note("this looks like a flake fix: add `Flake-Proof: <how reproduced>; <N> consecutive passes under <load>`")
        v.bad(
            "no end-to-end proof declared. Add one of `E2E: artifact-keeper-test#N`, `E2E: tier <name>`, "
            f"`E2E: suite tests/<area>/<file>.sh`, or `E2E-Exempt: <category>: <reason>` plus the label {EXEMPT_LABEL}"
        )
        return finish(v, "missing end-to-end proof", 1)

    if not targets:
        v.note("no linked issue to match the proof against; checking the proof's shape only")
    covered = set()
    for text in proofs:
        m_pr, m_tier, m_suite = TEST_PR_RE.match(text), TIER_RE.match(text), SUITE_RE.match(text)
        want = targets or [0]
        if m_pr:
            got = check_test_pr(int(m_pr.group(1)), want, base, test_repo, v)
        elif m_tier:
            got = check_tier(m_tier.group(1), want, base, test_repo, v)
        elif m_suite:
            got = check_suite(m_suite.group(1), want, base, test_repo, v)
        else:
            v.bad(f"unrecognised proof line `E2E: {text}`")
            continue
        covered |= got
    missing = [n for n in targets if n not in covered]
    if missing and not v.problems:
        v.bad("no declared proof covers " + ", ".join(f"#{n}" for n in missing))
    if v.problems:
        return finish(v, "the declared proof does not hold", 1)
    return finish(v, "end-to-end proof declared and checked", 0)


def finish(v, headline, code):
    status = "PASS" if code == 0 else "FAIL"
    print(f"{status}: {headline}")
    for m in v.ok:
        print(f"  [ok]   {m}")
    for m in v.problems:
        print(f"  [FAIL] {m}")
    for m in v.notes:
        print(f"  note: {m}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"### E2E proof: {status}\n\n{headline}\n\n")
            for m in v.ok:
                fh.write(f"- ok: {m}\n")
            for m in v.problems:
                fh.write(f"- **problem**: {m}\n")
            for m in v.notes:
                fh.write(f"- note: {m}\n")
            fh.write("\nPolicy: CONTRIBUTING.md, \"End-to-end proof for bug fixes\".\n")
    return code


# --- the milestone subcommand ------------------------------------------------

MILESTONE_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    milestone(number: $number) {
      issues(first: 50, after: $cursor, states: CLOSED, labels: ["type:bug"]) {
        pageInfo { hasNextPage endCursor }
        nodes {
          number
          title
          stateReason
          labels(first: 50) { nodes { name } }
          closedByPullRequestsReferences(first: 10, includeClosedPrs: false) {
            nodes {
              number
              title
              body
              merged
              headRefName
              baseRefName
              labels(first: 50) { nodes { name } }
            }
          }
        }
      }
    }
  }
}
"""


def read_ledger(path):
    """issue -> (category, reason) from the TSV ledger."""
    out = {}
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) != 3 or not cols[0].strip().isdigit():
                raise ValueError(f"{path}:{lineno}: want `issue<TAB>category<TAB>reason`")
            n, cat, reason = int(cols[0]), cols[1].strip(), cols[2].strip()
            if cat not in LEDGER_CATEGORIES:
                raise ValueError(f"{path}:{lineno}: unknown category '{cat}'")
            if len(reason) < 10:
                raise ValueError(f"{path}:{lineno}: #{n} needs a reason")
            if cat in NAMES_A_TEST and not TEST_NAME_RE.search(reason):
                raise ValueError(f"{path}:{lineno}: #{n} '{cat}' must name its test")
            if n in out:
                raise ValueError(f"{path}:{lineno}: #{n} listed twice")
            out[n] = (cat, reason)
    return out


def gate_tiers(workflow_text):
    """tier -> job for every tier in the dtf-gate / dtf-advisory matrices."""
    out, job = {}, None
    for line in (workflow_text or "").splitlines():
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            job = m.group(1)
            continue
        if job in GATE_JOBS:
            t = re.match(r"^\s+tiers:\s*(.+?)\s*$", line)
            if t:
                for name in t.group(1).strip("\"'").split():
                    out.setdefault(name, job)
    return out


def scan_tests_tree(root):
    """(tier -> covers, tier -> FIX issues, gate tiers) from a test-repo tree."""
    covers, fixes = {}, {}
    tiers_root = os.path.join(root, TIERS_DIR)
    for name in sorted(os.listdir(tiers_root)) if os.path.isdir(tiers_root) else []:
        mpath = os.path.join(tiers_root, name, "manifest")
        if not os.path.isfile(mpath):
            continue
        with open(mpath, encoding="utf-8", errors="replace") as fh:
            covers[name] = covers_of(fh.read())
        opath = os.path.join(tiers_root, name, "oracle.sh")
        if os.path.isfile(opath):
            with open(opath, encoding="utf-8", errors="replace") as fh:
                fixes[name] = fix_cases(fh.read())
    wf = os.path.join(root, GATE_WORKFLOW)
    gate = {}
    if os.path.isfile(wf):
        with open(wf, encoding="utf-8") as fh:
            gate = gate_tiers(fh.read())
    return covers, fixes, gate


def fetch_tests_tree(test_repo, ref, dest):
    url = os.environ.get("E2E_PROOF_TEST_REPO_URL", f"https://github.com/{test_repo}.git")
    steps = [
        ["git", "init", "-q", dest],
        ["git", "-C", dest, "fetch", "-q", "--depth", "1", url, ref],
        ["git", "-C", dest, "checkout", "-q", "FETCH_HEAD"],
    ]
    for cmd in steps:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if p.returncode != 0:
            raise Infra(f"could not fetch {test_repo}@{ref}: {p.stderr.strip()[:300]}")


def run_milestone(args):
    repo, test_repo = args.repo, args.test_repo
    try:
        ledger = read_ledger(args.exemptions)
    except (OSError, ValueError) as e:
        print(f"INFRA: exemption ledger: {e}", file=sys.stderr)
        return 2

    if args.tests_dir:
        tree = args.tests_dir
        ref_label = args.tests_ref or args.tests_dir
    else:
        tree = tempfile.mkdtemp(prefix="e2e-proof-tests-")
        fetch_tests_tree(test_repo, args.tests_ref, tree)
        ref_label = args.tests_ref
    covers, fixes, gate = scan_tests_tree(tree)
    if not gate:
        raise Infra(f"no dtf-gate tiers found in {GATE_WORKFLOW} at {ref_label}")
    by_issue = {}
    for tier, nums in covers.items():
        for n in nums:
            by_issue.setdefault(n, []).append(tier)

    milestones = gh_list(f"repos/{repo}/milestones?state=all")
    ms = next((m for m in milestones if m.get("title") == args.milestone), None)
    if ms is None:
        print(f"INFRA: milestone '{args.milestone}' does not exist in {repo}", file=sys.stderr)
        return 2

    owner, name = repo.split("/")
    nodes, cursor = [], None
    while True:
        variables = {"owner": owner, "name": name, "number": int(ms["number"])}
        if cursor:
            variables["cursor"] = cursor
        data = gh_graphql(MILESTONE_QUERY, variables)
        page = data["repository"]["milestone"]["issues"]
        nodes.extend(page["nodes"])
        if not page["pageInfo"]["hasNextPage"]:
            break
        cursor = page["pageInfo"]["endCursor"]

    rows, blocking = [], 0
    for issue in sorted(nodes, key=lambda i: i["number"]):
        n = issue["number"]
        if issue.get("stateReason") not in (None, "COMPLETED"):
            rows.append((n, "skip", f"closed as {issue['stateReason'].lower()}"))
            continue
        ilabels = [lbl["name"] for lbl in issue["labels"]["nodes"]]
        status, detail = proof_for_issue(n, issue, ilabels, ledger, by_issue, fixes, gate, tree, repo)
        if status in ("MISSING", "DEFERRED", "UNWIRED"):
            blocking += 1
        rows.append((n, status, detail))

    print(f"E2E proof for closed {BUG_LABEL} issues in milestone {args.milestone} (tests at {ref_label})")
    for n, status, detail in rows:
        print(f"  #{n:<6} {status:<9} {detail}")
    counts = {}
    for _, s, _ in rows:
        counts[s] = counts.get(s, 0) + 1
    print("  totals: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    if blocking:
        print(f"NOT READY: {blocking} closed bug(s) in {args.milestone} have no end-to-end proof in the gate.")
        return 1
    print(f"READY: every closed bug in {args.milestone} has an end-to-end proof or an exemption.")
    return 0


def proof_for_issue(n, issue, ilabels, ledger, by_issue, fixes, gate, tree, repo):
    # Every issue here is type:bug, so the closing PR's title type and diff
    # paths never exempt it (the rule run_pr applies): a bug closed by a
    # `test: ...` PR still needs a tier, a suite, or an explicit exemption.
    tiers = by_issue.get(n, [])
    wired = [t for t in tiers if t in gate]
    if wired:
        t = wired[0]
        extra = "" if n in fixes.get(t, set()) else " (warning: no `FIX #N` case)"
        stale = f"; remove {DEFER_LABEL}" if DEFER_LABEL in ilabels else ""
        return "covered", f"tier {t} ({gate[t]}){extra}{stale}"
    if n in ledger:
        return "exempt", f"ledger: {ledger[n][0]}: {ledger[n][1][:80]}"
    prs = issue["closedByPullRequestsReferences"]["nodes"]
    for pr in prs:
        body = sanitize(pr.get("body"))
        plabels = [lbl["name"] for lbl in pr["labels"]["nodes"]]
        pr_obj = {"number": pr["number"], "title": pr["title"], "labels": plabels}
        ex = declared_exemption(pr_obj, body)
        if ex and ex[2] is None:
            return "exempt", f"#{pr['number']}: {ex[0]}: {ex[1][:70]}"
        flake = FLAKE_RE.search(body)
        if flake and FLAKE_SHAPE_RE.match(flake.group(1)) and set(plabels + ilabels).intersection(FLAKE_LABELS):
            return "exempt", f"#{pr['number']}: flake fix"
        for text in PROOF_RE.findall(body):
            ms = SUITE_RE.match(text)
            if ms:
                p = os.path.join(tree, ms.group(1))
                if os.path.isfile(p):
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        if re.search(rf"#{n}\b", fh.read()):
                            return "covered", f"suite {ms.group(1)} (#{pr['number']})"
            mt = TIER_RE.match(text)
            if mt and mt.group(1) in gate and (n in covers_list(tree, mt.group(1)) or n in fixes.get(mt.group(1), set())):
                return "covered", f"tier {mt.group(1)} ({gate[mt.group(1)]}, #{pr['number']})"
    if tiers:
        return "UNWIRED", f"tier {', '.join(tiers)} COVERS it but is not in the release-gate matrix"
    if DEFER_LABEL in ilabels:
        return "DEFERRED", f"labelled {DEFER_LABEL}; no tier covers it yet"
    via = ", ".join(f"#{p['number']}" for p in prs) or "no closing PR"
    return "MISSING", f"no tier, suite or exemption ({via}): {issue['title'][:70]}"


def covers_list(tree, tier):
    p = os.path.join(tree, TIERS_DIR, tier, "manifest")
    if not os.path.isfile(p):
        return []
    with open(p, encoding="utf-8", errors="replace") as fh:
        return covers_of(fh.read())


# --- main --------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pr")
    p.add_argument("--event")
    p.add_argument("--pr", type=int)
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO))
    p.add_argument("--test-repo", default=DEFAULT_TEST_REPO)
    p.add_argument("--no-write", action="store_true")
    m = sub.add_parser("milestone")
    m.add_argument("--milestone", required=True)
    m.add_argument("--tests-ref", help="artifact-keeper-test branch/tag/sha to fetch")
    m.add_argument("--tests-dir", help="a local checkout to read instead (--tests-ref then only labels it)")
    m.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO))
    m.add_argument("--test-repo", default=DEFAULT_TEST_REPO)
    here = os.path.dirname(os.path.abspath(__file__))
    m.add_argument("--exemptions", default=os.path.join(here, "e2e-exemptions.tsv"))
    args = ap.parse_args(argv)
    if args.cmd == "milestone" and not (args.tests_ref or args.tests_dir):
        ap.error("milestone needs --tests-ref or --tests-dir")
    try:
        return run_pr(args) if args.cmd == "pr" else run_milestone(args)
    except Infra as e:
        print(f"INFRA: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
