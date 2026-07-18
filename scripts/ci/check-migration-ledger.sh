#!/usr/bin/env bash
#
# CI gate for issue #2689: migration-ledger divergence guardrail.
#
# FAILS the build when `main` (the current tree) and an active `release/*`
# branch assign the SAME migration version number to DIFFERENT content
# (different filename and/or different file bytes). That reuse is a ledger
# divergence: a database that applied the release-branch migration N stores a
# checksum that `sqlx migrate run` later rejects against main's migration N on
# upgrade (`Migration(VersionMismatch(N))`), bricking the upgrade. This is the
# root-cause prevention for #2686 (v1.5.x -> 1.6.0 upgrade brick); the 1st
# occurrence of the class was release/1.1.x slots 73-75.
#
# What it does:
#   1. Enumerates active release branches via `git ls-remote --heads origin
#      'release/*'` (works for N branches, not just release/1.5.x).
#   2. Shallow-fetches each release branch into refs/remotes/origin/<branch>
#      so the comparison works on a shallow CI checkout.
#   3. For every version number N present in backend/migrations/ on BOTH the
#      current tree AND a release branch, compares the SHA-384 of the file
#      bytes and the filename.
#   4. FAILS (nonzero exit) on any divergence not pinned in the committed
#      allowlist (scripts/ci/migration-ledger-allowlist.txt).
#
# KNOWN, HANDLED divergences (main vs release/1.5.x slots 154/155, reconciled
# by backend/src/migration_repair.rs::repair_release_1_5_x_divergence) are
# pinned by SHA-384 in the allowlist so the build is green today and fails
# ONLY on new, unhandled reuse.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$ROOT/backend/migrations}"
ALLOWLIST="${ALLOWLIST:-$ROOT/scripts/ci/migration-ledger-allowlist.txt}"
# Space-separated override for tests / air-gapped runs; normally discovered
# from the remote.
RELEASE_BRANCHES="${RELEASE_BRANCHES:-}"

python3 - "$ROOT" "$MIGRATIONS_DIR" "$ALLOWLIST" "$RELEASE_BRANCHES" <<'PY'
import hashlib
import os
import re
import subprocess
import sys

root, migrations_dir, allowlist_path, branches_override = sys.argv[1:5]

VER = re.compile(r"^(\d+)_.*\.sql$")


def git(*args, capture_bytes=False):
    return subprocess.run(
        ["git", "-C", root, *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not capture_bytes,
    ).stdout


def discover_release_branches():
    if branches_override.strip():
        return branches_override.split()
    try:
        out = git("ls-remote", "--heads", "origin", "release/*")
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(
            "ERROR: could not enumerate release branches via "
            "`git ls-remote --heads origin 'release/*'`:\n"
            f"{exc.stderr}\n"
        )
        sys.exit(2)
    branches = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        ref = line.split("\t", 1)[1] if "\t" in line else line.split()[-1]
        if ref.startswith("refs/heads/"):
            branches.append(ref[len("refs/heads/") :])
    return sorted(set(branches))


def ensure_fetched(branch):
    """Shallow-fetch a release branch so its tree is readable on a shallow
    CI checkout. Idempotent; tolerates already-present refs when offline."""
    remote_ref = f"refs/remotes/origin/{branch}"
    try:
        git(
            "fetch",
            "--depth=1",
            "origin",
            f"refs/heads/{branch}:{remote_ref}",
        )
    except subprocess.CalledProcessError as exc:
        # If the ref is already present (e.g. offline test run) keep going;
        # otherwise the read below will surface a clear error.
        try:
            git("rev-parse", "--verify", "--quiet", remote_ref)
        except subprocess.CalledProcessError:
            sys.stderr.write(
                f"ERROR: could not fetch release branch {branch}:\n{exc.stderr}\n"
            )
            sys.exit(2)


def ledger_from_tree():
    """version -> (filename, sha384) for the current working tree."""
    out = {}
    for name in os.listdir(migrations_dir):
        m = VER.match(name)
        if not m:
            continue
        with open(os.path.join(migrations_dir, name), "rb") as fh:
            digest = hashlib.sha384(fh.read()).hexdigest()
        out[int(m.group(1))] = (name, digest)
    return out


def ledger_from_branch(branch):
    """version -> (filename, sha384) for a release branch's migrations dir."""
    ref = f"origin/{branch}"
    rel = os.path.relpath(migrations_dir, root)
    out = {}
    names = git("ls-tree", "-r", "--name-only", ref, "--", rel).splitlines()
    for path in names:
        name = path.split("/")[-1]
        m = VER.match(name)
        if not m:
            continue
        blob = subprocess.run(
            ["git", "-C", root, "show", f"{ref}:{path}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
        out[int(m.group(1))] = (name, hashlib.sha384(blob).hexdigest())
    return out


def load_allowlist():
    """(branch, version) -> (main_name, main_sha, rel_name, rel_sha)."""
    allow = {}
    if not os.path.exists(allowlist_path):
        return allow
    with open(allowlist_path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            fields = line.split()
            if len(fields) != 6:
                sys.stderr.write(
                    f"ERROR: malformed allowlist line {allowlist_path}:{lineno} "
                    f"(expected 6 fields, got {len(fields)}): {line}\n"
                )
                sys.exit(2)
            branch, version, main_name, main_sha, rel_name, rel_sha = fields
            allow[(branch, int(version))] = (main_name, main_sha, rel_name, rel_sha)
    return allow


def main():
    branches = discover_release_branches()
    allow = load_allowlist()
    tree = ledger_from_tree()

    if not branches:
        print("OK: no active release/* branches to compare against.")
        return

    print(f"Comparing current tree against release branches: {', '.join(branches)}")

    violations = []
    matched_allow = set()

    for branch in branches:
        ensure_fetched(branch)
        rel = ledger_from_branch(branch)
        for version in sorted(set(tree) & set(rel)):
            main_name, main_sha = tree[version]
            rel_name, rel_sha = rel[version]
            if main_name == rel_name and main_sha == rel_sha:
                continue  # same version, identical content: not a divergence

            key = (branch, version)
            entry = allow.get(key)
            if entry and entry == (main_name, main_sha, rel_name, rel_sha):
                matched_allow.add(key)
                print(
                    f"  allowlisted: {branch} v{version} "
                    f"({main_name} / {rel_name})"
                )
                continue

            reason = "not in allowlist"
            if entry is not None:
                reason = "allowlist entry does not match current content"
            violations.append((branch, version, main_name, main_sha, rel_name, rel_sha, reason))

    # Report allowlist entries that no longer correspond to a live divergence
    # (stale pins — a warning, not a failure).
    for key in sorted(allow):
        if key not in matched_allow:
            print(
                f"  note: stale allowlist entry {key[0]} v{key[1]} "
                f"(no matching divergence found — safe to remove)"
            )

    if violations:
        sys.stderr.write(
            "\nERROR: migration-ledger divergence detected (issue #2689).\n"
            "The same migration version number carries DIFFERENT content on\n"
            "`main` and a release branch. A database upgraded across this fork\n"
            "will hit `sqlx migrate run` VersionMismatch and fail to start.\n\n"
        )
        for branch, version, mn, ms, rn, rs, reason in violations:
            sys.stderr.write(
                f"  version {version} ({reason}):\n"
                f"    main            : {mn}\n"
                f"                      sha384={ms}\n"
                f"    {branch:<15} : {rn}\n"
                f"                      sha384={rs}\n\n"
            )
        sys.stderr.write(
            "Fix: add a migration_repair reconciliation AND an allowlist entry\n"
            f"({os.path.relpath(allowlist_path, root)}), or renumber the\n"
            "migration so the version numbers no longer collide.\n"
        )
        sys.exit(1)

    print("OK: no unhandled migration-ledger divergences.")


main()
PY
