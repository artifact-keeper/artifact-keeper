#!/usr/bin/env python3
"""Check every source-built curl pin against curl's own advisory feed (#6003).

WHY
---
docker/Dockerfile.backend (the curl-bin stage) and docker/Dockerfile.openscap
(the curl-builder stage) build curl / libcurl from a source tarball at a
hand-maintained `ARG CURL_VERSION`. Nothing else watches those pins: Trivy and
the Docker Publish gate read the RPM database, which no longer lists this
curl, and Dependabot does not read ARGs. A libcurl CVE against the pin would
neither fail a publish nor raise a code-scanning alert. This script is the
control that closes that gap; .github/workflows/scheduled-curl-advisory-watch.yml
runs it daily.

THE FEED
--------
https://curl.se/docs/vuln.json is a JSON array of OSV (schema 1.5) records,
one per curl advisory. For each record this reads:
  affected[].ranges[] with type SEMVER   ordered `introduced` / `fixed` (and,
                                          if curl ever emits them,
                                          `last_affected` / `limit`) events
  affected[].versions[]                  the explicit list of affected releases
  database_specific.affects              "lib", "tool" or "both"
A pin is affected when either the SEMVER ranges or the explicit list says so.
An event or range shape this script does not understand is INFRA, not clean:
a parser that skipped what it could not read would report a vulnerable pin as
a clean one.

SCOPE PER IMAGE
---------------
The backend image ships the curl TOOL with libcurl linked statically into it,
so "lib", "tool" and "both" advisories all apply. The OpenSCAP image ships only
the LIBRARY from source (its curl command is the curl RPM (curl-7.76.1), which Trivy
already sees), so a "tool"-only advisory is reported there as not applicable.
The PINS table below is the source of truth; a pin that disappears from its
Dockerfile is INFRA, so retiring a stage means editing that table.

EXIT CODES
  0  every pin measured, none affected
  1  at least one pin is affected by at least one advisory
  2  something could not be measured (feed unreachable or malformed, a pin
     missing or not a plain X.Y.Z version). Unmeasured is never reported as
     clean.

USAGE
  check-curl-advisories.py [--feed PATH_OR_URL] [--repo-root DIR]
  REPO_ROOT may also be given in the environment.
"""

import argparse
import json
import os
import re
import sys
import urllib.request

FEED_URL = "https://curl.se/docs/vuln.json"

# (Dockerfile, the advisory `affects` scopes that apply to what it ships)
PINS = [
    ("docker/Dockerfile.backend", {"lib", "tool", "both"},
     "curl tool, libcurl linked statically"),
    ("docker/Dockerfile.openscap", {"lib", "both"},
     "libcurl shared library only"),
]

ARG_RE = re.compile(r"^\s*ARG\s+CURL_VERSION\s*=\s*\"?([^\s\"]+)\"?\s*$", re.MULTILINE)
VERSION_RE = re.compile(r"^\d+(\.\d+){1,3}$")


class Unmeasurable(Exception):
    pass


def vkey(v):
    if v == "0":
        return (0,)
    if not VERSION_RE.match(v):
        raise Unmeasurable(f"not a plain dotted version: {v!r}")
    parts = tuple(int(p) for p in v.split("."))
    return parts + (0,) * (4 - len(parts))


def in_semver_range(pin, events, adv_id):
    """OSV range evaluation over one ordered event list."""
    p = vkey(pin)
    parsed = []
    for ev in events:
        if not isinstance(ev, dict) or len(ev) != 1:
            raise Unmeasurable(f"{adv_id}: unexpected range event {ev!r}")
        (kind, ver), = ev.items()
        if kind not in ("introduced", "fixed", "last_affected", "limit"):
            raise Unmeasurable(f"{adv_id}: unknown range event type {kind!r}")
        if not isinstance(ver, str):
            raise Unmeasurable(f"{adv_id}: non-string version in {ev!r}")
        parsed.append((vkey(ver), kind))
    # OSV: sort by version; at equal versions an `introduced` sorts first.
    parsed.sort(key=lambda e: (e[0], 0 if e[1] == "introduced" else 1))
    affected = False
    for ver, kind in parsed:
        if kind == "introduced":
            if p >= ver:
                affected = True
            else:
                break
        elif kind == "fixed" or kind == "limit":
            if p >= ver:
                affected = False
            else:
                break
        elif kind == "last_affected":
            if p > ver:
                affected = False
            else:
                break
    return affected


def advisory_hits(pin, adv):
    """(affected?, why) for one OSV record."""
    adv_id = adv.get("id", "<no id>")
    affected_list = adv.get("affected")
    if not isinstance(affected_list, list) or not affected_list:
        raise Unmeasurable(f"{adv_id}: no `affected` list")
    vkey(pin)
    for aff in affected_list:
        ranges = aff.get("ranges", [])
        versions = aff.get("versions", [])
        if not isinstance(ranges, list) or not isinstance(versions, list):
            raise Unmeasurable(f"{adv_id}: malformed `affected` entry")
        semver = [r for r in ranges if isinstance(r, dict) and r.get("type") == "SEMVER"]
        if not semver and not versions:
            raise Unmeasurable(f"{adv_id}: neither a SEMVER range nor a version list")
        for r in semver:
            events = r.get("events")
            if not isinstance(events, list) or not events:
                raise Unmeasurable(f"{adv_id}: SEMVER range without events")
            if in_semver_range(pin, events, adv_id):
                return True, "in SEMVER range"
        if pin in versions:
            return True, "listed in affected versions"
    return False, ""


def load_feed(src):
    try:
        if re.match(r"^https?://", src):
            req = urllib.request.Request(src, headers={"User-Agent": "curl-advisory-watch"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
        else:
            with open(src, "rb") as fh:
                raw = fh.read()
    except Exception as exc:  # noqa: BLE001 - any failure here is INFRA
        raise Unmeasurable(f"could not read the advisory feed {src}: {exc}")
    try:
        feed = json.loads(raw)
    except ValueError as exc:
        raise Unmeasurable(f"advisory feed {src} is not JSON: {exc}")
    if not isinstance(feed, list) or not feed:
        raise Unmeasurable(f"advisory feed {src} is not a non-empty JSON array")
    for adv in feed:
        if not isinstance(adv, dict) or "id" not in adv:
            raise Unmeasurable(f"advisory feed {src} has a record without an id")
    return feed


def read_pins(root):
    pins = []
    for rel, scopes, ships in PINS:
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            raise Unmeasurable(f"{rel}: cannot read ({exc})")
        found = ARG_RE.findall(text)
        if not found:
            raise Unmeasurable(
                f"{rel}: no `ARG CURL_VERSION=` pin. If that stage was retired, "
                "drop it from PINS in scripts/ci/check-curl-advisories.py.")
        for v in sorted(set(found)):
            vkey(v)
            pins.append((rel, v, scopes, ships))
    return pins


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--feed", default=FEED_URL)
    ap.add_argument("--repo-root", default=os.environ.get("REPO_ROOT") or
                    os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
    args = ap.parse_args(argv)

    try:
        pins = read_pins(args.repo_root)
        feed = load_feed(args.feed)
        print(f"curl advisory feed: {args.feed} ({len(feed)} advisories)")
        any_hit = False
        for rel, pin, scopes, ships in pins:
            hits, skipped = [], []
            for adv in feed:
                hit, why = advisory_hits(pin, adv)
                if not hit:
                    continue
                db = adv.get("database_specific") or {}
                scope = db.get("affects", "both")
                cve = ",".join(adv.get("aliases") or []) or adv["id"]
                line = (f"{cve} [{db.get('severity', '?')}] affects={scope} "
                        f"{adv.get('summary', '').strip()} ({why}; "
                        f"{db.get('www', '')})")
                # An `affects` value this script does not know counts as a hit.
                known = scope in ("lib", "tool", "both")
                (hits if scope in scopes or not known else skipped).append(line)
            status = "AFFECTED" if hits else "clean"
            print(f"\n{rel}: CURL_VERSION={pin} ({ships}): {status}")
            for h in hits:
                print(f"  AFFECTED  {h}")
            for s in skipped:
                print(f"  n/a       {s} -- this image does not ship that part")
            any_hit = any_hit or bool(hits)
    except Unmeasurable as exc:
        print(f"INFRA: {exc}")
        return 2
    if any_hit:
        print("\nAt least one source-built curl pin is affected. Bump CURL_VERSION "
              "and CURL_SHA256 in the Dockerfile(s) named above.")
        return 1
    print("\nEvery source-built curl pin is clean against the feed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
