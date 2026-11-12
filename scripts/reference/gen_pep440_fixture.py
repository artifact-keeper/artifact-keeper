#!/usr/bin/env python3
"""Generate backend/test_fixtures/reference/pep440.jsonl.

Each line is one version string with what pypa/packaging says about it:
whether it is a valid PEP 440 version, its normalized form, whether it is a
pre-release, and its rank in packaging's ordering (equal versions share a
rank). `formats::pypi` is checked against this file by
`pep440_reference_vectors`, so the hand-written parser cannot drift from the
reference implementation without a test failing.

Usage: python3 scripts/reference/gen_pep440_fixture.py > backend/test_fixtures/reference/pep440.jsonl

Uses `packaging` if installed, else the copy pip vendors.
"""
import itertools
import json
import random

try:
    import packaging
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover
    import pip._vendor.packaging as packaging
    from pip._vendor.packaging.version import InvalidVersion, Version

random.seed(440)

RELEASES = ["0", "1", "1.0", "1.0.0", "1.1", "1.10", "1.9", "2", "2.0.1", "01.02", "2024.1.15", "1.0.0.0.1"]
PRES = ["", "a1", "a2", "b1", "rc1", "a", "alpha1", "beta2", "c1", "pre1", "preview3", ".a1", "-a1", "_a1", "a.1", "a-1", "A1", "RC1", "rc01"]
POSTS = ["", ".post1", ".post2", "post1", "-post1", ".post", "-1", ".rev1", ".r1", ".POST1", "_post1", ".post.1"]
DEVS = ["", ".dev1", ".dev2", "dev1", "-dev1", ".dev", ".DEV3", "_dev1", ".dev.1"]
LOCALS = ["", "+abc", "+abc.def", "+abc-def", "+abc_def", "+1", "+1.2", "+ABC", "+a.1", "+1.a", "+ubuntu.1"]
EPOCHS = ["", "1!", "2!", "0!", "01!"]

corpus = set()
# Every combination would be ~1.5M; sample the grid, and take full slices
# along each axis so each spelling is covered.
axes = [EPOCHS, RELEASES, PRES, POSTS, DEVS, LOCALS]
base = ["", "1.0", "", "", "", ""]
for i, axis in enumerate(axes):
    for value in axis:
        parts = list(base)
        parts[i] = value
        corpus.add("".join(parts))
for a, b in itertools.combinations(range(len(axes)), 2):
    for va in axes[a]:
        for vb in axes[b]:
            parts = list(base)
            parts[a], parts[b] = va, vb
            corpus.add("".join(parts))
for _ in range(700):
    corpus.add("".join(random.choice(axis) for axis in axes))

# Strings that are near PEP 440 but not valid, or valid in a surprising way.
corpus.update([
    "v1.0", "V1.0", "vv1.0", " 1.0 ", "1.0 ", "1.0\n", "1..0", "1.0.", ".1.0", "1.0+", "1.0++a", "1.0+a..b",
    "1.0+_a", "1.0+a_", "1.0a1a2", "1.0.dev1a1", "1.0.post1a1", "1.0.dev1.post1", "1.0.post1.dev1",
    "1.0a1.post1.dev1", "1.0-1-1", "1.0_1", "1.0a1-2", "1.0a1_2", "1.0.1-1", "1!", "!1.0", "1!!2", "a!1.0",
    "1.0x", "1.0alpha", "1.0.alpha", "latest", "", "1.0a99999999999999999999", "99999999999999999999",
    "99999999999999999999!1", "1.0.post99999999999999999999", "1.0+99999999999999999999", "1.0-rc.1",
    "1.0.0-alpha.1", "1.0.0-beta+exp.sha.5114f85", "1.0-SNAPSHOT", "1.0final", "1.0.final", "1.0c", "1.0pre",
    "1.0-r1", "1.0r", "1.0.b", "１.0", "1.0 ", "1.0-", "1.0a1dev1", "1.0adev", "1.0b2.post345.dev456",
    "1.0+abc.5", "1.0+5", "1.0+abc", "1.0+ABC.5", "1.0+a-b_c.d",
])

rows = []
for text in sorted(corpus):
    try:
        version = Version(text)
    except InvalidVersion:
        rows.append({"version": text, "valid": False})
        continue
    rows.append({"version": text, "valid": True, "normalized": str(version),
                 "prerelease": version.is_prerelease, "_v": version})

valid = sorted((r for r in rows if r["valid"]), key=lambda r: r["_v"])
rank = -1
previous = None
for row in valid:
    if previous is None or row["_v"] != previous:
        rank += 1
        previous = row["_v"]
    row["rank"] = rank
print(json.dumps({"_generated_by": "scripts/reference/gen_pep440_fixture.py", "packaging": packaging.__version__}))
for row in rows:
    row.pop("_v", None)
    print(json.dumps(row, ensure_ascii=True, sort_keys=True))
