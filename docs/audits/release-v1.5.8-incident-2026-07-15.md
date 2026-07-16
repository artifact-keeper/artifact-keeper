# v1.5.8 Release Integrity Incident — 2026-07-15

**Status:** Containment in progress

**Related baseline:** `docs/audits/release-assurance-baseline-2026-07-15.md`

## Summary

The `v1.5.8` Git tag was used for two different source commits. Both release
workflow runs failed their required full release gate, but a public GitHub
Release existed and the second run replaced every attached binary with a
different build.

The container set also has an identity gap. Backend, web, and OpenSCAP have
application-version tags, while scanner-adapter is independently versioned as
`1.2.0`. Its exact semver tag was later moved by a `main` build without a
version bump, so it no longer identifies the adapter built by the v1.5.8 tag
run.

## Timeline

All timestamps are UTC on 2026-07-15 unless noted.

| Time | Event |
|---|---|
| 18:47 | Release run `29441967462` started for `v1.5.8` at source `69994531eb7bd223cc8e073471e692c8586e6688` |
| 19:34 | Its aggregate full release gate failed |
| 19:55 | Its release job completed after building five binaries; failed gates caused draft intent |
| 22:13 | A second tag event started release run `29454678955` for the same `v1.5.8` name at different source `97680d2875f5110febe90001f63080252247aece` |
| 22:57 | The second aggregate full release gate failed |
| 23:05:14 | GitHub records release `354677069` as published |
| 23:11 | The second run's final binary build completed |
| 23:12 | The second release job requested `draft: true`, found the existing release, deleted all prior assets, and uploaded replacements while the release remained public |

The organization audit-log API returned HTTP 404 for the authenticated
organization administrator, so the canonical audit event was unavailable.
Corroborating event evidence is mixed but useful:

- The repository `ReleaseEvent` records action `published` with actor/author
  `github-actions[bot]` at 23:05:14.
- The release-triggered `Sync OpenAPI Spec` run (`29457482883`) records
  `triggering_actor=brandonrc` and started at 23:05:16.

This is consistent with publication of an action-created draft through an
authenticated user interaction, but the unavailable organization audit event
prevents treating that inference as definitive.

## Gate results for the second tag event

Required failures:

- Pinned vulnerable-image efficacy: Trivy database fetch unauthorized.
- Lifecycle: unbound `LAYER_DIGEST` in OCI GC mark-sweep.
- Platform: metrics endpoint/series assertions failed.
- Aggregate `collect-results`: failed.

Additional red evidence:

- Security: 71 tests passed, 1 failed; job was soft-failing.
- Mesh: registration/failover failures; job was optional.
- Docker publication verification: expected a nonexistent scanner-adapter
  `1.5.8` tag even though the component's declared version was `1.2.0`.

## Binary replacement evidence

The first run's retained workflow artifacts and the current public release
contain different SHA-256 checksums for every binary.

| Asset | First tag run (`69994531`) | Current public release (`97680d2`) |
|---|---|---|
| `artifact-keeper-darwin-amd64.tar.gz` | `d65a4e2642a0908c576edbba7243632993c402d90ff490dd911d5154c684255e` | `d43f29d170ba50ee7cd0ec22b130e831ce5cdfb0243694597a1b8ffafcff8340` |
| `artifact-keeper-darwin-arm64.tar.gz` | `bd3979d16abf5c526ce04f5bc63faa7297959fb2236588fd183582e94d656a80` | `a9638d24d8e7801d0e34be82874d5e228c9baf8ca6c2fd5a8cd460b79d987166` |
| `artifact-keeper-linux-amd64.tar.gz` | `29bef4a091f633c2ac2e0c320fc21f9b622e46a1bb80f97757c21fec87035096` | `63bc1604454418e0fd0a290d90ed99311d5617fba6673159bde03fe7b0c635c7` |
| `artifact-keeper-linux-arm64.tar.gz` | `cf9f7fe717bba377f05114b04438b89b31bd1eadf7c098291a391b59bcf20482` | `bf62a1aab18fe7ea47d9432295509c3839378bcd16fe5c5a1cc6741851fe4a3d` |
| `artifact-keeper-windows-amd64.exe` | `4e646c4ddff3270c12b97ad8ce477b385353e8945c55d7549afc14b75a782675` | `844500e9c0f768472cba6fd9271f55e1b5446588c48bdbede32fe058f5887373` |

The release action had `overwrite_files: true` by default/effective behavior.
Its log explicitly shows deletion of the ten existing binary/checksum assets
before replacement.

## Registry digest inventory

Registry manifests were resolved directly with OCI-index accept headers. GHCR
and Docker Hub agreed for every currently resolvable tag.

| Component/tag | Current digest in both registries |
|---|---|
| Backend `1.5.8` | `sha256:741f1d89ea2e435fb9bd8247d2429d6033318ec4ee5f21dc5895b42004facbf4` |
| OpenSCAP `1.5.8` | `sha256:16fc6d6beb4242487e87a115c68e0574f845fc5a2f2a71653bb6a7d210cc494f` |
| Web `1.5.8` | `sha256:3d19838cd0885a2c13f99d05450bdf41ece714c78d79fc2777f824b17d8300cd` |
| Scanner adapter `1.2.0` / `1` | `sha256:2df0e935f367f9749d50a4181bb8238c70fccdf8e8fe8479d8aa80540d0d3467` |

The v1.5.8 Docker publication log proves scanner-adapter `1.2.0` originally
resolved to:

`sha256:5aa1488c8ff917ff957ed4635ecaa4ee19552e39ac36d636c9da01068614e286`

A later `main` build moved `1.2.0`, `1.2`, `1`, and `latest` to
`sha256:2df0e935...` while `docker/scanner-adapter/VERSION` remained `1.2.0`.
The exact semver tag therefore does not currently provide immutable component
identity.

## Root control failures

1. Tag updates/deletion were not prevented, so one version named two commits.
2. Binary builds explicitly continued after full release-gate failure.
3. The release job ran after failed gates and relied on a draft flag as its
   only publication control.
4. A retry found an existing public release and overwrote its assets despite
   requesting draft mode.
5. Stable container publication was independent of the release verdict.
6. Scanner-adapter exact semver tags were republished from `main`.
7. One Docker verifier assumed application semver for an independently
   versioned component. This verifier was corrected on `main` by `ee862db1`,
   but the component-tag immutability issue remains.

## Containment actions

- [x] Require exact release-gate success before building release binaries.
- [x] Require exact required-gate success before invoking the release action.
- [x] Refuse to create or update a release when its tag already has a release
      object.
- [x] Disable release-asset overwrite.
- [x] Reject forced/moved tag events in both publication workflows. Repository
      tag-rule enforcement remains outstanding.
- [ ] Protect version tags from update or deletion with a repository ruleset.
- [x] Stop publishing scanner-adapter semver/stable tags from `main`.
- [x] Refuse to move an existing scanner-adapter exact semver tag to a new
      digest; require a VERSION bump.
- [x] Bump scanner-adapter to `1.2.1` because `1.2.0` moved and its current
      manifest lacks immutable source-revision metadata.
- [ ] Add a visible v1.5.8 integrity notice and supersede it with a new version
      after required gates pass.

## Evidence retention

- First run artifacts were downloaded to
  `/tmp/ak-v158-first-run-29441967462` during investigation.
- Current public checksum files were downloaded to
  `/tmp/ak-v158-current-release-checksums`.
- Workflow logs and GitHub-hosted artifacts remain the source of record; `/tmp`
  copies are investigative conveniences only.
