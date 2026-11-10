---
section: Fixed
issues: [#5573]
---
- **A hosted publish no longer reads every row of its repository to send `artifact.uploaded`** ([#5573]). Most native format handlers (`mvn deploy`, `npm publish`, `cargo publish`, `docker push` and others, but not PyPI, NuGet or Debian) look up the `artifacts` row they have just written, so the event can name it. The lookup compared the `CHAR(64)` `checksum_sha256` column with a `text` parameter, so PostgreSQL could not use the checksum index and filtered the whole repository instead. On an instance with several million artifacts and one large hosted Maven repository that averaged 0.8 to 1.7 seconds per call, nearly all of it CPU, and several hundred thousand buffer hits for each published artifact, enough to saturate a small database for the length of a release. The digest is now compared as `bpchar`, which makes the lookup a probe of the existing `idx_artifacts_checksum` index. No migration is needed.
