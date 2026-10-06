---
section: Changed
issues: [#3896, #3897, #4359]
---
- **A release run now dispatches the release announcement and the AMI build itself, and both can be run by hand** (#3896, #3897, #4359). `release.yml` creates the GitHub Release with `GITHUB_TOKEN`, which starts no `release: published` workflow, so since the certified flow no release had been announced or had an AMI built while every release run stayed green. `release.yml` now dispatches `release-announce.yml` (every release) and `ami-build.yml` (stable tags only) and follows each run, so a failed downstream run fails the release run. Both workflows gain a validated `workflow_dispatch` (`tag`, and `version`/`regions`), and the announcement no longer calls a stable release "a new pre-release" or doubles the product name in its title. Before the next stable cut, `DISCORD_RELEASE_WEBHOOK` must be rotated and `AWS_AMI_BUILDER_ROLE_ARN` must exist; the AMI job is non-blocking until a tagged build succeeds.
