---
section: Changed
issues: [#3896, #3897, #4359]
---
- **A release run now dispatches the release announcement and the AMI build itself, and both can be run by hand** (#3896, #3897, #4359). Releases are created by the release workflow, and a release created that way starts no other workflow, so recent releases were never announced and had no AMI built although every release run was green. The release workflow now starts the announcement (every release) and the AMI build (stable releases only) and waits for each, so a failed one fails the release run. Both can also be dispatched by hand for a given tag or version. The announcement no longer calls a stable release "a new pre-release" or repeats the product name in its title.
