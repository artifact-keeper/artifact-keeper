---
section: Fixed
issues: [#5573]
---
- **Hosted publishes no longer re-read the `artifacts` table to announce the upload** ([#5573]). Every hosted format publish (Maven, npm, Cargo, OCI and the rest) ended by looking up the row it had just written by repository and SHA-256, ordered by creation time, to fill the `artifact.uploaded` event. No index serves that lookup, so in a large repository each publish walked hundreds of thousands of buffers, and during Maven release bursts it was the largest consumer of database time. The handlers now hand the registration the id and uploader of the row they wrote, so a publish issues no query for the event. The webhook and email payload is unchanged, except that a file whose bytes already exist at another path in the same repository is now reported as itself rather than as that other file.
