---
section: Fixed
issues: [#3587, #3814]
---
- **Maven hosted uploads commit the artifact row and its metadata in one transaction** (#3587, #3814). The `ON CONFLICT` upsert that closed #3587 and the dependent `artifact_metadata` write ran as two autocommit statements, so a metadata failure after the row landed left a live artifact with no Maven metadata, and a concurrent republish could observe the row before its metadata existed. Both now commit together, matching the shared `ArtifactService` upload path; the quarantine upload-hold and catalog registration run after the commit as before. The #3587 regression now runs its eight racers on a multi-thread runtime so the statements genuinely overlap.
