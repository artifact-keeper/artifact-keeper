---
section: Fixed
issues: [#6271]
---
- **A file outside the `groupId/artifactId/version/file` layout in a Maven or Gradle repository no longer shows up as a package** (#6271, artifact-keeper-web#1234). An upload such as `_remote.repositories`, `resolver-status.properties` or a three-segment path like `com/myDomain/notes.txt` fell back to the generic path coordinate and registered the first group directory as a package (`com` at version `myDomain`). Publish time and chunked uploads (peer replication included) now use the same Maven coordinate helper as the catalog backfill and the migration worker, so these files keep their artifact row and register no package.

  Rows registered before the fix stay. Every Maven/Gradle package is named `groupId:artifactId`, so the leftovers are the ones without a colon. List them first (read-only):

  ```sql
  SELECT r.key, p.name, p.version FROM packages p JOIN repositories r ON r.id = p.repository_id WHERE r.format::text IN ('maven', 'gradle') AND p.name NOT LIKE '%:%' ORDER BY r.key, p.name;
  ```

  After reviewing that list, delete them (their `package_versions` rows go with them):

  ```sql
  DELETE FROM packages p USING repositories r WHERE r.id = p.repository_id AND r.format::text IN ('maven', 'gradle') AND p.name NOT LIKE '%:%';
  ```
