---
section: Fixed
issues: [#5262]
---
- **Scanning a Maven JAR no longer reports the `provided` and `test` dependencies declared in its embedded build POM as shipped components** (#5262). The scan workspace unpacks the archive before running grype on the directory, which exposed `META-INF/maven/<groupId>/<artifactId>/pom.xml` to syft's POM cataloger; every declared dependency was then graded as if bundled, so a Maven plugin declaring `maven-core` as `provided` could be blocked on `maven-core` CVEs. Directory scans now pass `--exclude '**/META-INF/maven/**/pom.xml'`. The archive itself stays in the workspace, so its own identity and any bundled or shaded components are still cataloged from their `pom.properties`.
