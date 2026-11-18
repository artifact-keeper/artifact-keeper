---
section: Fixed
issues: [#6233]
---
- **The Trivy filesystem scan of a Maven JAR no longer grades the dependencies declared in its embedded build POM as shipped components** (#6233). #5262 kept `META-INF/maven/<groupId>/<artifactId>/pom.xml` out of the grype directory scan, but the Trivy filesystem scan of the same staged workspace still read it, so a JAR that bundles none of the code it declares (including `provided` and `test` scope) could be blocked or quarantined on those dependencies' CVEs. The scan workspace now drops the embedded build POMs before Trivy runs, on both the local CLI and scanner-adapter paths. Bundled and shaded components are still graded at the versions they ship, from their `pom.properties`.
