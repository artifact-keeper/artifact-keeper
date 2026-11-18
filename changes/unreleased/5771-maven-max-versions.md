---
section: Fixed
issues: [#5771]
---
- **A `max_versions` lifecycle policy on a Maven or Gradle repository now keeps the newest N versions of each groupId:artifactId, with all their files** (#5771). It ranked artifact rows by artifactId alone and counted files rather than versions, so it kept the N most recently uploaded *files* per artifactId across every groupId: deploying `com.example.beta:core` could delete every version of `com.example.alpha:core`, and a kept version could lose its `.pom`. Maven-layout files are now grouped by their groupId/artifactId directory and ranked per version, so a version's pom, jars, classifier jars and Gradle `.module` are kept or deleted together. "Newest" is still upload time (a version's most recent upload), not version order. The same ranking backs `min_keep` on `max_age_days` and `composite` policies, which had the same bug. Other formats are ranked as before. A preview of an existing policy reports the corrected count.
