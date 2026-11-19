---
section: Fixed
issues: [#5913]
---
- **Concurrent first scans of images containing JAR files no longer fail on the Java DB download** (#5913). The scanner adapter ran one trivy process per scan, and each one that met a JAR downloaded trivy's Java DB (~1 GiB) into the same cache directory on demand, so two such scans right after an adapter start unpacked over each other and one failed with `chmod .../java-db/trivy-java.db: no such file or directory`, each staging its own ~1.9 GiB copy in `TMPDIR`. The adapter (now 1.7.1) downloads the Java DB itself, one download at a time (shared in-process, and under a file lock across replicas that share a cache volume), into a staging directory that is renamed into place, and every scan runs with `--skip-java-db-update`. Connected installs fetch it in the background at startup without delaying readiness, and refresh it once its `NextUpdate` passes, like the vulnerability DB.

  If the Java DB cannot be downloaded, the adapter logs it and keeps scanning: images without JAR files scan as before, and images with JAR files fail with the download error, with the next attempt 5 minutes later. `SCANNER_TRIVY_SKIP_DB_UPDATE` skips the startup download and refreshes (the first JAR scan still fetches a missing Java DB on demand), and `SCANNER_OFFLINE` never downloads it.

  This ships in scanner-adapter **1.7.1**, a separate image. Connected installs now download the Java DB (~1 GiB) in the background at startup even if they never scan a JAR, and a refresh briefly needs room for two copies in `SCANNER_TRIVY_CACHE_DIR`; size that volume accordingly. Under a `block_on_fail` policy, a JAR scan that fails because the Java DB is unavailable quarantines the artifact until a later scan succeeds.
