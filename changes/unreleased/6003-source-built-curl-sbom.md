---
section: Security
issues: [#6003]
---
- **The backend and OpenSCAP images now list their source-built curl and libcurl in an embedded CycloneDX SBOM, and a daily check compares those curl pins with curl's advisory feed** (#6003). Both images build curl or libcurl from source at a pinned `CURL_VERSION` instead of installing the RPM. Scanners that read the RPM database, such as Trivy, can't see that copy. Each image now carries `/usr/share/sbom/curl.cdx.json`, generated at build time from the same `CURL_VERSION`. It has the CPEs `cpe:2.3:a:haxx:libcurl:<version>` (and `haxx:curl` in the backend image) and `pkg:generic` purls, so scanners that read embedded SBOMs and match by CPE, such as grype, report curl CVEs against these images.

  The new `Scheduled curl Advisory Watch` workflow checks each pin against https://curl.se/docs/vuln.json every day. When a pin is affected, the workflow fails and opens or updates a `type:security` tracking issue.
