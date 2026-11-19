---
section: Security
issues: [#6320]
---
- **The scanner adapter's bundled trivy is rebuilt on Go 1.27.4** (#6320). It fixes CVE-2026-97054 (net/http: `MaxBytesReader` on HTTP/1 servers) in the trivy binary shipped in the scanner-adapter image, which was built on Go 1.27.3. Only the Go toolchain changes; trivy is still 0.76.0 with the same overrides.
