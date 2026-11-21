---
section: Security
issues: [#6394]
---
- **The scanner adapter's bundled trivy now links containerd v2.4.2** (#6394). It fixes CVE-2026-95839 (containerd daemon crash via a malformed digest in a subject-annotated descriptor), which the Docker Publish scan reported against containerd v2.4.1 in the trivy binary shipped in the scanner-adapter image. Trivy is still 0.76.0, so it still pairs with the 0.76.0 trivy server sidecar. Only the containerd module changes. The scanner adapter image version moves to 1.7.2.
