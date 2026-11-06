---
section: Security
issues: [#5440]
---
- **zip is now 9.1.2, which fixes GHSA-m665-v7pm-7grj (critical)** (#5440). zip 9.0.4 and earlier had a parser differential between the local file header and the central directory record (Zip Cloaking), so one archive could show different entries to different readers and get around checks made on the other view. The backend parses uploaded NuGet, VS Code extension, PyPI wheel, Composer, Go, Swift, Terraform and conda archives, WASM plugins and Artifactory imports with this crate. The change is lockfile-only.
