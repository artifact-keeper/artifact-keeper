---
section: Fixed
issues: [#4166]
---
- **`scan_on_upload` now scans packages pushed through every format's native client, not only generic, PyPI, NuGet, Debian, Incus and conda uploads** (#4166). Thirty format-native upload handlers (npm, Maven, Cargo, Go, docker push, Composer, Conan, Helm, RubyGems, RPM, Alpine, Hex, CRAN, Ansible, Puppet, Hugging Face, Swift, Terraform, VS Code, JetBrains, Pub, SBT, Chef, CocoaPods, Git LFS, Protobuf and the chunked upload API) wrote the artifact row themselves and never started the scan, so a repository with scan-on-upload enabled stayed unscanned until someone ran a repository scan by hand. Every handler now goes through one shared trigger, and a source-scan test fails the build if a new upload path inserts an artifact without it.
