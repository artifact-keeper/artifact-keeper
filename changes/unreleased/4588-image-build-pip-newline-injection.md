---
section: Security
issues: [#4588]
---
- **Image build specs no longer accept a pip requirement containing a line break** (#4588, GHSA-59mx-6fq9-pp9p). The pip requirement pattern allowed `\s` inside the extras bracket and around version comparators, and `\s` also matches `\n` and `\r`. Each requirement is written into the generated Containerfile's `RUN pip install` line, and the Containerfile parser ends an instruction at an unescaped newline, so a requirement such as `foo[a\nRUN ...]` added its own instruction to the build. That bypassed `AK_IMAGE_BUILD_ALLOW_RUN=false`. Reaching it needs permission to start an image build, which is administrators only unless `AK_IMAGE_BUILD_ADMIN_ONLY=false`. The pattern now allows only spaces and tabs as blanks, and every package spec, for every package manager, is refused with 400 when it contains a control character other than a tab.
