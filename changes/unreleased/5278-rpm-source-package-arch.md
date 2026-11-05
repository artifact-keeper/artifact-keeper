---
section: Fixed
issues: [#5278]
---
- **RPM repodata lists source RPMs as `src`** (#5278). An uploaded `.src.rpm` was described in `primary.xml`, `filelists.xml` and `other.xml` under its header's ARCH, which in a source package is the build host's architecture (e.g. `x86_64`), so dnf treated it as an installable binary package that provides every subpackage it builds, resolved dependencies on those subpackages to it, and failed the transaction check. A source package (RPMTAG_SOURCEPACKAGE set, the rule `createrepo_c` uses) is now recorded and listed with arch `src`, so dnf never installs it or uses it to satisfy a dependency. Source packages uploaded before the fix need no re-upload: their repodata block is re-derived from the stored header on the next render (only packages that may be source packages are re-read). The `arch` field of such a package's stored artifact metadata keeps the old value until it is re-uploaded; the repodata does not depend on it.
