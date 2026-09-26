---
section: Fixed
issues: [#3801]
---
- **Local RPM repositories now publish dependency metadata in `primary.xml`, so `dnf` resolves dependencies** (#3801). Each package's `<format>` block now carries `rpm:provides`, `rpm:requires` (with `flags`/`epoch`/`ver`/`rel` and `pre="1"`), `rpm:conflicts`, `rpm:obsoletes` and the weak-dependency lists, plus `rpm:header-range`, vendor, buildhost, packager, the header's epoch, build time, installed and archive sizes, and the primary file list. `filelists.xml` now lists every file. The output follows `createrepo_c` element for element. Packages uploaded before this release are fixed automatically: the first repodata render reads each one's stored header (a ranged read, not the whole package) and records the missing metadata, so no manual backfill or re-upload is needed.
