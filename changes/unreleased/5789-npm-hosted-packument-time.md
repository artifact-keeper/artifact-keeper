---
section: Fixed
issues: [#5789]
---
- **npm packuments of hosted packages carry `time`, so Yarn 4's default age gate no longer quarantines every hosted version** (#5789). The full document of a Local or Staging package had only `name`, `versions` and `dist-tags`, and the abbreviated one no `modified`. Yarn 4 counts a version without a publish time as quarantined forever under its default `npmMinimalAgeGate`, and `npm install --before` picked the newest version. The packument now has a `time` entry per live version from the artifact's `created_at`, plus `created` and `modified`, and the abbreviated document has `modified`. A Virtual merges it as it already does for Remote members.
