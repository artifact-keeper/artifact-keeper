---
section: Fixed
issues: [#4258]
---
- **A local (hosted) Debian/APT repository can be created from the web UI again** (#4258). The create dialog attaches `debian: {distribution_paths: [], components: [], architectures: []}` to every Debian-format create request — local, staging and virtual included — and the handler rejected any present `debian` object on a repository that is not a Debian Remote ("debian filter config is only valid for Debian remote (proxy) repositories"), so an untouched form made creating a local Debian repository impossible. An all-default payload configures nothing, so it is now skipped on those targets; a payload that sets something is still rejected (#2460), and an all-`None` patch (`"debian": {}`) is treated the same way on update. Mirrors the npm scope-policy fix (#3299).
