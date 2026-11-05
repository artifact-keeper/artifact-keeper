---
section: Fixed
issues: [#5277]
---
- **A Remote Helm repository serves upstream indexes whose chart dependencies have no `version`** (#5277). Upstreams such as `charts.rancher.io` and `rke2-charts.rancher.io` list local subcharts (`repository: file://...`) without a `version`, which Helm allows. `GET /helm/{key}/index.yaml` answered 502 `Failed to parse upstream index.yaml` for the whole repository, and a strict virtual repository with such a member answered 502 for its merged index. Dependency `version` and `name` and maintainer `name` are now optional, as in Helm, and the proxied index leaves out any field the upstream left out. An upstream index entry that still cannot be read, such as a `null` entry or one with no chart `name` or `version`, is now skipped with a warning, as `helm repo add` does, so the other charts in the index are still served.
