---
section: Fixed
issues: [#4081]
---
- **A finding now names the dependency it is actually about, instead of whichever dependency happened to be first in the manifest** (#4081). Every `RawFinding` the dependency scanner emitted set `affected_component: Some(deps.first()…unwrap_or_default())`. `GET /api/v1/…/sbom` joins on `COALESCE(sf.affected_component, sf.title)` to name a component, so the wrong name propagated into generated SBOM documents — which consumers treat as authoritative — and into the finding dedup key, where two advisories against two different packages could collapse into one. The symptom was documented in-tree (a comment telling readers to treat the field as absent) but the cause was never fixed. `DependencyScanner::scan` now walks the lookup's per-dependency slots and files each finding against the dependency whose slot produced it.
