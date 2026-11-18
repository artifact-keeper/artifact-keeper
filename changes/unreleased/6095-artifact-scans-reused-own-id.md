---
section: Fixed
issues: [#6095]
---
- **An artifact's scan list no longer shows the same scan id twice after a rescan** (#6095). A rescan resolved by reusing the artifact's own earlier scan is listed under its own id, a reuse across byte-identical artifacts still reports the source scan's id
