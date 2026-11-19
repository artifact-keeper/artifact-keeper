---
section: Security
issues: [#6281]
---
- **On a build someone else created, the builds API lists only artifacts that are really stored in a repository you can read, and counts only those** (#6281). A non-owner used to see a recorded artifact whenever its path started with the key of a readable repository. That path is text the build's creator types, so `dist/x.jar` was shown to every signed-in user whenever a public repository named `dist` existed. Now `<key>/<path>` must be a stored artifact in repository `<key>`, and otherwise only the creator and administrators see it. `artifact_count` on such a build is now the number of artifacts the caller is shown, not the total attached, so it no longer reveals how many are hidden. The creator and administrators see every artifact and the full count, as before.
