---
section: Fixed
issues: [#6494]
---
- **A public virtual repository whose members are all private now challenges an anonymous request with 401 instead of answering 404** (#6494). Maven and Gradle send configured credentials only after a `401` with `WWW-Authenticate: Basic`, so the `404 Virtual repository has no accessible members` made them report the artifact as missing. The challenge is the one a private repository already answers. A signed-in caller without a read grant on any member still gets the 404, and a virtual with at least one public member serves anonymous callers as before
