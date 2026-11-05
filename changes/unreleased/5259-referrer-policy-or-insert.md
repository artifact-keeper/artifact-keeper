---
section: Fixed
issues: [#5259]
---
- **Agent Plugins token URLs now really send `Referrer-Policy: no-referrer`** (#5259). The `/agentplugins/t/{token}/...` routes carry a credential in the path and set `no-referrer` so a browser never leaks the URL in a `Referer`, but the global security-headers middleware unconditionally replaced it with the default `strict-origin-when-cross-origin`. The middleware now fills in the default Referrer-Policy only when a route has not set one, the same way it already treats Content-Security-Policy (#1773), so a route can tighten it. Deployments that expose the backend directly (without a reverse proxy restoring the header) were affected; every other route keeps the same default.
