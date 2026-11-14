---
section: Security
issues: [#5547]
---
- **The MCP lint checks the URLs a transport URL template expands to, and package `transport.url`** (#5547). The `remote_url_shape` and `secret_literal` URL rules ran on the raw template only, so `{base}/sse` with a variable `default` of `https://user:pass@host` (no `://` in the template) carried a credential past the lint, and a package's `transport.url` was never run through them at all. Both are now linted as written and as expanded with the publisher's own values (`value`, `default`, `placeholder`, `choices`); a finding on an expansion says so and never quotes it. A package transport URL gets the credential and user-info rules only, since `http://localhost:<port>` is normal for a server the client launches. The scheme check (`http(s)` only) is unchanged.
