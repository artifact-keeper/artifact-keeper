---
section: Changed
issues: [#5110]
---
- **Every outbound HTTP client now sends `User-Agent: artifact-keeper/<version>`** (#5110). Follow-up to #5036, which covered only the SSO/OIDC client. The upstream/proxy, webhook, internal service, large-object and server-side-copy clients, the S3 `object_store` client, and the clients for cloud metadata endpoints, presigned storage URLs and AWS token fetches sent none, which web application firewalls (for example the AWS WAF `NoUserAgent_HEADER` rule) commonly refuse or rate-limit. A repository's custom User-Agent still takes precedence on proxied requests.
