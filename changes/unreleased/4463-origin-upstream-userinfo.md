---
section: Security
issues: [#4463]
---
- **Artifact origin records no longer keep the credentials of a Remote whose upstream URL embeds `user:password@`** (#4463). The origin trigger copied the Remote's `upstream_url`, userinfo included, into `artifacts.origin` of every artifact proxied through it (and the upstream index from migration 230 held the same value); the proxy-cache catalogue recorded the credentialed fetch URL too. The origin normalizer (SQL `ak_normalize_upstream_url` and its Rust mirror, now pinned to each other by a test) strips the userinfo, migration 271 rewrites the stored origins and `proxy_cache_artifacts.upstream_url` in 5000-row batches, and the catalogue strips it on write. This also fixes origin policies: `allowed_upstreams` never admitted, and `denied_upstreams` never denied, an artifact proxied through a credentialed Remote, because the stored value carried the credentials and the policy's did not. Both now match the credential-free URL.

  Operator note: the Remote's own `upstream_url` still holds the credentials, because the proxy authenticates from it, and policy results saved before #4462 may still quote them. Move the secret to the Remote's encrypted upstream-auth fields (recreate the Remote with a credential-free URL) and rotate it.
