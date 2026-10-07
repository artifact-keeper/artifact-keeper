---
section: Security
issues: [#4463]
---
- **Artifact origin records and the proxy-cache catalogue no longer keep the credentials of a Remote whose upstream URL embeds `user:password@`** (#4463). The origin trigger copied the Remote's `upstream_url`, userinfo included, into `artifacts.origin` of every artifact proxied through it, and the upstream index from migration 230 held the same value. The proxy-cache catalogue recorded the credentialed fetch URL too.
  - The origin normalizer strips the userinfo. This applies to the SQL `ak_normalize_upstream_url` and its Rust mirror, which a test now pins to each other.
  - The fill trigger now also normalizes an explicitly supplied origin, and a new trigger strips `proxy_cache_artifacts.upstream_url` on every write. The database is therefore the single enforcement point, including for a replica still running the previous release during a rolling upgrade.
  - Migration 271 rewrites the stored values in 5000-row batches. While it runs, the immutability trigger admits only an `upstream_url` change to its normalized form.
  - A Remote's upstream URL containing whitespace or control characters is now refused with 400 on create and update. Such URLs were accepted and authenticated, but kept their credentials at rest.

  This also fixes origin policies: `allowed_upstreams` never admitted, and `denied_upstreams` never denied, an artifact proxied through a credentialed Remote, because the stored value carried the credentials and the policy entry did not. Both now match the credential-free URL.

  Operator note: the Remote's own `upstream_url` still holds the credentials, because the proxy authenticates from it. On pre-release builds, policy results saved before #4462 may also still quote them. Move the secret to the Remote's encrypted upstream-auth fields (recreate the Remote with a credential-free URL) and rotate it.
