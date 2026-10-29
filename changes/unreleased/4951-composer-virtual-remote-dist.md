---
section: Fixed
issues: [#4951]
---
- **Composer Virtual repositories now serve Packagist-style Remote members' metadata and dist archives** (#4951). Metadata proxied through a Virtual served the member's `dist.url`s verbatim, sending the Composer client to the off-registry host and bypassing the Virtual; and a non-scanning Remote member's dist was resolved by synthesizing `dist/<vendor>/<package>/<version>/<ref>.zip` against the member's upstream base, which Packagist-style upstreams never serve and answered 404. The Virtual metadata now rewrites dist URLs to the Virtual key like the single-repo Remote path, and the Virtual download walk resolves each Remote member's real dist URL from its own cached metadata before streaming or scanning it.
