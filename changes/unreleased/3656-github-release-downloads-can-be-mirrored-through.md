---
section: Added
issues: [#3657, #3658]
---
- **GitHub release downloads can be mirrored through dedicated github, mise and aqua formats** (#3657). The formats share the generic handler and `/general` route, with a seven-day finite release-asset cache lifetime and existing revalidation and TTL overrides. Ordinary generic cache and write behaviour is unchanged. Documents private token-backed mirrors and mise lockfiles; GitHub API caching remains unchanged (#3658), and standalone aqua CLI integration is not provided. Nothing in the code prevents a mirror from combining `is_public: true` with an upstream token, so any anonymous caller could spend that token against GitHub; operators must keep token-bearing mirrors private. The mise `url_replacements` recipe puts the Artifact Keeper token in the URL userinfo (`https://USER:TOKEN@host/...`), so it can surface in mise's logs, shell history or proxy logs; treat that token as exposed wherever the mise config is readable.
