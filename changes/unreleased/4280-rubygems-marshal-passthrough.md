---
section: Fixed
issues: [#4280, #4272]
---
- **RubyGems remote and virtual specs indexes no longer come back empty when the upstream serves gzipped Marshal** (#4280, #4272). rubygems.org's `specs.4.8.gz`, `latest_specs.4.8.gz` and `prerelease_specs.4.8.gz` are gzipped Ruby Marshal, not JSON. A remote repository rebuilt them from cached gems only, and a virtual repository JSON-parsed the upstream body, failed and silently dropped the member, so `gem` and `bundler` saw an empty (~24-byte) index. A remote repository now passes the upstream index through unchanged. A virtual repository decodes each remote member's Marshal index and merges it with its hosted members' gems; a hosted member keeps precedence for every gem name it owns, and a remote member whose index cannot be fetched or decoded now fails the request with 502 naming the member instead of being left out. Thanks to @vvs9896 for the original fix.
