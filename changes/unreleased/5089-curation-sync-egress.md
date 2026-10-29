---
section: Fixed
issues: [#5089]
---
- **Curation sync now reaches each source Remote the way proxy fetches do** (#5089). The sweep built one HTTP client for every staging repository, so a Remote's `direct` or `explicit` egress proxy setting was not applied to its index fetches and attestation downloads, and the stored upstream URL was not checked by the upstream URL validation. Each Remote now gets a client built from its own egress configuration, and a Remote whose upstream URL the validation refuses is skipped with an info log, without a request, and is not marked as synced.
