---
section: Fixed
issues: [#3937]
---
- **A Cargo virtual member whose sparse-index body is stored content-encoded now contributes its versions to the merged index instead of silently dropping them** (#3937). The ungated Virtual member index fetch used the coding-blind `proxy_fetch_capped`, so a gzip-stored member body parsed as zero NDJSON lines and the member contributed nothing to the merged sparse index with no error — cargo then could not resolve versions the upstream plainly published. The fetch now goes through the encoding-aware `proxy_fetch_capped_encoded` plus the same decode step the age-gated member path already used.
