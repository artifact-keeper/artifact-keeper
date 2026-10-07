---
section: Changed
issues: [#2904]
---
- **Hex publish rejects a tarball without a usable `CHECKSUM` member with 422** (#2904). Such a tarball used to be accepted and stored, but the registry could never describe the release (`inner_checksum` is required by `mix`), so every later `/packages/{name}` read answered 500. The check now runs before anything is stored, so a refused publish leaves no artifact or storage object behind. Tarballs built by `mix hex.build` always carry the member; releases already stored keep resolving through the existing read-path backfill.
