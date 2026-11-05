---
section: Fixed
issues: [#5250]
---
- **An instance administrator with an unrestricted credential can list, make and revoke acknowledgement decisions in every repository** (#5250). `GET /api/v1/security/acknowledgements` and `"scope": "all_repositories"` no longer depend on which repository roles the administrator holds, so a fresh install's built-in `admin` can use them. A credential restricted to some repositories still reaches only those.
