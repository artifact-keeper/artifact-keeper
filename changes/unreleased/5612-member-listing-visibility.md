---
section: Security
issues: [#5612]
---
- **The virtual member listing no longer tells an existing private repository from an unknown key** ([#5612]). `GET /api/v1/repositories/{key}/members` checked the repository's type and the token's repository scope before checking whether the caller could read the repository. A logged-in user with no grant, or a token scoped to other repositories, therefore got a wrong-type `400` or a `403` for an existing private key where an unknown key answers `404`, and learned whether the key was a virtual. The listing now checks visibility first and answers such a caller exactly what an unknown key answers: `404 {"code": "NOT_FOUND", "message": "Repository not found"}`. A caller who can read the repository keeps the wrong-type `400` and the listing, and admins and owners are unaffected.
