---
section: Fixed
issues: [#4130]
---
- **A token scoped to a virtual repository can read its Packages catalog through that virtual repository** (#4130). The format endpoints and virtual artifact reads already support request-bound member reads (#4559), but `GET /api/v1/packages?repository_key=<virtual>` still intersected the member rows with a token naming only the parent, returning an empty page. Package detail had the same mismatch; package versions now also accept the optional `repository_key` context. The list, count, detail and versions use the same authorized leaf-member set, including nested virtuals, after checking that the caller can read the named parent and each member. Unknown or unreadable contexts reveal no membership, and a package outside the named repository does not match.

  The token itself is unchanged: no selector expansion flag, read-expansion JWT claim, or implicit direct-member access is added. Reads without a virtual context keep their existing scope checks, member writes remain unavailable to a virtual-only token, and native index/download policy enforcement is unchanged. This is catalog metadata authorization, not a replacement for the format-specific package admission or scanning gates.
