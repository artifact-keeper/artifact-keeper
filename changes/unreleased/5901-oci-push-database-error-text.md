---
section: Security
issues: [#5901]
---
- **OCI push and upload errors no longer carry the database's own error text** (#5901). The `/v2` upload start, chunked `PATCH`, completing `PUT` and the upload-session helpers built their error message from the raw database error, which could name tables, columns and constraints. They now answer `503 UNAVAILABLE` with `Retry-After` when the database cannot answer and `500` otherwise, with a fixed message; the original goes to the server log only. The `/v2` error envelope also strips database error text from any other 5xx, and a plain `500` that carried an unavailable database's error, on push and pull routes alike, now answers `503` with `Retry-After` (#4765).
