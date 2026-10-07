---
section: Fixed
issues: [#4424]
---
- **pacman `.db` requests no longer read every package's file list, and `.files` is rendered once per repository state** (#4424). Hosted pacman repositories kept each package's file list (up to 500,000 names) inside its `artifact_metadata` document, so every `pacman -Sy`, anonymous on a public repository, made PostgreSQL detoast all of them only to strip them again, and every `pacman -Fy` re-read and re-gzipped them all. File lists now live in their own `pacman_file_lists` table that the `.db` query never touches, and the rendered `.files` database is cached in memory per repository, architecture and package set, so a publish, delete or signature upload is picked up on the next request without explicit invalidation. Migration 272 creates the table and moves existing lists out of `artifact_metadata` in resumable batches of 100 rows.
