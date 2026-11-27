---
section: Fixed
issues: [#6546]
---
- **The second hop of a promotion chain no longer answers 409 on cloud storage** (#6546). On a shared-namespace backend (S3, GCS, Azure) a promotion copies the source's storage key, and the cross-repository write guard (#2511) exempted only the source and the target. After `dev -> stage`, `dev` still owns the key, so `stage -> prod` was refused with "already owned by another repository". The guard now also lets a promotion through when the repository holding the key recorded the same SHA-256 as the artifact being copied, since rewriting an object with the bytes it holds overwrites nothing. A repository holding other bytes at that key still blocks the promotion.
