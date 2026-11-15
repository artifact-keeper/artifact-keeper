---
section: Fixed
issues: [#5912]
---
- **The quota pre-check now checks write permission first, so a caller who cannot write a repository gets the permission refusal, not the quota refusal** (#5912). The check that refuses an over-quota upload on its `Content-Length` before the body is read ran ahead of the write authorization on the repository artifact API and on OCI `/v2`. A caller without write permission on a public repository who declared an over-quota upload was answered `403 QUOTA_EXCEEDED` with the repository's `limit_bytes`, `used_bytes`, `scope`, `repository` and `project`, instead of the refusal it got before. The pre-check now answers a quota refusal only to a caller who passes the repository's write gate. Anyone else gets the answer from before the pre-check existed: `401` for an anonymous caller and `403 FORBIDDEN` (`DENIED` on `/v2`) for a signed-in caller who may not write. A caller who may write is still refused before the body is read.
