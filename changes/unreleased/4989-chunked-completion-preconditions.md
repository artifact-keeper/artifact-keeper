---
section: Fixed
issues: [#4989]
---
- **Completing a chunked upload honours `If-Match` and `If-None-Match`** ([#4989]). `PUT /api/v1/uploads/{session_id}/complete` ignored both headers, so a client doing a compare-and-swap through the chunked flow got a blind write: `If-Match` on a path no artifact held committed anyway, `If-None-Match: *` on an occupied path answered the immutability `409`, and a matching `If-Match` could not replace the artifact it named. The completion now applies the same rule as the whole-body `PUT` of a generic repository: a precondition that does not hold is `412 PRECONDITION_FAILED` (a malformed header `400`), checked before the chunks are assembled and again with the artifact row locked when it commits, so of two conditional completions against one ETag exactly one wins. A refused completion writes nothing and leaves the session open for a retry, and a matched `If-Match` replaces the live artifact. See `docs/generic-conditional-writes.md`.
