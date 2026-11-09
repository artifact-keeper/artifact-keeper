---
section: Fixed
issues: [#5502]
---
- **The generic download route honours `Range` on proxied serves** (#5502). A Remote repository's proxy-cache hit or upstream fetch, and a Virtual repository's serve through its members (Remote members included), answered a ranged GET through `/general/{key}/{path}` or `/{key}/download/{path}` with `200` and every byte, so clients that fetch byte windows and check each against its own digest (apk segment fetches) failed and fell back to the origin. Both arms now cut the client's range from the serve with the helper the Hugging Face `resolve` route uses since #5145, which moves next to `ranged_stream_response`: `206` with `Content-Range`, `416` for an unsatisfiable range, `If-Range` honoured, HEAD unchanged. `Range` is still never forwarded upstream, so a cold serve keeps filling the cache with the whole object.
