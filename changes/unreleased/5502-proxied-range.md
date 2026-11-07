---
section: Fixed
issues: [#5502]
---
- **The generic download route honours `Range` on a Remote repository's proxied serves** (#5502). A proxy-cache hit or upstream fetch through `/general/{key}/{path}` answered a ranged GET with `200` and every byte, so clients that fetch byte windows and check each against its own digest (apk segment fetches) failed and fell back to the origin. The Remote arm now cuts the client's range from the proxied serve with the same helper the Hugging Face `resolve` route uses since #5145: `206` with `Content-Range`, `416` for an unsatisfiable range, `If-Range` honoured, HEAD unchanged. `Range` is still never forwarded upstream, so a cold serve keeps filling the cache with the whole object.
