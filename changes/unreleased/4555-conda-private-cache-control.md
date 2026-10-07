---
section: Security
issues: [#4555]
---
- **Conda channel responses to authenticated requests are marked `Cache-Control: private` instead of `public`** (#4555). `repodata.json`, `channeldata.json`, the shards and the other channel documents were sent with `public, max-age=60` even when the request carried credentials, so a shared cache in front of the registry could store a private channel's index, or a virtual channel's index as merged for one caller's member access, and serve it to the next requester of the same URL. Any conda response to a request with an `Authorization` header or a session cookie now has the `public` directive replaced by `private`; anonymous responses to public channels are unchanged, and the token-in-URL routes keep `private, no-store`.
