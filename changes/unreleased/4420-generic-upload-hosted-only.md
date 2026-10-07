---
section: Security
issues: [#4420]
---
- **Generic, chunked and multipart uploads now refuse remote and virtual repositories** (#4420). The native format routes already rejected writes to a remote (proxy) or virtual repository, but `POST /api/v1/uploads` (chunked sessions), the generic `PUT /api/v1/repositories/{key}/artifacts/{path}` and both multipart `POST` upload routes did not, so a user with write access could plant an artifact in a remote repository that shadowed the upstream it proxies, without it ever being fetched from that upstream (for example a chunked `.deb` into a remote Debian repository got a full catalog row). These paths now answer exactly like the native routes: 405 for a remote repository and 400 for a virtual one, before any session row is opened or any byte is staged. A chunked session staged against such a repository before this change can no longer be completed either: the completion is refused with the same status and the session is failed.
