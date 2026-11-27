---
section: Fixed
issues: [#6465]
---
- **Downloading a file from the repository browser no longer loads it whole into backend memory** (#6465). `GET /api/v1/tree/content` read the entire stored object before answering, and `max_bytes` cut the buffer only after that, so one or two multi-GB downloads could get the backend OOM-killed. A download now streams from storage, and a preview with `max_bytes` reads only that many bytes
