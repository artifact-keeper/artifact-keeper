---
section: Fixed
issues: [#6299, #5656]
---
- **The error that stops the backend is now a log line, JSON under `LOG_FORMAT=json`, and an unknown `/api/v1` path answers `Not found` instead of `Repository not found`** (#6299, #5656). A startup failure such as an unreachable database printed a plain `Error: ...` to stderr that bypassed the subscriber, so a JSON log pipeline could not parse the one line that says why the pod is crash-looping. It now goes through `tracing` at ERROR as `fatal error, exiting` with the error in `error`. Unknown `/api/v1` paths fell through to the package routes, whose repository lookup answered `404 Repository not found`; they now get the API's own JSON `404 NOT_FOUND`. The logging guide also says the chart sets `LOG_FORMAT` and `LOG_ANSI` as values, and the API token guide notes that Basic auth with a password costs a bcrypt per request
