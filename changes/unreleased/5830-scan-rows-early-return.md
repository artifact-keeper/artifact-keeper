---
section: Fixed
issues: [#5830]
---
- **A manual scan that stops before its scanners run no longer leaves its scan rows `running` for 30 minutes** ([#5830]). `POST /api/v1/security/scan` with an `artifact_id` returns one `running` row id per scanner and runs the scan in the background. When that scan returned early (the artifact's bytes could not be read from storage, the artifact was deleted after the trigger, or a database call failed before or between scanners), the rows stayed `running` until the stuck-scan janitor failed them with `janitor: scan worker did not complete`, and the real error was only in the server log. Every row the scan did not finish now ends `failed` as soon as the scan returns, with `error_message` set to `scan stopped before the <scanner> scanner finished: <error>`, its inventory `failed`, and the artifact flagged as for any failed scan (`block_on_fail` policies apply). Rows the scan did finish are left as they are.
