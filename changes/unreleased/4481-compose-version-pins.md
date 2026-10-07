---
section: Fixed
issues: [#4481, #2708]
---
- **`ARTIFACT_KEEPER_VERSION` now pins the openscap image too, and the web image has its own `ARTIFACT_KEEPER_WEB_VERSION` pin** (#4481, #2708). The stock `docker-compose.yml` documented `ARTIFACT_KEEPER_VERSION` as the way to pin a release, but only the backend honoured it: `artifact-keeper-openscap`, which every backend release publishes with the same tag, and `artifact-keeper-web` were hardcoded to `:latest`, so a "pinned" stack still pulled whatever `latest` was for two of its images. openscap now uses `${ARTIFACT_KEEPER_VERSION:-latest}`. Because web releases are decoupled from backend releases (#2708), web gets a separate `ARTIFACT_KEEPER_WEB_VERSION` (default `latest`). Both are documented in `.env.example`.
