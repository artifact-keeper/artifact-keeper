---
section: Fixed
issues: [#6063]
---
- **Repository create and update now refuse `versioning_enabled: true` for formats that cannot version artifacts** (#6063). The flag was accepted and echoed back for every format, but uploads only append immutable revisions for Generic and Mlmodel repositories, so a hosted Debian repository could report versioning as enabled and still answer `409 Package already exists` on a re-upload. `POST` and `PATCH /api/v1/repositories` now answer `400 VALIDATION_ERROR` for an opt-in on any other format, and config-as-code imports inherit the refusal because they apply through those same handlers. Omitting the flag or setting it to `false` remains valid for every format, and existing repositories that already hold `true` on an unsupported format are left untouched until they are changed. Clients that send the flag unconditionally across formats must stop sending `true` for the unsupported ones.
