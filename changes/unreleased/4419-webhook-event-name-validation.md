---
section: Changed
issues: [#4419]
---
- **Creating a webhook now rejects event names that can never fire** (#4419). `POST /api/v1/webhooks` stored any string in `events`, so a plausible spelling such as `artifact.uploaded` (the internal event-bus name) was accepted while deliveries are matched on `artifact_uploaded`, and the webhook silently never fired. Every entry is now checked against the subscribable set (`artifact_uploaded`, `artifact_deleted`, `repository_created`, `repository_deleted`, `user_created`, `user_deleted`, `build_started`, `build_completed`, `build_failed`, `age_gate_queued`, `age_gate_approved`, `age_gate_rejected`, `age_gate_reopened`); an unknown name returns 400 naming the offending entries and listing the accepted ones. Webhooks already stored with an unknown name are left as they are and still never fire; recreate them with the accepted spelling.
