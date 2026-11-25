---
section: Fixed
issues: [#6404]
---
- **A full search reindex no longer starts while another one runs** (#6404). `POST /api/v1/admin/search/reindex` and `POST /api/v1/admin/reindex` started a new full reindex on every call, so a double click or a retrying script stacked runs that multiplied the database and search load and raced each other's index refresh setting. Both endpoints and the startup reindex now share one cluster-wide lease, and a call while a reindex runs on any replica answers `409 Conflict`. A call after it finishes starts a new one
