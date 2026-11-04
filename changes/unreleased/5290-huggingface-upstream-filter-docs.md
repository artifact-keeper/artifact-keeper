---
section: Added
issues: [#5290, #840]
---
- **The Hugging Face guide now explains how to restrict which models a Remote can fetch, and a new page documents upstream filters in general** (#5290, #840). A Hugging Face Remote requests model info as `api/models/<org>/<name>...` and files as `<org>/<name>/resolve/...`, so a filter written for one shape (`^acme/`, or `^api/models/acme/`) silently breaks `snapshot_download` and `hf download` on their first call. `docs/huggingface.md` gives a pattern that matches both shapes, `^(api/models/)?(org-a|org-b)/[^/]+(/|$)`, and explains anchoring, look-alike organisations, case and how to check the result. `docs/upstream-filter.md` covers the subject rules for every format, the npm and Hugging Face two-shape cases, and how already-cached content behaves. Unit tests read the documented patterns out of both pages and check them against the paths the Hugging Face handler sends upstream.
