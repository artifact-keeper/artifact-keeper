---
section: Fixed
issues: [#3873]
---
- **Ansible Galaxy pagination links now stay inside the repository URL the client configured** (#3873). When `ansible-galaxy` was pointed at a Galaxy repository's generic download URL (`/api/v1/repositories/{key}/download/`), a Remote repository streamed the upstream's JSON verbatim, so `links.next` was the upstream's root-relative `/api/v3/plugin/...` path and following it left the repository (401/404). Galaxy API reads on that URL are now answered by the Galaxy handler itself, and the collection and version lists honour `limit`/`offset` with `first`/`previous`/`next`/`last` links built from the path the client requested — under either `/ansible/{key}/` or the generic download URL. Requests without paging parameters still receive the complete list as a single page.
