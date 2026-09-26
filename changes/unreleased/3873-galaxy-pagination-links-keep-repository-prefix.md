---
section: Fixed
issues: [#3873]
---
- **Ansible Galaxy pagination links now stay inside the repository URL the client configured** (#3873). When `ansible-galaxy` was pointed at a Galaxy repository's generic download URL (`/api/v1/repositories/{key}/download/`), a Remote repository streamed the upstream's JSON verbatim, so `links.next` was the upstream's root-relative `/api/v3/plugin/...` path and following it left the repository (401/404). Galaxy API reads on that URL, and the collection tarballs they advertise, are now answered by the Galaxy handler itself. Every link a client follows (`href`, `versions_url`, `download_url` and the `first`/`previous`/`next`/`last` paging links) is built from the path the client requested, so it stays under whichever of `/ansible/{key}/` or the generic download URL the client was configured with. Requests without paging parameters still receive the complete list as a single page.

  Behaviour change: the collection and version lists on the `/ansible/{key}/` route now honour `limit`/`offset` as well. `ansible-galaxy` sends `?limit=100`, so a collection with more versions is now served in pages with a `next` link, where it previously came back as one unpaged list.
