---
section: Security
issues: [#5458]
---
- **A refused write no longer tells an existing private repository from an unknown key, on any format** ([#5458]). Before this fix, an authenticated caller who could not read a private repository got `403` (or a wrong-type `400`) for an existing key but `404` for a key that names no repository. Such callers include an owner of a different repository and a token scoped to other repositories. Any of them could enumerate private repository keys by attempting writes. These refusals now return exactly what an unknown key returns:
  - native format routes (`/pypi/`, `/npm/`, `/maven/`, ..., and the MCP registry, which renders it as its unknown-name problem+json): `404 Repository not found`. This covers publishes, uploads, deletes, MCP status changes and introspection probes.
  - REST under `/api/v1/repositories/{key}`: `404 Repository not found`. This covers:
    - every route behind the shared write gate: generic uploads and deletes, chunked upload sessions, labels, security settings, cache TTL, upstream credentials, egress proxy and upstream filters;
    - `PATCH` and `DELETE` of the repository;
    - environment ingest and delete;
    - `GET .../npm-scope-policy`;
    - the Remote-only routes and the virtual member routes, where the wrong-type `400` is hidden too;
    - the virtual conda allowlist;
    - the Remote MCP management routes (sync, seed, pin and approval decisions).

    `POST /api/v1/curation/repos/{key}/sync` answers the same way.
  - OCI `/v2` pushes and deletes: `404 NAME_UNKNOWN`. The `/v2` format check now runs after the write gate. Docker-mirror mode (`AK_DEFAULT_DOCKER_MIRROR_REPO`) no longer re-resolves a push to an unknown key to the mirror; a pull-through mirror never accepts a push.

  The decision is made before any repository-specific check runs, and nothing is written. A caller who can read the repository but may not write it still gets `403`. So does any caller on a `public` repository, and any authenticated caller on an `internal` one, except a token scoped elsewhere.

  **Behaviour change.** A CI token scoped to the wrong repository, or a user without a grant, now sees "not found" instead of "forbidden" when writing to a private repository. That includes the MCP registry's unknown-server-name `404` and OCI's `NAME_UNKNOWN`. The same applies to admin-tier configuration reads that run the write or admin gate, such as `GET .../age-gate`, the age-gate review queue, `GET .../npm-scope-policy` and `GET .../egress-proxy`. If a publish starts failing with `404`, check the token's repository scope and the caller's grants before checking the key's spelling. See `docs/repository-visibility.md`.

  **Not covered:** writes by artifact id (`/api/v1/artifacts/{id}`), where the target is an unguessable id rather than a key, and the member key of a virtual-member mutation.
