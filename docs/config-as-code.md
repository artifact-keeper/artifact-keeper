# Config as code: export, plan and apply instance configuration

Standing up a second Artifact Keeper with the setup of the first (a
disconnected site, a staging copy, a rebuild after loss) used to mean replaying
dozens of per-setting API calls. Since #5292 an administrator can read the
configuration of every repository as one versioned JSON document, review it,
diff it against another instance and apply it there.

This first version covers **repositories and their per-repository settings**.
The rest of the instance configuration is listed under [Not covered
yet](#not-covered-yet).

## Export

```bash
# Every repository.
curl -H "Authorization: Bearer $TOKEN" \
  https://registry.example.com/api/v1/admin/config/export > ak-config.json

# Only some repositories.
curl -H "Authorization: Bearer $TOKEN" \
  "https://registry.example.com/api/v1/admin/config/export?repositories=npm-remote,npm"
```

Both routes are instance-admin only (`admin_middleware`, like every
`/api/v1/admin` route). An unknown key in `repositories=` answers 404.

The export reads each setting through the handler behind its own GET route
(`GET /api/v1/repositories/{key}`, `/upstream-mode`, `/cache-ttl`,
`/on-upstream-not-found`, `/stale-if-error-grace`, `/upstream-filter`,
`/routing-rules`, `/egress-proxy`, `/npm-scope-policy`, `/members`), so it
reports exactly what those routes report.

## Document shape

```json
{
  "schema_version": 1,
  "exported_at": "2026-11-04T12:00:00Z",
  "producer": "artifact-keeper 1.13.0",
  "repositories": [
    {
      "key": "npm-remote",
      "name": "npm remote",
      "format": "npm",
      "repo_type": "remote",
      "visibility": "internal",
      "upstream_url": "https://registry.npmjs.org/",
      "promotion_only": false,
      "versioning_enabled": false,
      "curation_enabled": false,
      "curation_default_action": "allow",
      "upstream_mode": "cache_only",
      "cache_ttl_seconds": 600,
      "on_upstream_not_found": "keep",
      "stale_if_error_grace_seconds": 7200,
      "upstream_filter": { "include_patterns": ["^@acme(/|%2F)"], "exclude_patterns": [] },
      "egress_proxy": {
        "mode": "explicit",
        "proxy_url": "http://proxy.corp:3128/",
        "proxy_credentials": { "secret_ref": "egress_proxy/npm-remote" },
        "no_proxy": "internal.example"
      },
      "upstream_auth": {
        "auth_type": "basic",
        "username": "svc-npm",
        "password": { "secret_ref": "upstream_auth/npm-remote" }
      },
      "npm_scope_policy": { "allowed_scopes": ["@acme"], "allow_unscoped": false }
    },
    {
      "key": "npm",
      "name": "npm",
      "format": "npm",
      "repo_type": "virtual",
      "visibility": "internal",
      "members": [{ "key": "npm-local", "priority": 1 }, { "key": "npm-remote", "priority": 2 }]
    }
  ]
}
```

- Objects are keyed by repository `key`, never by database id, so documents
  from two instances diff cleanly.
- Order is stable: repositories by `key`, virtual members by `priority` then
  `key`, fields in a fixed order. Two exports of an unchanged instance differ
  only in `exported_at` and `producer`.
- Fields at their default are omitted: `upstream_mode` absent means `online`,
  `egress_proxy` absent means `inherit`, `upstream_filter` absent means no
  filter, `npm_scope_policy` absent means no restriction,
  `stale_if_error_grace_seconds` absent means the instance default, an empty
  `routing_rules` or `members` list is omitted.
- `upstream_mode` is the mode stored for the Remote (`upstream_mode` of
  `GET .../upstream-mode`), not the effective one: the instance-wide
  `PROXY_UPSTREAM_MODE=cache_only` environment variable belongs to the
  instance and is not exported.
- Remote-only settings appear only on `remote` repositories; `members` only on
  `virtual` ones.
- `storage_backend` is not exported: it is chosen by the target instance.
- Unknown fields are refused on import, so a typo cannot be silently ignored.

A JSON Schema for the document is in
[`schemas/config-document.v1.json`](schemas/config-document.v1.json). The
OpenAPI spec carries the same shape as `ConfigDocument`.

## Secrets

No credential is ever exported. Each one is replaced by a placeholder:

| Placeholder | Stands for | Value to supply |
| --- | --- | --- |
| `{"secret_ref": "upstream_auth/<key>"}` | the basic-auth password or bearer token | the password or token |
| `{"secret_ref": "upstream_url/<key>"}` (`upstream_url_credentials`) | `user:password@` embedded in the upstream URL | percent-encoded `user:password` |
| `{"secret_ref": "egress_proxy/<key>"}` (`proxy_credentials`) | `user:password@` embedded in the egress proxy URL | percent-encoded `user:password` |

The upstream-auth `username` and the AWS provider settings (`region`,
`registry_id`, `domain`, ...) are not secret and are exported as is.

An import is given the values in a `secrets` map next to the document. A
secret is needed only when the setting that carries it has to be written:
for a repository being created, or when that setting differs on the target.
When the target already holds the same setting (same auth type and username,
say), the placeholder compares equal and no secret is needed. Consequently an
import does not rotate a credential the target already has; use the
per-repository route for that.

## Plan and apply

```bash
# What would change? Writes nothing.
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data @import.json \
  "https://registry.example.com/api/v1/admin/config/import?mode=plan"

# Apply it.
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data @import.json \
  "https://registry.example.com/api/v1/admin/config/import?mode=apply"
```

`import.json` is `{"document": <the export>, "secrets": {"upstream_auth/npm-remote": "..."}}`.
A bare document (no `document` key) is accepted too, with no secrets.

Both modes answer the plan:

```json
{
  "create": ["npm-remote"],
  "update": [{ "key": "npm", "changes": ["members"] }],
  "unchanged": ["maven-local"],
  "not_in_document": ["scratch"],
  "missing_secrets": [],
  "errors": [],
  "applicable": true,
  "applied": false
}
```

- `create`: in the document, not on the target.
- `update`: differs; `changes` names the top-level fields that differ.
- `unchanged`: already as described.
- `not_in_document`: on the target but not in the document. Never deleted.
- `missing_secrets`: placeholders that must be written but have no value in
  `secrets`.
- `errors`: changes an import cannot make: changing `format`, `format_key` or
  `repo_type` of an existing repository, removing a
  `stale_if_error_grace_seconds` override (the API has no route that clears
  it), a virtual member that exists neither in the document nor on the target,
  or a key listed twice.
- `applicable`: `false` when either list above is non-empty. `mode=apply`
  then answers 400 naming them and writes nothing.

`mode=apply` creates missing repositories and writes changed settings through
the same handlers the per-setting PUT/PATCH routes use, so validation, SSRF
checks, cache invalidation and the normal per-repository audit rows
(`REPOSITORY_CREATED`, `REPOSITORY_UPDATED`) all apply. It works in dependency
order: non-virtual repositories first, then virtual ones, then virtual
memberships. It is idempotent: applying the same document again writes
nothing, and a plan against an up-to-date instance reports every repository
as `unchanged`. It also writes one `CONFIG_IMPORTED` audit row summarising the
run ([audit events](audit-events.md)).

Apply is not one database transaction: each setting is written by its own
route. If a write fails part way, the response is that error, the
`CONFIG_IMPORTED` row records `completed: false` and what had been written,
and re-running the import converges.

`prune=true` (delete what the document does not mention) answers 400; only
`prune=false` is accepted in this version.

`schema_version` other than `1` is refused with 400 before the rest of the
document is read. A future server that writes a newer version will keep
reading version 1 documents.

## Not covered yet

- Scan policies and per-repository scan configuration
- Curation rules
- Age-gate policy
- Lifecycle policies, quality gates and promotion rules
- Sync policies
- Permissions, groups and roles
- `prune=true`
- `ak config export|plan|apply` in artifact-keeper-cli
- Remaining per-repository settings: npm name patterns and Virtual isolate
  mode, OCI trusted bearer realms, Debian/APT settings, quarantine settings,
  conda allowlists, PyPI tracks, proxy cache cap, project assignment

Users, tokens, artifact content and audit history are out of scope by design.
