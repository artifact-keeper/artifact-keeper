# Lifecycle policy assignments

Lifecycle policies use explicit repository scope:

| `applies_to_all` | `repository_ids` | Effect |
| --- | --- | --- |
| `false` | `[]` | Unassigned: no artifact deletion, OCI cleanup, or run bookkeeping |
| `false` | Repository UUIDs | Only those repositories |
| `true` | `[]` | All current and future repositories |

Global scope with a nonempty assignment list is rejected with HTTP 422.
All seven policy types support these scopes. Version retention groups and storage
quotas are evaluated independently in each repository. Existing `config.exclude`
protection remains per policy; it does not protect artifacts from other policies.

## Policy configuration

Every policy type accepts these optional `config` keys:

- `exclude`: `{"versions": [...], "version_patterns": [...]}` names versions
  the policy never deletes. `versions` are exact matches; `version_patterns`
  are regexes (see below).
- `match.path_prefix` limits the policy to artifacts whose repository-relative
  path starts with that literal string.
- `match.version_pattern` limits the policy to artifacts whose version (the tag,
  for container images) matches a regex. It is a **PostgreSQL** regular
  expression, checked by PostgreSQL when the policy is created or updated. It is
  unanchored unless you use `^` / `$`, so `sha-` also matches `release-sha-1`.
  Use `\y`, not `\b`, for a word boundary. A version-less artifact is in scope
  only if the pattern matches the empty string.

Every lifecycle regex -- `match.version_pattern`, each
`exclude.version_patterns` entry, and the `pattern` of `tag_pattern_keep` /
`tag_pattern_delete` -- is a **PostgreSQL** (ARE) regular expression, because
PostgreSQL runs it. Patterns are unanchored unless they use `^` / `$`. When a
policy is created or updated, each pattern is compiled by PostgreSQL (with a
2-second limit, on its own connection) and the request returns 400 if:

- PostgreSQL rejects it, for example `\z`, `\pL`, `(?P<name>...)` or a
  mid-pattern `(?i)`, or it takes too long to compile;
- it uses `\b` or `\B`. In PostgreSQL these mean backspace and backslash, so
  `\bstable\b` would protect nothing. Write `\ystable\y` instead;
- it uses a back-reference (`\1` to `\9`);
- it is longer than 512 bytes, or `exclude.version_patterns` has more than 64
  entries.

Policies stored before these checks are not changed. On every start the backend
logs one WARN per stored policy with a pattern PostgreSQL cannot compile or
that uses `\b` / `\B`. A preview (`POST /api/v1/admin/lifecycle/{id}/preview`)
lists the problems in `errors`, and stops with zero matches when a pattern
cannot compile. A live run refuses (400) a policy whose protective pattern --
an `exclude.version_patterns` entry, or the `pattern` of `tag_pattern_keep` --
has such a problem, because it would delete what it was written to keep. A
`match.version_pattern` or `tag_pattern_delete` pattern with `\b` matches
nothing, so it still runs and deletes nothing. Fix the policy with
`PATCH /api/v1/admin/lifecycle/{id}`.

Scope and exclusions filter before `min_keep` / `max_versions` count their kept
versions, so out-of-scope and excluded versions never take a kept slot.

`composite` deletes artifacts that meet **every** condition in `conditions`:

```json
{
  "conditions": [
    {"type": "max_age_days", "value": 14},
    {"type": "no_downloads_days", "value": 7}
  ],
  "min_keep": 5,
  "match": {"version_pattern": "^sha-[0-9a-f]+$"},
  "exclude": {"versions": ["latest", "stable"]}
}
```

- The condition types are `max_age_days` and `no_downloads_days`. Each one
  matches exactly what the single-condition policy of that name matches.
- Each type may appear only once.
- `min_keep` is a top-level key, as on `max_age_days`. It keeps the newest N
  versions of each package or image whether or not they meet the conditions.
- Day windows are between 1 and 36500.

A composite policy, like a policy with `exclude`, `min_keep` or
`match.version_pattern`, never evicts a Remote repository's proxy cache. Assigning
one to a non-OCI Remote repository returns 422.

## Safe rollout and compatibility

Migration 233 preserves every existing policy: previously global policies remain
global, and previously single-repository policies gain one explicit assignment.
Configuration, exclusions, enabled flags, schedules, and run history are retained.

**New creates are deliberately different:** omitting scope, or sending a null
legacy `repository_id`, creates an unassigned policy. Creating a global policy
now requires `applies_to_all: true`. A non-null legacy `repository_id` still
creates a single assignment, but cannot be combined with `repository_ids`.

The response's deprecated `repository_id` is a singleton projection: one UUID
for exactly one explicit assignment, otherwise null. **Null no longer means
global.** Use `applies_to_all` and `repository_ids`. Repository deletion keeps
the reusable policy and removes only its assignment; the projection updates
transactionally, and the last removal leaves a dormant policy.

**This is not a rolling-backend or binary-downgrade-compatible change.** Stop
old backend instances and lifecycle schedulers before migrating; do not run
old binaries against the new assignment model. Old binaries interpret null as
global and cannot represent dormant or multiple-repository policies. Upgrade all
backend instances before enabling new UI writes. A downgrade requires deliberate
scope reconciliation; simply deploying an older binary is unsafe.

Before scope/assignment writes, clients must positively verify:

```http
GET /api/v1/admin/lifecycle/capabilities
```

```json
{"explicit_repository_assignment": true}
```

This also works with an empty policy collection. A missing, failed, or malformed
capability response must disable new writes, not trigger a legacy fallback:
older backends ignore the new fields and may create a global policy.

## API

All endpoints below are under `/api/v1/admin/lifecycle` and require a global
administrator (401 without authentication, 403 for non-admins). Assigning policies
from repository settings does not grant repository members this privilege.

Create an unassigned policy:

```http
POST /api/v1/admin/lifecycle
Content-Type: application/json
```

```json
{
  "name": "CI retention",
  "policy_type": "max_age_days",
  "config": {"days": 14, "exclude": {"versions": ["stable"]}},
  "applies_to_all": false,
  "repository_ids": []
}
```

Create and update return HTTP 200 with the full policy. `GET /` returns a bare
array of all policies, including unassigned and disabled ones.
`GET /?repository_id={uuid}` returns global and explicitly assigned policies
effective for that repository, including disabled policies. `GET /{id}` returns
the full policy.

`PATCH /{id}` optionally accepts `applies_to_all` and `repository_ids`. Omission
preserves that field; a supplied array replaces assignments atomically, and `[]`
detaches all. Null is not an alternative to omission for either new PATCH field.
The resulting scope must be valid: converting an assigned policy to global uses
`{"applies_to_all":true,"repository_ids":[]}`. Setting `applies_to_all:false` on
a global policy makes it dormant unless assignments are supplied.

For incremental assignment, without replacing other repositories' membership:

| Method and path | Body | Success |
| --- | --- | --- |
| `PUT /{id}/repositories/{repository_id}` | None | 200, full updated policy |
| `DELETE /{id}/repositories/{repository_id}` | None | 200, full updated policy |

Both mutations are idempotent. Missing policies or repositories return 404.
Attempts to attach/detach a global policy return 422: global policies do not
support per-repository opt-outs. Duplicate UUIDs in replacement lists are
deduplicated and response arrays are sorted. Invalid repository IDs abort the
whole operation. Scope edits and incremental mutations are serialized per policy,
with repository locks taken first to avoid racing repository deletion. Repeated
concurrent scope changes can return 409; retry the request against fresh state.

`DELETE /{id}` deletes the policy and its assignment rows, not artifacts. The
repository UI should detach a shared policy rather than delete the policy.

## Execution

`POST /{id}/preview` and `POST /{id}/execute` remain **policy-wide**, not scoped
to the repository page from which a user followed a link. Preview reports
`bytes_matched` without deleting artifacts or tags; `bytes_freed` remains zero.
Live execution uses the same matchers, including exclusions.

Scope is snapshotted for each run. Attach/detach edits affect the next run;
detaching does not cancel an already-running cleanup or its associated OCI
cleanup. Globally opted-in policies resolve the current repositories on each run.

An enabled, unassigned policy can be previewed or manually executed and returns
zero counts/bytes with no writes, including no `last_run_at` update. Disabled
policies can still be previewed but cannot be executed live. Scheduled execution
and execute-all skip unassigned policies. OCI cleanup uses only the same concrete
repositories selected for execution, including recovery of previously stale
soft-deleted references in those repositories.
