# Lifecycle policy assignments

Lifecycle policies use explicit repository scope:

| `applies_to_all` | `repository_ids` | Effect |
| --- | --- | --- |
| `false` | `[]` | Unassigned: no artifact deletion, OCI cleanup, or run bookkeeping |
| `false` | Repository UUIDs | Only those repositories |
| `true` | `[]` | All current and future repositories |

Global scope with a nonempty assignment list is rejected with HTTP 422.
All six policy types support these scopes. Version retention groups and storage
quotas are evaluated independently in each repository. Existing `config.exclude`
protection remains per policy; it does not protect artifacts from other policies.

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
