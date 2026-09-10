# Repository visibility

Every repository carries one visibility state — `public`, `internal` or
`private`. It answers a single question: **who may read this repository before
any grant is consulted.**

Visibility is orthogonal to the grant model (`role_assignments` and
`permissions`). It never confers write, delete or administrative capability, in
any state, and it is persisted with the repository rather than derived from any
server-wide flag.

## The three states

| State | Anonymous caller | Authenticated principal, no grant | Grant holder |
| --- | --- | --- | --- |
| `public` | read | read | read |
| `internal` | refused | read | read |
| `private` | refused | refused | read |

`internal` differs from `private` in exactly one respect: on the **read** path,
the set of principals satisfying the baseline becomes "any resolved principal"
instead of "grant holders". For every other decision — write, delete, admin,
configuration, tenancy pre-gates, anonymous listing — `internal` behaves exactly
as `private`.

Two consequences of that sentence are worth stating outright, because both are
easy to assume the other way round:

- **A repository-scoped API token still confines an `internal` repository.** A
  token whose `allowed_repo_ids` excludes the repository is refused, and the
  refusal is the existence-hiding 404, not a 403. Public repositories are
  exempted from that ceiling (a scoped credential must never be worse off than
  no credential at all), but an anonymous caller gets nothing from an internal
  repository, so there is no credential-free baseline for a scoped credential to
  have fallen below.
- **`internal` never satisfies a write.** Publishing, deleting and reconfiguring
  all route through the repository action check, deny-by-default, exactly as they
  do for a private repository.

An anonymous caller cannot distinguish `internal` from `private`. Both answer the
same status codes on every surface and neither appears in an unauthenticated
listing or search.

## Where it is enforced

The state produces the same read decision on every surface a repository can be
reached through:

- the REST API (`/api/v1/repositories/...`, artifacts, tree, storage);
- native package-manager protocols (PyPI, npm, Maven, Cargo, … );
- the OCI Distribution endpoints (`/v2/*`);
- repository listing;
- search, including the artifact inventory.

A repository the caller may not read never appears in a listing or in search
results for that caller.

Changing a repository's visibility is propagated to every serving instance
immediately: the change fires the repository-changed `NOTIFY` trigger, which
evicts the cached repository record. Without that, a repository narrowed from
`internal` to `private` would keep being served under the old decision until the
60-second cache TTL expired — a stale-*authorization* window, not merely a
stale-metadata one.

## Relationship to guest access

`AK_GUEST_ACCESS_ENABLED` is a server-wide policy, not a per-repository one. When
it is disabled, no anonymous request is served at all, so a `public` repository
is unreachable by the audience that makes it public.

A request to create or update a repository as `public` while guest access is
disabled is therefore **coerced to `internal`**, and the coercion is logged as a
structured warning.

It is coerced to `internal` rather than to `private` deliberately. Coercing to
`private` — which is what earlier versions did — destroyed the operator's stated
intent instead of reinterpreting it: re-enabling guest access left every affected
repository private, with nothing recording that `public` had ever been asked for.
`internal` keeps anonymous access impossible while preserving "broadly readable",
and is reversible by setting the repository back to `public`.

Visibility itself is never changed by toggling the policy. Only requests that
explicitly ask for `public` while guests are disabled are affected.

## API representation

`visibility` is the authoritative field on the create, update and read shapes.

The pre-existing boolean is retained for compatibility:

| Field | Meaning |
| --- | --- |
| `visibility` | `"public"` \| `"internal"` \| `"private"` — authoritative |
| `is_public` | deprecated; exactly `visibility == "public"` |
| `allow_anonymous_access` | alias of `is_public` |

A client that speaks only the boolean — an older SDK, the out-of-tree Terraform
provider — keeps working unchanged and reads an `internal` repository as
`is_public: false`. That is correct: an internal repository is not anonymously
readable. It is simply indistinguishable from `private` to such a client, which
cannot express the state either way.

Two rules govern how the fields combine:

- **Contradictory input is refused.** `visibility: "private"` together with
  `is_public: true` returns 400 rather than silently resolving to one of them.
  `visibility: "internal"` with `is_public: false` is *consistent* — internal is
  not public — and is accepted.
- **Clearing the boolean means only "not public".** An update carrying
  `is_public: false` narrows a `public` repository to `private` and leaves an
  `internal` or `private` one alone. It is not read as "set to private", because
  a client that can only speak the boolean sends `false` for an internal
  repository too, on every request — treating that as `private` would narrow
  every internal repository such a client manages, silently, on each apply, and
  the drift would be invisible to the client, whose next read still shows
  `false`.

## Security reporting

Blast-radius reports classify a repository's reachability as `public`,
`internal`, `restricted_acl` or `restricted_roles`. `internal` is reported as its
own scope rather than folded into the restricted states: an operator triaging a
CVE needs to know that a vulnerable artifact was reachable by the whole instance,
not by a handful of grantees. The accessible-users endpoint likewise reports
`exposure: everyone` for an internal repository instead of enumerating the entire
user table.

## Upgrading

Migration 217 introduces the column and backfills it from the previous boolean:
`is_public = true` becomes `public`, `false` becomes `private`. No repository
becomes `internal` automatically, and no repository's audience changes.

Repositories that were *meant* to be internal but had already been coerced to
`is_public = false` by the older guest-access behaviour cannot be recovered from
the data — they are indistinguishable from ordinary private repositories. See the
upgrade note in [`CHANGELOG.md`](../CHANGELOG.md) for the review query.
