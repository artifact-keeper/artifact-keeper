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
  refusal is the existence-hiding 404, not a 403. (The one exception is a read
  routed through a virtual repository the token's scope names; see
  [Tokens scoped to a virtual repository](#tokens-scoped-to-a-virtual-repository).)
  Public repositories are
  exempted from that ceiling (a scoped credential must never be worse off than
  no credential at all), but an anonymous caller gets nothing from an internal
  repository, so there is no credential-free baseline for a scoped credential to
  have fallen below.
- **`internal` never satisfies a write.** Publishing, deleting and reconfiguring
  all route through the repository action check, deny-by-default, exactly as they
  do for a private repository.

**"Any resolved principal" is wider than "every employee with a login".** It is
every identity the instance authenticates, including:

- **CI workloads signing in through OIDC** (`/api/v1/auth/ci`) whose trust
  mapping sets no repository list. Such a workload is unrestricted by repository,
  so it reads every `internal` repository. A mapping that does set a repository
  list confines the workload exactly as a repository-scoped token does.
- **SSO users provisioned just-in-time** on their first OIDC, SAML or LDAP login
  when the provider's "Auto Create Users" switch is on.
  An identity provider that admits anyone in a large directory, or a broad
  trust policy on a CI issuer, makes `internal` effectively public to that
  population.

Before marking a repository `internal`, check who your identity providers and CI
trust mappings admit. Use `private` plus a group grant when the audience should
be narrower than that.

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

## Tokens scoped to a virtual repository

A token whose repository scope names a virtual repository (a repository token
minted on it, or a user token whose `repo_selector` matches it) reads the
virtual's members through the virtual, even though its scope does not name the
members. This is what lets a consumer use one per-repository, read-only token
on the one URL it is told to use, for example a virtual conda channel.

Three limits apply:

- **Only through the virtual.** The members are readable on requests routed
  through the virtual (`/<format>/<virtual>/...`, the virtual's REST listings and
  downloads, and the `/t/<token>/` forms of those). A request to a member's own
  URL is still refused with the existence-hiding 404, so a virtual's policies
  (such as a conda package allowlist) cannot be bypassed by going to the member
  directly.
- **Only what the token's owner may read.** Each member is still checked
  against the owner's grants, as a direct read by the owner would be. A member
  the owner cannot read is left out of the virtual's listings and indexes and
  cannot be downloaded through it.
- **Reads only.** Publishing through a virtual still requires the token's scope
  to name the hosted member it deploys to.

Members of a nested virtual are reached the same way: they are resolved from
the virtual the request names, and each is checked against the owner's grants.

## Relationship to guest access

Guest access is a server-wide policy, not a per-repository one. An administrator
switches it at runtime with `PATCH /api/v1/admin/settings/system`
(`{"guest_access_enabled": false}`, #867); `AK_GUEST_ACCESS_ENABLED`, when set
explicitly to `true`/`1`/`false`/`0`, pins it and wins over that setting. When
it is disabled, no anonymous request is served at all, so a `public` repository
is unreachable by the audience that makes it public.

A request to create or update a repository as `public` while guest access is
disabled is therefore **refused with a 400** (#3855) that names both switches
(the admin setting and `AK_GUEST_ACCESS_ENABLED=false`). Earlier versions silently coerced such a request
to `private`, which a Terraform provider read back as drift on every plan.

`internal` is never refused: it does not ask for anonymous access, so it passes
the guest-access check untouched. The request is not rewritten to `internal`
either. The callers that send `public` on such an instance are mostly the ones
speaking only the deprecated boolean (the Terraform provider, older SDKs), which
can neither ask for `internal` nor decline it, so rewriting them to it would
quietly make their repositories org-readable on exactly the instances that
disabled guest access to prevent that. An operator who wants `internal` asks for
it.

Visibility itself is never changed by toggling the policy.

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

Migration 245 introduces the column and backfills it from the previous boolean:
`is_public = true` becomes `public`, `false` becomes `private`. No repository
becomes `internal` automatically, and no repository's audience changes.

Repositories that were *meant* to be internal but were coerced to
`is_public = false` by the pre-#3855 guest-access coercion cannot be recovered
from the data: they are indistinguishable from ordinary private repositories. See
the upgrade note in the release's `CHANGELOG.md` entry for the review query.

During a rolling deploy, pods still running the previous release do not know
`internal`: they read the repository's `is_public = false` mirror and serve it
as `private`, so an authenticated caller without a grant gets a 404 from those
pods until they are replaced. This is narrower than the new behaviour, never
wider, so it is safe; it is only visible as inconsistent answers while the
rollout is in progress.

Change a repository's visibility through the API rather than with a raw SQL
`UPDATE`. Both propagate to every serving instance (the database trigger emits
the cache-invalidation event either way), but only the API records the change in
the audit log.
