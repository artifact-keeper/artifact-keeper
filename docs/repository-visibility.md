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

### Write refusals to callers who cannot read

A write or delete refused to an authenticated caller who cannot read the
repository answers exactly what a key naming no repository answers, on every
surface (#5458). Examples of such callers are an owner of some other
repository and a token scoped to other repositories. The answers are:

- native package-manager routes (`/pypi/...`, `/npm/...`, `/maven/...`, the
  MCP registry, ...): `404 Repository not found`, the same status, headers and
  body as an unknown key;
- the REST API under `/api/v1/repositories/{key}`: `404`
  `{"code": "NOT_FOUND", "message": "Repository not found"}`, as for an unknown
  key. This covers every route behind the shared write gate
  (`require_repo_write_access`: artifact uploads and deletes, chunked upload
  sessions, labels, security and scan settings, cache TTL, upstream
  credentials, egress proxy, upstream filters). It also covers `PATCH` and
  `DELETE` of the repository itself, environment ingest and delete,
  `GET .../npm-scope-policy`, the Remote-only routes (`upstream-auth`,
  `egress-proxy`, `test-upstream`, and `GET`/`PUT`/`DELETE .../proxy-cache-cap`
  (#5610), which also hide the wrong-type `400` and the token-scope and admin
  `403`), the virtual member routes (`GET`/`PUT`/`POST .../members` (the `GET`
  since #5612), `DELETE .../members/{member}`, which also hide the wrong-type
  `400` and, for the `GET`, the token-scope `403`), the conda allowlist of a virtual
  conda repository, `POST /api/v1/curation/repos/{key}/sync`, and the Remote MCP
  management routes;
- OCI (`/v2/<name>/...` push and delete): `404 NAME_UNKNOWN`, echoing the
  requested key exactly as a miss does. The `/v2` format check runs after the
  write gate, so a push to a non-OCI key the caller cannot read is not told
  the key's format. Docker-mirror mode (`AK_DEFAULT_DOCKER_MIRROR_REPO`) does
  not apply to writes: a push to a key naming no repository is `404
  NAME_UNKNOWN`, never the mirror's answer, because a pull-through mirror
  never accepts a push.

Before this, such a write answered `403` for an existing private repository
(or an `internal` one, for a token scoped elsewhere) and `404` for an unknown
key, so trying to write
enumerated private repository keys. The refusal is decided before anything
repository-specific runs, and nothing is written.

A caller who **can** read the repository but may not write it still gets
`403`: it already knows the repository exists. So does every caller on a
`public` repository, and every authenticated caller on an `internal` one,
except a token scoped elsewhere, which cannot read it either.

**Troubleshooting.** A CI job whose token is scoped to the wrong repository,
or a user who lost their grant, now sees "not found" (`404 Repository not
found`, `NAME_UNKNOWN`, or on the MCP registry the unknown-server-name `404`)
when publishing to a private repository, not "forbidden". Check the token's
repository scope and the caller's grants before checking the key's spelling.

Changing a repository's visibility is propagated to every serving instance
immediately: the change fires the repository-changed `NOTIFY` trigger, which
evicts the cached repository record. Without that, a repository narrowed from
`internal` to `private` would keep being served under the old decision until the
60-second cache TTL expired — a stale-*authorization* window, not merely a
stale-metadata one.

## Reading through a virtual repository

A virtual repository has no access of its own to hand out. Its members are
separate repositories with their own grants, and every member is checked
against the caller exactly as a direct read of that member would be. **To read
through a virtual, the principal needs read on each member it should see; a
grant on the virtual alone yields an empty channel.** The grant on the virtual
is still required: it is what lets the caller reach the virtual's URL at all.

For example, to let the members of group `developers` resolve through a Maven
virtual `maven-all` whose members are `maven-internal` (local) and
`maven-central` (remote), grant the group `read` on all three:

```bash
for repo in maven-all maven-internal maven-central; do
  REPO_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$AK/api/v1/repositories/$repo" | jq -r .id)
  curl -s -X POST "$AK/api/v1/permissions" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"principal_type\":\"group\",\"principal_id\":\"$GROUP_ID\",
         \"target_type\":\"repository\",\"target_id\":\"$REPO_ID\",
         \"actions\":[\"read\"]}"
done
```

With `read` on `maven-all` only, `/maven/maven-all/...` answers 404 for every
artifact, and the server logs `virtual member walk narrowed by caller
authorization` with `members_accessible=0`. Granting a subset of the members
is how a virtual is narrowed per audience: each caller sees the members it can
read, in the virtual's priority order. Putting the virtual and its members in
one project and granting the group on the project covers all of them with one
rule.

Since 1.11.2, when a caller holding read on a virtual can read none of its
members, `GET /api/v1/repositories/{key}/members` and
`GET /api/v1/repositories/{key}/artifacts` add an `X-AK-Virtual-Members-Notice`
header saying so (#4690). The header is decided only by "no member is readable
by this caller", so a virtual with no members at all answers the same and the
header does not reveal whether private members exist. The format endpoints
(`/maven/<virtual>/...` and the like) still answer a plain 404.

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

## Public Remotes with upstream credentials

A public Remote serves anonymous callers, and every upstream request it makes
for them carries the repository's upstream credentials: upstream-auth (basic,
bearer, AWS) or userinfo embedded in `upstream_url`. An anonymous caller then
reads whatever those credentials can read upstream (#4662).

Moving a repository into that state is **refused with a 400** whose `code` is
`PUBLIC_REMOTE_UPSTREAM_CREDENTIALS`, on every path that can do it: creating a
public repository with credentials, making a credentialed repository public,
adding userinfo to a public repository's `upstream_url`, and
`PUT /api/v1/repositories/{key}/upstream-auth` on a public repository.

An administrator who means it sends `allow_public_with_upstream_credentials:
true` on the same request. The acceptance is stored with the repository (a later
toggle back to public does not need it again; `false` withdraws it), logged at
`WARN`, and recorded in the audit log as
`allow_public_with_upstream_credentials: true` in the `REPOSITORY_CREATED` /
`REPOSITORY_UPDATED` details.

Repository responses carry `public_with_upstream_credentials` (the state) and
`allow_public_with_upstream_credentials` (whether it was accepted). A repository
that was already public with credentials before the guardrail existed is not
refused on unrelated updates, so a Terraform apply that re-sends
`is_public: true` keeps working, but it reports
`public_with_upstream_credentials: true` with the acceptance `false`.

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
