# CI OIDC: keyless authentication for pipelines

A CI job can authenticate to Artifact Keeper with the OIDC ID token its CI
platform already issues (GitLab CI `id_tokens`, GitHub Actions
`id-token: write`, or any OIDC issuer) instead of a stored API token. The job
sends that token to `POST /api/v1/auth/ci/token` and receives a short-lived
Artifact Keeper access token for a **service account**.

This page covers what an operator sets up, which account a pipeline becomes,
how to give that account access, and what the pipeline side looks like.

## The model: one mapping, one principal

Two objects are configured, both through the admin API:

- A **provider** is a trusted issuer: its `issuer_url` must equal the token's
  `iss`, and its `audience` must appear in the token's `aud`.
- An **identity mapping** belongs to a provider and says *which* tokens from
  that issuer are accepted: its `claim_filters` must all match the token's
  claims. Mappings are evaluated in ascending `priority` order and the first
  enabled one that matches wins.

**Each mapping has exactly one service account**, and every token exchange the
mapping matches authenticates as that account. It does not matter which
branch, tag, job, pipeline or project presented the token. Two branches of one
project, a tag pipeline after a branch pipeline, and two projects admitted by
the same mapping all become the same principal.

The account is created **together with the mapping**. The create response,
and every later read of the mapping, carries its identity:

```json
{
  "id": "7c0f3b2e-…",
  "name": "app-deploy",
  "service_account_id": "4f9d8e1a-…",
  "service_account_username": "ci-7c0f3b2e91d4"
}
```

You can therefore grant the account access before any pipeline has run. You
never need to read `ci-…` out of a job log.

The token's `sub` and project claims do not decide which account is used.
They appear in the account's display name and in the exchange's `security`
log line, so an audit record can still name the project and ref that
presented the token.

## Setting up

All admin endpoints require an admin token.

### 1. Register the provider

```bash
curl -sS -X POST "$AK/api/v1/admin/ci-oidc" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "gitlab",
        "provider_type": "gitlab",
        "issuer_url": "https://gitlab.example.com",
        "audience": "https://artifacts.example.com"
      }'
```

`issuer_url` must use HTTPS and match the token's `iss` exactly. A trailing
slash does not matter. `provider_type` (`gitlab`, `github` or `generic`)
only affects how the account's display name is built.

### 2. Create a mapping

```bash
curl -sS -X POST "$AK/api/v1/admin/ci-oidc/$PROVIDER_ID/mappings" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "app-deploy",
        "claim_filters": { "project_id": "4242" },
        "allowed_repo_ids": null
      }'
```

- `claim_filters` is an object of claim name to required value. A string must
  match exactly. An array matches any of its values. All keys must match. An
  empty object `{}` matches every token from the issuer, so do not use it
  outside a single-tenant issuer.
- Prefer immutable claims. In GitLab, `project_id` survives a project rename or
  transfer and `project_path` does not. If a path is freed and reused by another
  project, a `project_path` filter admits that new project.
- `allowed_repo_ids` narrows every token minted through the mapping to the
  listed repositories: `null` means no restriction, `[]` denies all.
- The response contains `service_account_id` and `service_account_username`.

If the account name the mapping derives is already taken, the create is
refused with `409 Conflict` naming the account, and nothing is written. Retry
the create; a new mapping id derives a new name.

### 3. Grant the service account access

A mapping authenticates a pipeline. It does not authorize it: a new service
account has no repository access until you grant some. Grant access through a
**group**, using the `service_account_id` from the mapping response:

```bash
# Create a group and add the service account to it
curl -sS -X POST "$AK/api/v1/groups" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "ci-app-deploy"}'

curl -sS -X POST "$AK/api/v1/groups/$GROUP_ID/members" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"user_ids\": [\"$SERVICE_ACCOUNT_ID\"]}"

# Give the group write access to a repository
curl -sS -X POST "$AK/api/v1/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"principal_type\": \"group\", \"principal_id\": \"$GROUP_ID\",
       \"target_type\": \"repository\", \"target_id\": \"$REPO_ID\",
       \"actions\": [\"read\", \"write\"]}"
```

Use group memberships and permissions, not roles assigned directly to the
account. A CI account's roles are re-derived on every exchange, the same way
as for other federated accounts, so directly assigned roles are overwritten.

Because the account exists from the moment the mapping does, Terraform or any
other configuration tool can create the mapping and the grant in a single
apply by referencing the mapping's `service_account_id`.

## The pipeline side (GitLab)

```yaml
publish:
  image: alpine:3.20
  id_tokens:
    AK_ID_TOKEN:
      aud: https://artifacts.example.com   # the provider's `audience`
  script:
    - apk add --no-cache curl jq
    - |
      RESPONSE=$(curl -sSf -X POST "https://artifacts.example.com/api/v1/auth/ci/token" \
        -H "Authorization: Bearer ${AK_ID_TOKEN}")
      AK_TOKEN=$(echo "$RESPONSE" | jq -r .access_token)
      AK_USER=$(echo "$RESPONSE" | jq -r .username)
    - echo "$AK_TOKEN" | docker login artifacts.example.com -u "$AK_USER" --password-stdin
```

- The ID token goes in the `Authorization` header, never in the body, so it
  stays out of access logs.
- No body is needed: the provider is chosen from the token's own `iss`. A body
  `{"provider_id": "<uuid>"}` is accepted only to disambiguate two enabled
  providers on the same issuer.
- The access token lives for the configured access-token TTL (15 minutes by
  default), and never longer than the ID token that bought it. Docker does not
  refresh credentials, so a job that runs longer must exchange again before
  its next push. `expires_in` gives the real lifetime.

GitHub Actions uses the same exchange. Request `permissions: id-token: write`,
fetch the token from `$ACTIONS_ID_TOKEN_REQUEST_URL` with the provider's
audience, and send it as above.

## The mapping is the security boundary

Every token a mapping matches becomes the same principal, with the same
grants and the same `allowed_repo_ids`. The mapping's `claim_filters` decide
who holds that access, and nothing tells the matched pipelines apart.

- **An any-of filter shares one credential.** If a mapping accepts
  `"project_path": ["group/app", "someone/app-fork"]`, the fork can publish
  exactly what the upstream can. Matching a fork means trusting the fork as
  much as the upstream.
- **Keep one mapping per project as the default.** Use an array only for
  projects you would equally trust with the same credential. Give projects
  that need different access different mappings, and so different accounts.
- **Filter on ref where it matters.** To let only protected branches or tags
  publish, add `ref_protected: "true"` or a `ref`/`ref_type` filter. Every ref
  the filter admits gets the account's full access.

## Lifecycle

- **Editing** a mapping (name, filters, priority, repository scope) keeps its
  account. Renaming does not change who it is.
- **Disabling** a mapping refuses its exchanges. The account and its grants
  are kept for when it is re-enabled.
- **Deleting** a mapping **deactivates** its account. It is not deleted, so
  everything it did stays attributable. Its refresh tokens are revoked.
  Deleting a provider does the same for all of its mappings.
- **Deactivating** the account, through user management, is a kill switch
  that stays in place: exchanges through its mapping are refused with `401`
  until an administrator reactivates it. An exchange never reactivates a CI
  account, and never creates a replacement for a deactivated one.
- **Recreating** an equivalent mapping creates a **new** account with no
  grants. Grants of the old, deactivated account are not carried over.
  Configuration that references the mapping's `service_account_id` follows
  the new account automatically. A hand-copied `ci-…` name does not.

## Upgrading from a version where accounts were keyed on the token subject

Earlier versions keyed the account on the token's `sub`. GitLab's `sub`
embeds the ref (`project_path:group/app:ref_type:branch:ref:main`), so only
the first ref to run could authenticate. Every other branch and tag got
`409 Conflict "Username already exists"`, and any-of filters could not work
at all. Those accounts were named `ci-<8 hex>` and were created on the first
successful exchange.

On upgrade, migration 232 re-keys those accounts in place:

- `users.id` does not change, so group memberships, permissions and audit
  history carry over. Existing `ci-<8 hex>` names are kept. New mappings get
  `ci-<12 hex>` names.
- An account is re-keyed only when exactly one mapping owns its name's prefix.
  Accounts whose mapping was deleted, or whose prefix two mappings share, are
  left untouched. If one of them can be attributed later, the first exchange
  through its mapping adopts it. A unique prefix match is effectively, not
  provably, the original mapping: if that mapping was deleted and a later one
  happens to share its 8-hex prefix (about 1 in 2^32 per pair), the account
  binds to the later mapping.
- Every decision is recorded in `ci_oidc_service_account_rekey_log`
  (`rewritten`, `skipped_orphaned`, `skipped_ambiguous`, and later `adopted`),
  with the previous key. Review the skipped rows: a `skipped_orphaned` account
  still holding grants belongs to a mapping that no longer exists.
- Mappings created before the upgrade report `service_account_id: null` until
  their account is re-keyed or adopted. A mapping that never had an account
  gets one on its first exchange.

**During a rolling upgrade**, a replica still running the old version cannot
find a re-keyed account, and its exchanges fail with the old 409 until
rollout completes. Re-running the job succeeds. An old replica that serves a
mapping created by the new version cannot find its account either, and
creates a stray `ci-<8 hex>` account keyed on the token subject. It has no
grants and the new version never uses it; deactivate it after rollout.

**To roll back**, restore the previous keys before starting the old version:

```sql
UPDATE users u SET external_id = l.previous_external_id
FROM ci_oidc_service_account_rekey_log l
WHERE l.user_id = u.id
  AND l.outcome IN ('rewritten', 'adopted')
  AND u.external_id = l.new_external_id;
```

Accounts created by the new version (`ci-<12 hex>`) have no previous key.
The old version does not recognise them. On its next exchange it creates a
new `ci-<8 hex>` account, which has none of the grants.
