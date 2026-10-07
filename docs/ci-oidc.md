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
slash does not matter. `provider_type` (`gitlab`, `github`, `kubernetes` or `generic`)
only affects how the account's display name is built, except for
`kubernetes`, which also changes what the exchange mints (see
[Kubernetes](#kubernetes-pulling-images-with-a-serviceaccount-token)).

By default a provider finds its signing keys through OIDC discovery at
`{issuer_url}/.well-known/openid-configuration` (`"key_source": "discovery"`).
When Artifact Keeper cannot reach the issuer, store the issuer's JWKS on the
provider instead (`"key_source": "static"`, see
[Static keys](#static-keys-when-the-issuer-is-not-reachable)).

### 2. Create a mapping

```bash
curl -sS -X POST "$AK/api/v1/admin/ci-oidc/$PROVIDER_ID/mappings" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "app-deploy",
        "claim_filters": { "project_id": "4242" },
        "allowed_repo_ids": null,
        "group_binding_ids": ["'"$GROUP_ID"'"]
      }'
```

- `claim_filters` is an object of claim name to required value. A string must
  match exactly. An array matches any of its values. All keys must match. An
  empty object `{}` matches every token from the issuer, so do not use it
  outside a single-tenant issuer.
- A key that starts with `/` is a JSON Pointer (RFC 6901) into nested claims:
  `{"/kubernetes.io/namespace": "payments"}` matches the `namespace` member
  of the `kubernetes.io` object. Matching is still exact, with no prefix or
  glob matching. Escape a `/` inside a member name as `~1` and a `~` as `~0`.
  A key without a leading `/` is always a top-level claim name, dots
  included: `"kubernetes.io"` compares the whole object. A pointer with any
  other `~` sequence is refused with `400` when the mapping is saved.
- Prefer immutable claims. In GitLab, `project_id` survives a project rename or
  transfer and `project_path` does not. If a path is freed and reused by another
  project, a `project_path` filter admits that new project.
- `allowed_repo_ids` narrows every token minted through the mapping to the
  listed repositories: `null` means no restriction, `[]` denies all. It is a
  **ceiling**, covered below — it never grants anything by itself.
- `group_binding_ids` is what actually grants access: the groups the service
  account holds membership of. See the next section.
- The response contains `service_account_id` and `service_account_username`.

If the account name the mapping derives is already taken, the create is
refused with `409 Conflict` naming the account, and nothing is written. Retry
the create; a new mapping id derives a new name. Naming a group that does not
exist is refused the same way, naming the missing group; a binding never
creates a group.

### 3. Grant the service account access with `group_binding_ids`

A mapping authenticates a pipeline. It does not authorize it on its own:
`allowed_repo_ids` reads like a grant but is only ever a **ceiling**,
intersected with whatever RBAC the account otherwise holds — and a new service
account starts with none. `group_binding_ids` is the floor: the set of groups
the mapping's service account SHALL belong to. Declare it and the account has
access from the moment the mapping does, with nothing configured anywhere
else:

```bash
curl -sS -X PUT "$AK/api/v1/admin/ci-oidc/$PROVIDER_ID/mappings/$MAPPING_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"group_binding_ids\": [\"$GROUP_ID\"]}"
```

`$GROUP_ID` must already exist (create it and its repository permissions the
usual way — `POST /api/v1/groups`, `POST /api/v1/permissions` — a binding
references groups, it never creates them). Because the service account exists
from the moment the mapping does, Terraform or any other configuration tool
can create the mapping, the group, its permissions, and the binding in a
single apply, with no reference to a `ci-…` username anywhere.

**Three states, not two.** `group_binding_ids` distinguishes *no claim* from
*declared empty*:

| Value | Meaning | Reconciles the account's memberships? |
|---|---|---|
| omitted / `null` | No binding. The mapping says nothing about groups. | No — whatever memberships the account holds (including ones you added by hand) are left exactly as they are. |
| `[]` | Declared: "no memberships." | Yes — strips every membership the account holds. |
| `["id", ...]` | Declared: exactly these groups. | Yes — adds what's missing, removes what's not listed. |

A mapping created before this feature existed has an absent binding, so it
behaves exactly as it always has; nothing changes until you declare one.

**The binding is authoritative once declared, and reconciles on every
exchange** — not only when you write the mapping. Add a group to the binding
and the next pipeline run has it; remove one and the next run does not. A
membership you added to the account by any other means does not survive a
binding's reconciliation — this is what makes the mapping the single place
that answers "what may this pipeline do." Roles assigned directly to the
account are likewise re-derived on every exchange, the same way as for other
federated accounts, and are not a place to grant CI access.

**Revocation window.** Narrowing a binding reconciles immediately when you
write the mapping, in the same transaction as the write, so a request made
*after* your `PUT` returns sees the narrower access right away — group grants
are not baked into the token at mint time. The write also clears the
permission cache on the replica that served it; other replicas are told to
clear theirs through the database's cache-invalidation notifications, and a
replica that has lost that connection falls back to the cache's 30-second
expiry. A credential a pipeline had already been handed keeps working as a
bearer token until it expires (default 15 minutes); what it can *do* with
that token is re-evaluated on every request against the current binding, same
as any other credential. There is no separate revocation list — shorten the
access-token TTL if you need a tighter bound.

**A binding is enforced or nothing happens.** If a mapping write cannot
reconcile its binding, the write fails and nothing changes: the mapping keeps
its previous binding and the account its previous memberships (a failed
create leaves no mapping and no account, so retrying it is safe). If an
exchange through a bound mapping cannot reconcile, it is refused with `503`
and no token is issued; the pipeline can retry. An exchange that was already
under way when you narrowed a binding applies the narrowed binding, never the
one it started with. Mappings without a binding never refuse an exchange on
these grounds.

**Every membership change is audited.** A mapping create or update that adds
or removes memberships writes a `CI_OIDC_GROUP_BINDING_RECONCILED` entry to
the audit log, naming the mapping, the service account, and the groups added,
removed, or no longer existing. A write that changes no membership writes no
entry.

**Adopting a binding on a mapping that already has hand-wired access:**
declare the binding, verify the pipeline still authenticates and acts
correctly, *then* remove the old `group_binding.../members` call or Terraform
resource that granted it by hand. Do the steps in that order — reconciliation
strips any membership the binding does not name, so removing the hand-wired
grant *before* confirming the binding covers the same access leaves the
pipeline with nothing on its next run.

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

## Kubernetes: pulling images with a ServiceAccount token

Since Kubernetes 1.34 the kubelet can hand an image credential provider a
ServiceAccount token bound to the pod that is being started (KEP-4412). That
token is an ordinary OIDC JWT, so the same exchange turns it into a registry
credential, with no `imagePullSecret` in any namespace and no static
credentials on any node (#1246).

Create one provider per cluster with `"provider_type": "kubernetes"`. The type
changes three things about an exchange:

- **The credential can pull and nothing else.** The access token carries only
  the `read:artifacts` and `read:repositories` scopes, whatever the service
  account's groups would otherwise allow. A push with it, as the Docker
  password or through a bearer from `/v2/token`, is refused with `403`. The
  mapping's `allowed_repo_ids` ceiling and the usual expiry cap still apply.
- **It cannot be renewed.** No refresh token is minted or stored, and the
  credential cannot mint an API token either: the token endpoints refuse every
  CI OIDC service account with `403`, whatever the provider type. The response
  keeps its shape (`access_token`, `token_type`, `expires_in`, `username`).
- **The workload is logged.** The exchange's `security` line adds
  `k8s_namespace`, `k8s_serviceaccount`, `k8s_pod` and `k8s_node` from the
  token's `kubernetes.io` claims. A claim the token does not carry is logged as
  `(absent)`. The account's display name names only the provider and the
  mapping, because one mapping serves many workloads.

The kubelet caches the credential on the node, where anything with root on the
host can read it. A leaked token that could push would let an attacker replace
images for every consumer of the registry, which is why this ceiling is fixed
by type and cannot be widened. `provider_type` is matched case-insensitively
and stored lowercase; a value that is not `gitlab`, `github`, `kubernetes` or
`generic`, a typo such as `k8s` included, is refused with 400. A provider
created before the type was checked may hold another value; an update that
sends that stored value back unchanged is accepted, so editing such a provider
in the web UI keeps working, and it still acts as `generic`. Changing a
provider's type, for example `kubernetes` to `generic`, is written to the
`security` log with the acting admin, because it widens every credential the
provider mints from then on.

### Issuer and key source per platform

The provider's `issuer_url` is the cluster's ServiceAccount issuer. On any
platform the cluster reports it itself:

```bash
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
```

| Platform | Issuer | Key source |
|---|---|---|
| EKS | `https://oidc.eks.<region>.amazonaws.com/id/<id>` (`aws eks describe-cluster --query cluster.identity.oidc.issuer`) | `discovery` |
| GKE | `https://container.googleapis.com/v1/projects/<project>/locations/<location>/clusters/<cluster>` | `discovery` |
| AKS with `--enable-oidc-issuer` | `az aks show --query oidcIssuerProfile.issuerUrl` | `discovery` |
| AKS without `--enable-oidc-issuer` | whatever the command above prints; its discovery document is not published outside the cluster | `static` |
| On-prem (kubeadm and others) | the API server's `--service-account-issuer`; kubeadm's default is `https://kubernetes.default.svc.cluster.local` | `static` |

Use `discovery` whenever Artifact Keeper can fetch the issuer's discovery
document over HTTPS. It follows key rotation by itself. Use `static` when it
cannot.

### Static keys when the issuer is not reachable

A `static` provider verifies tokens only against the JWKS stored on it and
never contacts the issuer. The API server serves that JWKS:

```bash
kubectl get --raw /openid/v1/jwks > jwks.json

curl -sS -X POST "$AK/api/v1/admin/ci-oidc" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "onprem-prod",
        "provider_type": "kubernetes",
        "issuer_url": "https://prod.k8s.example.internal",
        "audience": "https://artifacts.example.com",
        "key_source": "static",
        "static_jwks": '"$(cat jwks.json)"'
      }'
```

- The JWKS must hold at least one public RSA or EC key. Keys must have unique
  `kid`s. A key with private members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`)
  is refused with `400`: a trust anchor needs only the public key, and a pasted
  private key is already leaked.
- A token's `kid` must name a key in the set. A token whose `kid` is not there
  is refused with `401`, and the `security` log names the provider and the
  missing `kid`. There is no fall-back to another key. A token without a `kid`
  is accepted only when the set holds exactly one key.
- `iss`, `aud` and expiry are checked exactly as for `discovery`.
- `PUT /api/v1/admin/ci-oidc/{id}` with `static_jwks` replaces the whole set.
  Setting `"key_source": "discovery"` discards the stored set. Every change to
  the key source or the set is written to the `security` log with the admin
  and the resulting `kid`s.

**Key rotation.** When the cluster switches to a new signing key, every token
it issues names the new `kid`, and pulls fail until the provider holds that
key. Rotate with overlap:

1. Add the new public key to the API server's `--service-account-key-file`
   list. It now appears in `/openid/v1/jwks` next to the old one.
2. Push that JWKS, both keys, to the provider.
3. Switch `--service-account-signing-key-file` to the new key.
4. Once no token signed with the old key can still be valid, remove it from
   the API server and push the JWKS again.

A CronJob in the cluster can keep the provider current. Any ServiceAccount may
read `/openid/v1/jwks` through the default
`system:service-account-issuer-discovery` binding. The admin token it uses is
a full admin credential, so keep it in its own namespace and restrict who can
read that Secret.

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: artifact-keeper-jwks-sync
  namespace: artifact-keeper-sync
spec:
  schedule: "*/15 * * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: sync
              image: alpine:3.20
              env:
                - name: AK
                  value: https://artifacts.example.com
                - name: PROVIDER_ID
                  value: "<provider uuid>"
                - name: ADMIN_TOKEN
                  valueFrom:
                    secretKeyRef: {name: artifact-keeper-admin, key: token}
              command: ["/bin/sh", "-ec"]
              args:
                - |
                  apk add --no-cache curl jq >/dev/null
                  SA=/var/run/secrets/kubernetes.io/serviceaccount
                  JWKS=$(curl -sSf --cacert "$SA/ca.crt" \
                    -H "Authorization: Bearer $(cat "$SA/token")" \
                    https://kubernetes.default.svc/openid/v1/jwks)
                  jq -n --argjson jwks "$JWKS" '{static_jwks: $jwks}' |
                    curl -sSf -X PUT "$AK/api/v1/admin/ci-oidc/$PROVIDER_ID" \
                      -H "Authorization: Bearer $ADMIN_TOKEN" \
                      -H 'Content-Type: application/json' --data-binary @- >/dev/null
```

Managed clusters on `discovery` need none of this.

### Audience: dedicated, never the API server's

Set the provider's `audience` to a value used only for Artifact Keeper, such
as `https://artifacts.example.com`, and configure the kubelet credential
provider to request tokens for it. Never use the API server's own audience
(`https://kubernetes.default.svc`, or any value in `--api-audiences`):

- every pod's default projected token carries that audience, so the provider
  would accept any pod's token, not only tokens the kubelet requested for
  image pulls;
- a token presented to Artifact Keeper would also be valid against the API
  server.

Artifact Keeper does not yet refuse such an audience when a provider is
created (#4133), so check it yourself.

### Mappings for namespaces and ServiceAccounts

Use pointer keys to match the token's `kubernetes.io` claims:

```json
{ "/kubernetes.io/namespace": "payments" }
```

admits every ServiceAccount in `payments`, and

```json
{ "/kubernetes.io/namespace": "payments",
  "/kubernetes.io/serviceaccount/name": "api" }
```

admits only `payments/api`. Matching is exact: `"prod"` does not admit
`prod-sandbox`. `sub` (`system:serviceaccount:<namespace>:<name>`) also works
with an any-of array for a fixed list of ServiceAccounts.

Bind the mapping to a group that has **read** on the repositories the
workloads pull from (`group_binding_ids`). Granting write gains nothing, since
the credential cannot push.

### Several clusters

Give every on-prem cluster its own `--service-account-issuer`, such as
`https://prod.k8s.example.internal`. Issuer resolution picks the provider from
the token's `iss`. If two clusters keep kubeadm's default issuer, their tokens
cannot be told apart by issuer: two enabled providers on one issuer and
audience make the exchange fail with `400` unless the request names
`provider_id`, and a provider holding both clusters' keys would accept either
cluster's tokens under the other's mappings.

## The mapping is the security boundary

Every token a mapping matches becomes the same principal, with the same
grants and the same `allowed_repo_ids`. The mapping's `claim_filters` decide
who holds that access, and nothing tells the matched pipelines apart.

- **An any-of filter shares one credential.** If a mapping accepts
  `"project_path": ["group/app", "someone/app-fork"]`, the fork can publish
  exactly what the upstream can. Matching a fork means trusting the fork as
  much as the upstream. `group_binding_ids` makes what that trust is worth
  concrete and readable in one place — an any-of filter on a mapping bound to
  a broad group is the exact shape of over-grant to watch for in review.
- **A binding is a new way to express something an admin could already do,
  not a new capability.** Mapping create/update is admin-only, same as before;
  a binding lets that admin point a mapping at a group's existing access
  instead of wiring a matching membership by hand in a second place. Pointing
  several mappings at one broad group is easy and was always possible — it is
  just more convenient to do by accident now, so review what a binding
  actually reaches the same way you would review any other group grant.
- **Keep one mapping per project as the default.** Use an array only for
  projects you would equally trust with the same credential. Give projects
  that need different access different mappings, and so different accounts.
- **Filter on ref where it matters.** To let only protected branches or tags
  publish, add `ref_protected: "true"` or a `ref`/`ref_type` filter. Every ref
  the filter admits gets the account's full access.

## Lifecycle

- **Editing** a mapping (name, filters, priority, repository scope, group
  binding) keeps its account. Renaming does not change who it is. Editing the
  binding reconciles memberships immediately, whether you widen or narrow it.
- **Disabling** a mapping refuses its exchanges — no credential is issued
  under it while disabled. The account keeps whatever memberships its binding
  last reconciled; they take effect again once you re-enable the mapping and
  a pipeline exchanges through it.
- **Deleting** a mapping **deactivates** its account. It is not deleted, so
  everything it did stays attributable. Its refresh tokens are revoked.
  Deleting a provider does the same for all of its mappings. A deactivated
  account cannot authenticate, so its binding stops conferring anything the
  same way disabling does, whether or not anyone reconciles its memberships
  again.
- **Deactivating** the account, through user management, is a kill switch
  that stays in place: exchanges through its mapping are refused with `401`
  until an administrator reactivates it. An exchange never reactivates a CI
  account, and never creates a replacement for a deactivated one.
- **Recreating** an equivalent mapping creates a **new** account with no
  grants and no binding. Grants of the old, deactivated account are not
  carried over, and neither is a group binding — declare it again on the new
  mapping.
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
