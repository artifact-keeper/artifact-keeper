# Dynamic AWS upstream auth (ECR and CodeArtifact)

Remote repositories can authenticate to Amazon ECR and AWS CodeArtifact with
credentials Artifact Keeper mints itself, instead of a static password that has
to be rotated from the outside.

This is issue #1559. Both services hand out short-lived tokens — ECR's
`GetAuthorizationToken` is valid about 12 hours, CodeArtifact's up to 12 — so a
remote repository pinned to a fixed credential works until it silently stops.
The `aws_ecr` and `aws_codeartifact` upstream auth types replace that credential
with a *provider*: Artifact Keeper signs `GetAuthorizationToken` with its own
AWS identity, caches the token in memory, and refreshes it before it expires.

Nothing AWS-vended is written to the database. `repository_config` holds only
the non-secret provider settings (region, registry id / domain).

## Where the AWS credentials come from

The **default AWS credential chain**, resolved by the process, in this order:

| Source | Environment |
| --- | --- |
| Static keys | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN` |
| Web identity (**IRSA**) | `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`, optional `AWS_ROLE_SESSION_NAME` |
| ECS task role | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` |
| **EKS Pod Identity** | `AWS_CONTAINER_CREDENTIALS_FULL_URI`, `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` |
| Instance profile | IMDS (IMDSv2; `AWS_EC2_METADATA_DISABLED` turns it off) |

IRSA and EKS Pod Identity are the recommended deployment: the service account
projects the token, and **no AWS secret is stored in Artifact Keeper at all**.

The identity is process-wide. A per-repository `role_arn` / `external_id`
(`sts:AssumeRole`) is **not implemented**; if different repositories need
different AWS identities, run separate instances, or grant the one role access
to every registry/domain being proxied.

## IAM permissions

ECR:

* `ecr:GetAuthorizationToken` (no resource scope — it is account-wide)
* the usual pull permissions on the repositories being proxied:
  `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:BatchCheckLayerAvailability`

CodeArtifact:

* `codeartifact:GetAuthorizationToken` on the domain
* `codeartifact:ReadFromRepository` on the repository
* `sts:GetServiceBearerToken` (required for the token to be usable by package
  managers), conditioned on `sts:AWSServiceName = codeartifact.amazonaws.com`

Cross-account ECR pulls work without extra configuration: the token is always
minted for the *calling* account, and the target registry's registry policy is
what authorizes the pull.

## Configuring a repository

Create the remote repository with its `upstream_url` pointing at the AWS
endpoint, then set the provider:

```bash
# Amazon ECR (an OCI/docker remote)
curl -X PUT https://ak.example/api/v1/repositories/ecr-proxy/upstream-auth \
  -H 'Authorization: Bearer <admin token>' \
  -H 'Content-Type: application/json' \
  -d '{
        "auth_type": "aws_ecr",
        "aws": { "region": "us-east-1", "registry_id": "123456789012" }
      }'
```

```bash
# AWS CodeArtifact (npm / PyPI / Maven / NuGet / Cargo remotes)
curl -X PUT https://ak.example/api/v1/repositories/ca-npm/upstream-auth \
  -H 'Authorization: Bearer <admin token>' \
  -H 'Content-Type: application/json' \
  -d '{
        "auth_type": "aws_codeartifact",
        "aws": {
          "region": "eu-west-1",
          "domain": "platform",
          "domain_owner": "123456789012",
          "duration_seconds": 43200
        }
      }'
```

| Field | Provider | Notes |
| --- | --- | --- |
| `region` | both | Required. Validated as an AWS region code. |
| `registry_id` | `aws_ecr` | Optional 12-digit account id. Pins the upstream host to that registry. |
| `domain` | `aws_codeartifact` | Required. |
| `domain_owner` | `aws_codeartifact` | Optional 12-digit account id; defaults to the caller's account. |
| `duration_seconds` | `aws_codeartifact` | Optional; `0` or `900`–`43200`. Defaults to the AWS default of 12 hours. |

`upstream_username` / `upstream_password` are not used by either provider and
are rejected on the repository-create path — the AWS types must be configured
through `PUT /repositories/{key}/upstream-auth`, which is admin-gated exactly
like the static credential types.

The CodeArtifact token is domain-scoped, so there is no `repository` setting:
point the repository's `upstream_url` at the specific CodeArtifact repository
endpoint, e.g.
`https://platform-123456789012.d.codeartifact.eu-west-1.amazonaws.com/npm/main/`.

### Auth shape per format

CodeArtifact takes the token differently depending on the client, and Artifact
Keeper follows AWS's own instructions: **npm** (and `yarn` / `pnpm` / `bower`)
and **Cargo** get `Authorization: Bearer <token>`; Maven/Gradle, pip/twine,
NuGet and everything else get HTTP Basic with the fixed user name `aws`. ECR is
always HTTP Basic with the user name `AWS`, the shape `docker login` uses.

## Refresh and concurrency

* A cached token is reused until it has **less than 15 minutes** left, then
  re-minted. Both services issue ~12-hour tokens, so this is ~2 % of the
  lifetime: an AWS outage has the whole window to recover, and the extra API
  calls are negligible.
* Refreshes are **singleflighted** per registry/domain: a burst of concurrent
  pulls against a token that has just come due produces one
  `GetAuthorizationToken` call, not one per pull.
* **A failed refresh does not take the repository down.** While the token
  already held is still usable (more than a minute left), the failure is logged
  and that token keeps being served. Pulls only start failing once no usable
  token remains.

The cache is per process and in memory only; a restart re-mints. Its key is the
provider, region and registry/domain — deliberately *not* the AWS access-key id,
which rotates on every session refresh and would force a needless re-mint.

## Safety properties

* **The minted token never leaves the process except as an upstream
  `Authorization` header.** It is not persisted, not returned by the repository
  API (which reports only `upstream_auth_type` / `upstream_auth_configured`),
  and not renderable: `UpstreamAuthType` has a redacting `Debug`, and AWS
  responses are parsed rather than echoed into errors or logs.
* **Credentials only go to the AWS endpoint the operator configured.** The
  repository's `upstream_url` is checked against the provider config when the
  credentials are saved *and* again on every resolve, so an upstream edited
  afterwards cannot inherit an AWS-minted token. The existing OCI bearer-realm
  origin pin (GHSA-78h6-3wp8-2542) and the connect-time SSRF DNS guard continue
  to apply unchanged.

## Failure messages

| Symptom | What it means |
| --- | --- |
| `No usable AWS credentials for region …` | The default chain resolved nothing. Check IRSA/Pod Identity projection or the `AWS_*` environment. |
| `… not permitted to call GetAuthorizationToken` | The role is missing `ecr:GetAuthorizationToken` / `codeartifact:GetAuthorizationToken` + `sts:GetServiceBearerToken`. |
| `… expired or not valid for this region` | An assumed role lapsed, or the configured region does not match the credentials. |
| `AWS throttled the … call` | `ThrottlingException`. Returned as a retryable 503, and a token already held keeps serving. |
| `Upstream host … is not an Amazon ECR registry endpoint for region …` | The repository's `upstream_url` and its AWS provider config disagree. |

The detailed text is logged; clients see the generic configuration-error body
for the misconfiguration cases and the retryable message for throttling.
