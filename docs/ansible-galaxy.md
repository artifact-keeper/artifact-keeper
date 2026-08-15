# Ansible Galaxy repositories

Artifact Keeper serves the [Ansible Galaxy v3 API](https://galaxy.ansible.com/),
so `ansible-galaxy collection install` and `ansible-galaxy collection publish`
work against an Artifact Keeper repository with no plugin and no wrapper script
— only configuration. This page covers that configuration. It is issue #3283.

## Repository URL

Every Galaxy endpoint lives under the repository's format prefix:

```text
https://<artifact-keeper-host>/ansible/<repo-key>
```

That URL — with no trailing slash and no `/api` suffix — is what
`ansible-galaxy` calls the **server URL**. The client appends `/api` itself to
discover the API version, then reassigns its internal `api_server` from
whichever discovery URL answered.

> Both `GET <server>/api` and `GET <server>/api/` are served and return
> identical bodies. This is deliberate: ansible-core's `_urljoin` strips
> trailing slashes from every fragment, so the spelling the client requests is
> not the spelling a server author would naturally register. Registering only
> one of them was issue #3137.

## Creating an API key

Galaxy authentication uses an Artifact Keeper **API token**, not your password.

1. Sign in to the web UI and open **Profile → API Tokens**, or call
   `POST /api/v1/auth/tokens`.
2. Give the token the scopes it needs:
   - `read:artifacts` — required to install collections.
   - `write:artifacts` — additionally required to publish. A token without it
     gets `403 Forbidden` on publish while still being able to install.
3. Copy the token value. It is shown once.

Scope the token to the repositories it needs where possible; API tokens honour
per-repository restrictions.

### How the token is sent

`ansible-galaxy` sends the credential as:

```http
Authorization: Token <api_key>
```

**`Token`, not `Bearer`.** ansible-core sets `GalaxyToken.token_type = 'Token'`
and builds the header as `'%s %s' % (self.token_type, self.get())`; only its
Keycloak / Automation Hub variant uses `Bearer`. Artifact Keeper treats the
`Token` scheme as equivalent to `Bearer` and validates it through the same
API-token chain. (Rejecting it was the other half of #3137.)

Note also that ansible-core's `_add_auth_token` attaches this header to the
*discovery* probe too, even though discovery is declared `auth_required=False`.
That is expected and supported.

## Configuring `ansible.cfg`

Define the repository as a galaxy server:

```ini
[galaxy]
server_list = artifact_keeper

[galaxy_server.artifact_keeper]
url = https://artifact-keeper.example.com/ansible/ansible-local
token = <your-api-key>
```

Keep the token out of the file by using the environment instead — ansible-core
reads `ANSIBLE_GALAXY_SERVER_<NAME>_TOKEN`, upper-cased to match the section
name:

```bash
export ANSIBLE_GALAXY_SERVER_ARTIFACT_KEEPER_URL="https://artifact-keeper.example.com/ansible/ansible-local"
export ANSIBLE_GALAXY_SERVER_ARTIFACT_KEEPER_TOKEN="$AK_API_TOKEN"
```

### Or pass it per-invocation

```bash
ansible-galaxy collection install community.general \
  --server https://artifact-keeper.example.com/ansible/ansible-local \
  --api-key "$AK_API_TOKEN"
```

`--server` accepts either a name from `server_list` or a bare URL.

## Publishing a collection

```bash
ansible-galaxy collection build
ansible-galaxy collection publish \
  ./community-general-1.2.3.tar.gz \
  --server artifact_keeper
```

The upload returns `202 Accepted` with a body carrying an import **task**:

```json
{
  "namespace": "community",
  "name": "general",
  "version": "1.2.3",
  "href": "/ansible/ansible-local/api/v3/collections/community/general/versions/1.2.3/",
  "download_url": "/ansible/ansible-local/download/community-general-1.2.3.tar.gz",
  "task": "/ansible/ansible-local/api/v3/imports/collections/<task-id>/"
}
```

The client indexes `task` unconditionally and then polls it until `state` is no
longer `waiting` and `finished_at` is set. Artifact Keeper's import is
synchronous — the upload *is* the import — so the first poll already reports a
finished task.

Two properties of `task` matter to the client and are held by tests:

- It is **root-absolute**. Recent ansible-core resolves it with
  `urljoin(api_server, task)`, which only works for an absolute path.
- Its **last path segment is the task id**. Older ansible-core (stable-2.17
  onward) discards the rest and rebuilds the URL from `api_server`.

Omitting `task` entirely made the CLI raise `KeyError: 'task'` *after* a
successful upload; that was issue #3282.

### Filename determines coordinates

The namespace, name and version are parsed from the uploaded filename, which
must be `{namespace}-{name}-{version}.tar.gz`. `ansible-galaxy collection
build` produces exactly this. A filename that does not match is rejected with
`400`, and a rejected upload carries **no** `task` key.

If the request includes a `sha256` form field, it is verified against the
received bytes and a mismatch is a `400`.

## Installing

```bash
ansible-galaxy collection install community.general:1.2.3 \
  --server artifact_keeper
```

Against a `requirements.yml`:

```yaml
collections:
  - name: community.general
    version: 1.2.3
    source: https://artifact-keeper.example.com/ansible/ansible-local
```

```bash
ansible-galaxy collection install -r requirements.yml
```

## Private repositories

A private repository requires a credential on **every** request, including
discovery. An anonymous request gets `401`, not `404`, even for a repository
that does not exist — Artifact Keeper does not expose repository existence to
unauthenticated callers (#1808). If discovery 401s, the API key is missing,
wrong, or not scoped to that repository; it is not a routing problem.

## Endpoint reference

All paths are relative to `https://<host>/ansible/<repo-key>`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api`, `/api/` | Version discovery; both spellings served |
| GET | `/api/v3/` | v3 service index |
| GET | `/api/v3/collections/` | List collections |
| GET | `/api/v3/collections/{ns}/{name}/` | Collection detail |
| GET | `/api/v3/collections/{ns}/{name}/versions/` | Version list |
| GET | `/api/v3/collections/{ns}/{name}/versions/{version}/` | Version detail |
| GET | `/download/{ns}-{name}-{version}.tar.gz` | Artifact download |
| POST | `/api/v3/artifacts/collections/` | Publish |
| GET | `/api/v3/imports/collections/{task_id}/` | Import task status |

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `401` on every call, including install | Missing/invalid API key, or the key is not scoped to this repository. Private repos require auth on discovery too. |
| `403` on publish, install works | Token lacks `write:artifacts`. |
| `KeyError: 'task'` after upload | Server did not return the import task (#3282). Fixed; upgrade. |
| CLI hangs after publish | The import poll URL returned `404`. `wait_import_task` retries `404` forever and `--import-timeout` defaults to `0`. |
| `400` on publish | Filename is not `{namespace}-{name}-{version}.tar.gz`, or the declared `sha256` does not match the bytes. |

## Test coverage

- Unit tests: `backend/src/api/handlers/ansible.rs`
- Client-contract integration tests:
  [`backend/tests/ansible_galaxy_tests.rs`](../backend/tests/ansible_galaxy_tests.rs)
  — drives the production composition (handler table nested at `/ansible`
  behind `repo_visibility_middleware`) against a private repository, using the
  `Token` scheme and deriving every URL from the previous response body the way
  the real client does.

```sh
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
  cargo test --test ansible_galaxy_tests -- --ignored
```
