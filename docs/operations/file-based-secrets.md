# Secrets in files (`*_FILE`)

Every credential the backend reads from the environment also accepts a
`<NAME>_FILE` variable holding the **path** to a file containing the value
(#4142). The value then comes from a mounted secret file instead of the
process environment, which anything that can read the Kubernetes pod spec,
run `docker inspect`, or open `/proc/<pid>/environ` can see.

```sh
JWT_SECRET=...              # value in the environment (the legacy form)
JWT_SECRET_FILE=...         # path to a file holding the value
```

## Supported settings

| Area | Settings |
|---|---|
| Core startup | `DATABASE_URL`, `JWT_SECRET`, `PEER_API_KEY` |
| Admin bootstrap | `ADMIN_PASSWORD` |
| SSO / directories | `OIDC_CLIENT_SECRET`, `LDAP_BIND_PASSWORD`, `SSO_ENCRYPTION_KEY` |
| Migration | `MIGRATION_ENCRYPTION_KEY` |
| Webhooks | `AK_WEBHOOK_SECRET_KEY` |
| SMTP notifications | `SMTP_PASSWORD` |
| Search | `OPENSEARCH_PASSWORD` |
| Advisory feed | `GITHUB_TOKEN` |
| S3-compatible storage | `S3_SECRET_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `S3_PRESIGN_SECRET_ACCESS_KEY` |
| Azure storage | `AZURE_STORAGE_ACCESS_KEY`, `AZURE_CLIENT_SECRET` |

`INITIAL_ADMIN_PASSWORD_FILE` (#2803) and `DEPENDENCY_TRACK_API_KEY_FILE`
(#2084) already used this convention and behave identically. The two PEM keys
keep their own path variables, `GCS_PRIVATE_KEY_PATH` and
`CLOUDFRONT_PRIVATE_KEY_PATH`. Key *identifiers* (`S3_ACCESS_KEY_ID`,
`AZURE_CLIENT_ID`, usernames, bind DNs) are not secrets and stay env-only.

## Semantics

1. **The direct value wins** when it is set and non-empty, matching the
   `INITIAL_ADMIN_PASSWORD` / `INITIAL_ADMIN_PASSWORD_FILE` precedence: an env
   var can override a mounted secret without editing the mount.
2. Otherwise the file is read and its contents are trimmed of surrounding
   whitespace/newlines — the trailing newline from `echo secret > file` is the
   norm and is tolerated.
3. **A configured file that is unreadable or empty is an error**, never a
   silent fall-through to "unset". The error names the variable and the path
   but never the contents. An operator who points at a broken mount gets a
   loud failure instead of a backend that quietly runs without the secret.
   Which failure depends on the setting:
   - Startup configuration (`DATABASE_URL`, `JWT_SECRET`, `PEER_API_KEY`,
     `ADMIN_PASSWORD`, storage credentials, …) — the backend refuses to
     start.
   - `MIGRATION_ENCRYPTION_KEY` — the migration API request fails; the
     built-in dev fallback is still used only when the key is genuinely
     unset, as before.
   - `LDAP_BIND_PASSWORD` and `GITHUB_TOKEN` — these must not take the whole
     process down, so the error is logged and the secret is treated as
     absent, exactly as if the variable were unset.
4. A `_FILE` variable set to the empty string counts as unset, so compose
   files that render `FOO_FILE: ${FOO_FILE:-}` keep working.

## Examples

### Docker Compose

```yaml
services:
  backend:
    environment:
      JWT_SECRET_FILE: /run/secrets/jwt-secret
    secrets:
      - jwt-secret

secrets:
  jwt-secret:
    file: ./secrets/jwt-secret.txt
```

### Kubernetes

Point the `_FILE` variable at a volume-mounted secret. (A `secretKeyRef`
places the value in the environment again, which defeats the purpose.)

```yaml
      containers:
        - name: backend
          env:
            - name: JWT_SECRET_FILE
              value: /etc/artifact-keeper-secrets/jwt-secret
          volumeMounts:
            - name: artifact-keeper-secrets
              mountPath: /etc/artifact-keeper-secrets
              readOnly: true
      volumes:
        - name: artifact-keeper-secrets
          secret:
            secretName: artifact-keeper-secrets
```

### Generating the files

```sh
openssl rand -base64 48 > secrets/jwt-secret
```

Trailing newlines are trimmed on read; the file must be readable by the user
the backend runs as.
