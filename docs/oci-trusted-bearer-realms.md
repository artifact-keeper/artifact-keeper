# Trusted OCI Bearer token realms

A credentialed Remote OCI/Docker repository authenticates to its upstream with
the OCI token flow: the registry answers `401` with
`WWW-Authenticate: Bearer realm="<token endpoint>",service=...,scope=...`, and
Artifact Keeper asks that token endpoint for a short-lived bearer token.

The `realm` is chosen by the upstream, so since GHSA-78h6-3wp8-2542 the
configured upstream credentials are only sent to a realm on the **same origin**
(scheme, host and port) as the configured `upstream_url`. A realm on any other
origin gets an anonymous token request, and this is logged:

```text
WARN OCI bearer realm is a different origin than the configured upstream; requesting the token WITHOUT the upstream's Basic credentials (GHSA-78h6-3wp8-2542) ...
```

Some registries serve their token endpoint from a different host, so this rule
blocks them from authenticating. For those, a repository administrator can list
the token service's origin in the repository's `oci_trusted_bearer_realms`
(#3591). The credentials are then also sent to a realm whose origin matches an
entry exactly.

## Common configurations

| Upstream | `upstream_url` | `oci_trusted_bearer_realms` |
| --- | --- | --- |
| Docker Hub, private images or authenticated rate limits | `https://registry-1.docker.io` | `["https://auth.docker.io"]` |
| GitLab with a separate registry host | `https://registry.example.com` | `["https://gitlab.example.com"]` |

Nothing is trusted unless you configure it. That includes the Docker Hub pair:
without the entry, a credentialed Docker Hub remote still requests tokens
anonymously. For a credentialed Docker Hub remote, add
`"oci_trusted_bearer_realms": ["https://auth.docker.io"]`:

```bash
curl -X PATCH "$AK/api/v1/repositories/dockerhub" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"oci_trusted_bearer_realms": ["https://auth.docker.io"]}'
```

The same field is accepted on `POST /api/v1/repositories` and returned by
`GET /api/v1/repositories/{key}` when set. On update, leaving the field out
keeps the current list and `[]` clears it.

## Rules

Each entry is checked when it is written:

- It must use `https`. Credentials are never sent to a cross-origin realm over
  plain HTTP, and a realm that downgrades to `http` never matches.
- It must be an origin, `https://host[:port]`, with no path, query, fragment or
  `user:pass@`. Stored entries are normalized: the host is lowercased and the
  default port 443 is dropped.
- Wildcards and suffix matches are not supported. `https://example.com` does not
  trust `https://auth.example.com`, and `https://auth.docker.io` does not trust
  `https://auth.docker.io.attacker.example`.
- It goes through the same SSRF validation as upstream URLs. Private addresses
  are rejected by default; `UPSTREAM_ALLOW_PRIVATE_IPS` and
  `AK_SSRF_ALLOW_PRIVATE_CIDRS` relax that exactly as they do for upstream
  URLs. Loopback, link-local and cloud-metadata addresses are always rejected.
  This check runs when the list is written. The realm the registry sends is
  also SSRF-validated on every token request.
- Only Remote repositories accept the field, with at most 16 entries.
- Writing it needs the same permission as other repository settings: repository
  `admin` on update, and repository-creation rights on create.
