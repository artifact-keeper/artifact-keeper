# Hosted Terraform / OpenTofu provider registry

A hosted (`repo_type: local`) Terraform repository is a complete **origin
provider registry**: `tofu init` / `terraform init` / `tofu providers lock`
can resolve, download and authenticate providers straight from it with a plain
`direct {}` installation method. No `network_mirror` block and no gateway
rewrite are required.

The existing per-repository routes and the network-mirror endpoints are
unchanged.

## Routes

| Route | Purpose |
|-------|---------|
| `GET /.well-known/terraform.json` | Host-level service discovery (see below). Only served when `TERRAFORM_DEFAULT_REPO` is set. |
| `GET /terraform/{repo}/.well-known/terraform.json` | Per-repository service discovery (unchanged). |
| `GET /terraform/{repo}/v1/providers/{ns}/{type}/versions` | Version list. |
| `GET /terraform/{repo}/v1/providers/{ns}/{type}/{version}/download/{os}/{arch}` | Package document. |
| `GET /terraform/{repo}/v1/providers/{ns}/{type}/{version}/SHA256SUMS` | Checksum document (hosted repos). |
| `GET /terraform/{repo}/v1/providers/{ns}/{type}/{version}/SHA256SUMS.sig` | Binary (non-armored) detached OpenPGP signature of the checksum document, `application/pgp-signature` (hosted repos). The public key in the package document is ASCII-armored. |
| `PUT /terraform/{repo}/v1/providers/{ns}/{type}/{version}/{os}/{arch}` | Upload a provider ZIP. |

## Checksums and signatures

OpenTofu/Terraform do not trust the `shasum` field of the package document on
its own. They download a `SHA256SUMS` file, require it to contain the archive
filename, and verify a detached OpenPGP signature of that file against a key
listed in `signing_keys.gpg_public_keys`.

For a hosted repository that has a signing key configured, the package document
therefore carries `shasums_url`, `shasums_signature_url` and the repository
public key (`key_id` and `ascii_armor`).

`SHA256SUMS` is computed from the artifacts stored for that version, so
providers uploaded before this feature work with no re-upload:

```text
<sha256>  terraform-provider-<type>_<version>_<os>_<arch>.zip
```

One line per published platform, lowercase hex, sorted by filename, a single
trailing newline. The bytes are deterministic for a given set of artifacts.
`SHA256SUMS.sig` is a fresh signature over those bytes on each request (an
OpenPGP signature embeds its creation time), and every one verifies.

### Signing key: fail closed, never auto-provisioned

The registry reuses the repository signing infrastructure that also signs
RPM and Debian metadata (`/api/v1/signing`). It uses the repository's active
key (a key assigned to the repository with `sign_metadata: true`). The private
key is only ever decrypted in memory to sign; it is never logged or returned.

- **No signing key configured:** the `SHA256SUMS` and `SHA256SUMS.sig` routes
  return `404` and the package document keeps its previous shape (no
  `shasums_url`, empty `gpg_public_keys`), so nothing that worked before
  changes. OpenTofu cannot authenticate such a provider from the origin and
  `init` fails with a checksum error until a key is configured.
- **Key is not an OpenPGP (`gpg`) key:** both routes return `409`.

Keys are not auto-provisioned: the key identity and its rotation belong to the
operator, and an unattended key would be trusted by every client that pins it.

Set up a key once per repository:

```sh
# 1. create a gpg key for the repository
curl -u "$AK_USER:$AK_PASSWORD" -H 'Content-Type: application/json' \
  -d '{"repository_id":"<repo-uuid>","name":"terraform-signing","key_type":"gpg","algorithm":"rsa2048","uid_name":"Example Registry","uid_email":"registry@example.com"}' \
  "$AK_URL/api/v1/signing/keys"

# 2. make it the repository's metadata signing key
curl -u "$AK_USER:$AK_PASSWORD" -H 'Content-Type: application/json' \
  -d '{"signing_key_id":"<key-uuid>","sign_metadata":true,"sign_packages":false,"require_signatures":false}' \
  "$AK_URL/api/v1/signing/repositories/<repo-uuid>/config"
```

Rotating the key changes `signing_keys` immediately; clients that already have
the previous key in a lock file keep the `zh:` hashes, which do not depend on the
key.

## Protocols

The package and version documents advertise the plugin protocol versions the
provider supports. They are taken, in order, from:

1. the `X-Terraform-Protocols` header on upload (comma-separated, e.g.
   `5.0,6.0`; a malformed value is rejected with `400`);
2. `metadata.protocol_versions` of a `terraform-registry-manifest.json` inside
   the uploaded ZIP (the file `terraform-plugin-framework` providers already
   ship; a best-effort read, ignored if missing, oversized or malformed);
3. the default `["5.0"]`.

Only explicitly known values are stored; earlier uploads keep `["5.0"]`. The
version list advertises the union across the platforms of a version.

## Host-level service discovery

Terraform and OpenTofu look for `https://<host>/.well-known/terraform.json`
when resolving a provider source address `<host>/<namespace>/<type>`. Discovery
is per host, and Artifact Keeper serves many repositories, so it must be told
which one answers for the host root.

Set `TERRAFORM_DEFAULT_REPO` to the key of a Terraform repository:

```sh
TERRAFORM_DEFAULT_REPO=terraform-providers
```

`GET /.well-known/terraform.json` then returns

```json
{"providers.v1": "/terraform/terraform-providers/v1/providers/"}
```

and a provider source of `artifacts.example.com/<ns>/<type>` resolves against
that repository. When the variable is unset, or the repository does not exist
or is not a Terraform repository, the endpoint returns an identical generic
`404` (so it cannot be used to probe repository names). The endpoint is
public, like other discovery documents, because clients request it before
sending credentials; it only reveals the mount point. Package downloads and
uploads still follow the repository's normal visibility and authentication
rules.

### Reverse proxy / gateway note

The proxy in front of Artifact Keeper must forward this one path to the
backend. A typical nginx rule:

```nginx
location = /.well-known/terraform.json { proxy_pass http://artifact-keeper-backend; }
```

For an ingress/gateway, route the exact path `/.well-known/terraform.json` to
the backend service in the same way as `/terraform/`. The bundled Helm chart
does not define an Ingress, so no chart change is needed.

### Alternatives considered

- **Namespace-to-repo mapping on a host-level path** (e.g.
  `/v1/providers/{ns}/{type}/...`): needs a namespace registry, risks
  collisions between repositories, and adds many new host-level routes.
- **Hostname-to-repository map:** more configuration, and Artifact Keeper is
  usually served from one host.
- **Gateway rewrite:** what this feature removes the need for.

A single configured default repository is the least invasive: one new route,
off unless configured, no change to existing routes.

## Client configuration

```hcl
terraform {
  required_providers {
    contrail = { source = "artifacts.example.com/ns/contrail" }
  }
}
```

No `provider_installation` override is needed. Verify with
`tofu providers lock -platform=linux_amd64`.
