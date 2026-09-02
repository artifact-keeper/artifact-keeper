# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (development) | Yes |
| Latest release tag | Yes |
| Older releases | No |

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability, please report it responsibly through one of these channels:

### Preferred: GitHub Private Vulnerability Reporting

Use GitHub's built-in private reporting to create a confidential advisory visible only to maintainers:

**[Report a vulnerability](https://github.com/artifact-keeper/artifact-keeper/security/advisories/new)**

### Alternative: Email

Send details to **support@artifactkeeper.com**. If possible, include:

- Description of the vulnerability
- Steps to reproduce
- Affected components (backend API, auth, storage, specific format handler, etc.)
- Potential impact assessment
- Suggested fix or patch, if available

## What to Expect

- **Acknowledgment** within 72 hours of your report
- **Initial assessment** within 1 week
- **Fix timeline** depends on severity — critical issues are prioritized immediately

We will coordinate disclosure with you and credit reporters in the release notes (unless you prefer to remain anonymous).

## Scope

### In scope

- Backend API server (`artifact-keeper/`)
- Authentication and authorization (JWT, API keys, OIDC, LDAP, SAML)
- Package format handlers (upload, download, proxy)
- Storage backends (filesystem, S3)
- gRPC services
- Web frontend (`artifact-keeper-web/`)
- Docker images published to `ghcr.io`

### Out of scope

- Demo instance at `demo.artifactkeeper.com` (report issues, but no bounties)
- Example WASM plugin template (`artifact-keeper-example-plugin/`)
- Third-party dependencies (report upstream, but let us know if it affects us)

## Verifying a release

Every release published from `v1.8.2` onward is signed, carries build
provenance, and ships a software bill of materials. Verify before you run it.

### What ships, and what each file proves

| Asset | What it is |
|-------|------------|
| `artifact-keeper-<os>-<arch>.tar.gz` / `.exe` | the binary |
| `artifact-keeper-<os>-<arch>.tar.gz.sha256` | per-file digest, kept for compatibility |
| `checksums.txt` | one manifest covering **every** asset on the release |
| `checksums.txt.cosign.bundle` | the [Sigstore](https://www.sigstore.dev/) keyless signature over `checksums.txt` |
| `artifact-keeper-<os>-<arch>.cdx.json` | CycloneDX SBOM for that target |

A `.sha256` file on its own proves only that your download was not corrupted in
transit. It is served from the same place, by the same authority, as the
artifact it describes — anyone who can replace the tarball can replace its
checksum in the same action. **`checksums.txt` plus its cosign signature is what
proves the bytes came from us**, which is why the manifest, and not the
individual digests, is the thing that is signed.

### 1. Download

```sh
VERSION=1.8.2
gh release download "v${VERSION}" --repo artifact-keeper/artifact-keeper
```

### 2. Verify the signature on `checksums.txt`

Requires [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
v2.4 or later (v3.x recommended).

```sh
# The certificate identity contains dots, which are regex metacharacters.
IDENTITY="^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/release\.yml@refs/tags/v${VERSION//./\\.}$"

cosign verify-blob \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

For `v1.8.2` that expands to, in full:

```
^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/release\.yml@refs/tags/v1\.8\.2$
```

**Do not relax that pattern.** Sigstore's Fulcio is a public CA: it will issue a
certificate to anybody's GitHub Actions workflow. `--certificate-identity-regexp
'.*'` satisfies cosign's "you must constrain the identity" requirement and
constrains nothing — it accepts a signature made by any workflow, in any
repository, in the world. The three things worth pinning are all in the pattern
above: the repository, the workflow file, and the tag.

### 3. Verify the artifacts against the manifest

The signature covers `checksums.txt`. Only this step connects `checksums.txt`
to the files you actually downloaded, so it is not optional:

```sh
sha256sum -c checksums.txt
```

### 4. Verify build provenance

Requires the [GitHub CLI](https://cli.github.com/) (`gh` 2.49+):

```sh
gh attestation verify artifact-keeper-linux-amd64.tar.gz \
  --repo artifact-keeper/artifact-keeper \
  --signer-workflow artifact-keeper/artifact-keeper/.github/workflows/release.yml
```

`--signer-workflow` is worth including. Without it, `--repo` alone accepts an
attestation produced by any workflow in this repository that can write one, and
several can.

### 5. Inspect the dependency graph

The release binaries are built with
[`cargo auditable`](https://github.com/rust-secure-code/cargo-auditable), so the
exact set of crates that went into them is embedded in the binary itself. You do
not have to trust that an SBOM file shipped alongside describes the binary next
to it — you can ask the binary:

```sh
tar -xzf artifact-keeper-linux-amd64.tar.gz
cargo audit bin artifact-keeper-linux-amd64
```

Note that `cargo audit bin` **exits 0 on a binary with no embedded data**: it
falls back to recovering a partial list from panic messages and says so in a
warning. Read the output, not just the exit code. It should say
`Found 'cargo auditable' data`. The same data is readable by
[trivy](https://github.com/aquasecurity/trivy), [grype](https://github.com/anchore/grype)
and [syft](https://github.com/anchore/syft).

The `.cdx.json` files are the same information as a standalone CycloneDX
document, per target, for tooling that wants an SBOM as a file. They are covered
by `checksums.txt` and by the provenance attestation.

### Container images

Images published to `ghcr.io` have carried cosign signatures, an SBOM
attestation and build provenance for longer; see the image documentation for
the equivalent `cosign verify` and `gh attestation verify` invocations.

## Security Best Practices for Operators

- Always run behind a reverse proxy with TLS
- Use strong, unique values for `JWT_SECRET` and `CREDENTIAL_ENCRYPTION_KEY`
- Enable rate limiting in production
- Regularly rotate API keys and signing keys
- Keep your instance updated to the latest release

### JWT secret strength and rotation

`JWT_SECRET` signs every access token. A weak, low-entropy, or default value
lets an attacker forge tokens if it ever leaks, so treat it like a private key:

- **Generate a strong random secret** — at least 32 characters of high entropy:

  ```sh
  openssl rand -base64 48
  ```

- **Never ship a placeholder.** Values like `change-me`, `secret`, or
  `dev-secret` are rejected outright when `ENVIRONMENT=production`. In
  non-production environments the same weaknesses (too short, known placeholder,
  or low entropy) are tolerated but logged as a startup `WARN` — check your logs
  and replace the secret before promoting the deployment to production.

- **Rotate periodically and after any suspected exposure.** Rotating
  `JWT_SECRET` invalidates all outstanding tokens, forcing re-authentication;
  schedule rotations during a low-traffic window and roll the new value out to
  every backend replica at once.

### SSO group mapping trusts the IdP group taxonomy

The optional `map_groups_to_groups` setting on an OIDC or SAML provider
reflects the group names supplied by the identity provider into Artifact
Keeper group memberships (groups are found-or-created **by name** on first
sight). This is convenient for centralizing group management in the IdP, but
it has a security implication operators must understand before enabling it:

**When `map_groups_to_groups` is on, the IdP effectively controls membership
of any local group whose name collides with an IdP-supplied group name.** If a
privileged local group (for example one used to grant elevated repository
permissions, or a group referenced elsewhere in your authorization policy)
shares a name with a group the IdP can emit, then anyone the IdP places in
that group is joined into the privileged local group on login. In other words,
enabling this setting means you are **trusting the IdP's group taxonomy** — and
anyone who can influence group assignment in the IdP — for the membership of
those local groups.

Note that a mapped group membership persists after login: reconciliation is
scoped to the mapping source (e.g. it only prunes memberships tagged
`external_source = 'saml'`), so a membership added because of a name collision
is not automatically removed and must be cleaned up by an operator.

This does **not** grant the `is_admin` flag — administrator status is conferred
only through a provider's dedicated `admin_group` setting, not through general
group mapping. The risk is scoped to whatever any collision-shadowed local
group is authorized to do.

**Recommended mitigations:**

- **Review the IdP group taxonomy before enabling** `map_groups_to_groups`,
  and confirm no IdP-emittable group name collides with a privileged or
  policy-referenced local group.
- **Name privileged local groups so they can't be shadowed** by an
  IdP-supplied name — for example reserve an operator-only naming convention
  (such as an `ak-` / `local-` prefix) for groups that carry elevated
  permissions, and never use those names in the IdP.
- **Namespace / prefix mapped groups** where your IdP or mapping supports it,
  so IdP-sourced groups land in a distinct namespace and can never coincide
  with a locally managed privileged group.
- **Keep group-to-permission grants least-privilege**, so that even an
  unexpected membership has limited blast radius.
- Restrict who can create or assign groups in the IdP, since with this setting
  enabled that control governs Artifact Keeper group membership too.
