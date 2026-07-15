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
