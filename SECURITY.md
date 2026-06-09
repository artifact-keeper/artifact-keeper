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
