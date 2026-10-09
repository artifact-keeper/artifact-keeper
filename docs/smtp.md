# SMTP: TLS modes, private CAs, and Microsoft Exchange

Artifact Keeper sends mail (notifications, password expiry, the admin test
message) through one SMTP server configured by environment variables. This
page covers how the TLS settings behave and how to read a failure, with the
Exchange cases from #4591 / discussion #4244 as the worked example.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SMTP_HOST` | unset (mail disabled) | Server name. Also the name the TLS certificate is checked against. |
| `SMTP_PORT` | `587` | Port. |
| `SMTP_TLS_MODE` | `starttls` | `starttls`: connect in plaintext and upgrade with STARTTLS; fail if the server does not offer it. `starttls-opportunistic`: upgrade when offered, otherwise continue unencrypted (Forgejo's `smtp+starttls` and Nexus/JavaMail's "enable STARTTLS" behave this way). `tls`: TLS from the first byte (SMTPS, usually port 465). `none`: plaintext only. |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | unset | Both set: authenticate with AUTH PLAIN or LOGIN. Either unset: send without authenticating (anonymous relay). |
| `SMTP_TLS_CA_CERT` | unset | Extra CA certificate(s) to trust for the SMTP server: a PEM file path, or the PEM text itself. Added to the system trust store. |
| `CUSTOM_CA_CERT_PATH` | unset | The shared CA file used by the outbound HTTP clients. SMTP uses it too when `SMTP_TLS_CA_CERT` is unset. |
| `SMTP_TLS_SKIP_VERIFY` | `false` | `true` accepts any certificate and hostname. Logged as a warning at startup. Testing only: anyone on the network path can then read the SMTP password and the mail. |
| `SMTP_FROM_ADDRESS` | `noreply@artifact-keeper.local` | Sender address. |

In `starttls-opportunistic`, a STARTTLS that the server offers but that then
fails (an untrusted certificate, for example) is an error, not a quiet
fallback to plaintext. Only a server that does not advertise STARTTLS at all
gets an unencrypted session.

### Trusting a private CA

The TLS stack is OpenSSL (lettre with native-tls), so there are three ways to
make a certificate from an internal CA verify:

1. `SMTP_TLS_CA_CERT=/path/to/ca.pem` (or `CUSTOM_CA_CERT_PATH`, which also
   covers the HTTP clients).
2. Without any SMTP setting: `SSL_CERT_FILE` pointing at a PEM bundle that
   includes the CA. OpenSSL reads it in place of the system bundle, so the
   bundle must also contain any public CAs you still need.
3. Without any setting: replace the system bundle. In the UBI-based image
   that is `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` (the image
   runs as a non-root user without `update-ca-trust`, so mount a prepared
   bundle over that file).

Options 2 and 3 were checked against the published UBI image with STARTTLS
to a server whose certificate came from a private CA
(`scripts/native-tests/test-smtp-matrix.sh`, cells `sslcertfile` and
`systemstore`).

## Testing the configuration

`POST /api/v1/admin/smtp/test` with `{"to": "you@example.com"}` (also
behind the web UI's test-email button) sends a test message. When delivery fails it answers
`502` with three parts:

- the error from the SMTP library,
- `server advertised ...`: what the server offered in EHLO before and after
  STARTTLS, from a second connection that sends no credentials and no mail,
- `hint: ...`: the setting most likely to fix it.

Each delivery is limited to 60 seconds, so a mismatched port fails with
`no SMTP reply within 60s` instead of hanging.

## Exchange

On-prem Exchange receive connectors differ from most mail servers in two
ways that matter here:

- **Basic authentication is offered only after TLS.** By default the
  "Client Frontend" connector (port 587) advertises `AUTH NTLM GSSAPI` in
  plaintext and adds `LOGIN` only after STARTTLS. Artifact Keeper
  authenticates with PLAIN or LOGIN; it does not implement NTLM or GSSAPI.
- **Relay connectors often have TLS off.** A connector created for
  application relay frequently does not advertise STARTTLS and accepts mail
  from listed IP addresses without authentication.

What each message means:

| Message | Server shape that produces it | What to change |
|---|---|---|
| `internal client error: No compatible authentication mechanism was found` | Username and password are set, and the server offered no PLAIN or LOGIN on the connection Artifact Keeper used. With `SMTP_TLS_MODE=none` against Exchange: only `AUTH NTLM GSSAPI` before TLS. | Use `SMTP_TLS_MODE=starttls` so LOGIN is offered. If the connector only relays anonymously, unset `SMTP_USERNAME` and `SMTP_PASSWORD`. |
| `internal client error: STARTTLS is not supported on this server` | `SMTP_TLS_MODE=starttls` and the server did not advertise STARTTLS on that port (a connector with TLS disabled, or the wrong port). | Use the port where the connector has TLS, `SMTP_TLS_MODE=tls` on an implicit-TLS port (465), or `SMTP_TLS_MODE=starttls-opportunistic` to send unencrypted to that connector. |
| `permanent error (535): 5.7.3 Authentication unsuccessful` | STARTTLS worked and the server rejected the credentials. | Check that SMTP AUTH is allowed for the mailbox and on the connector, and try the username as `DOMAIN\user` and as the UPN (`user@domain`). |
| `permanent error (530): 5.7.1 Client was not authenticated` | No credentials were sent, and the connector requires authentication. | Set `SMTP_USERNAME` and `SMTP_PASSWORD`, or allow the Artifact Keeper host on a relay connector. |
| `Connection error: ... certificate verify failed (unable to get local issuer certificate)` | The certificate is from a CA the backend does not trust. | `SMTP_TLS_CA_CERT`, `CUSTOM_CA_CERT_PATH`, or one of the zero-config options above. |
| `Connection error: ... wrong version number` | `SMTP_TLS_MODE=tls` against a port that starts in plaintext. | `SMTP_TLS_MODE=starttls` (or the implicit-TLS port). |

Why another tool may work against the same connector: Forgejo's
`smtp+starttls` falls back to plaintext when STARTTLS is not offered, can
authenticate with NTLM, and skips authentication when it recognises none of
the offered mechanisms (`services/mailer/mailer.go`). JavaMail, which Nexus
uses, also falls back when STARTTLS is merely enabled rather than required,
and supports NTLM. Against a relay connector without TLS, those tools end up
relaying anonymously or with NTLM in plaintext; the equivalent Artifact
Keeper configuration is `SMTP_TLS_MODE=starttls-opportunistic` (or `none`)
with `SMTP_USERNAME` and `SMTP_PASSWORD` unset.

## Regression matrix

`scripts/native-tests/test-smtp-matrix.sh` runs the test endpoint against
real servers in containers (Mailpit for implicit TLS, required STARTTLS and
plaintext; a small aiosmtpd server for the Exchange-like shapes above, a
connector without STARTTLS, and a private-CA certificate) under every
`SMTP_TLS_MODE`, with and without credentials, and asserts delivery or the
expected error class. Run it with `AK_BIN=<backend binary>` or
`AK_IMAGE=<backend image>`; it skips when no container runtime is available.
