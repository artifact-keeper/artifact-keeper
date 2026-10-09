---
section: Added
issues: [#4591]
---
- **`SMTP_TLS_MODE=starttls-opportunistic` upgrades with STARTTLS when the server offers it and sends unencrypted when it does not** (#4591). This is how Forgejo's `smtp+starttls` and Nexus (JavaMail's `mail.smtp.starttls.enable`) behave, which is why the same mail server can work for them and fail for Artifact Keeper with `STARTTLS is not supported on this server`: Artifact Keeper's `starttls` mode requires STARTTLS, and still does. In the new mode a STARTTLS that is offered but fails (for example on an untrusted certificate) is an error, not a silent fallback to plaintext. Credentials sent after a fallback travel unencrypted, so prefer `starttls` or `tls` wherever the server supports them.
