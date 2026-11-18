---
section: Security
issues: [#6205]
---
- **lettre moves to 0.11.24 for RUSTSEC-2026-0560 to 0565** (#6205). The SMTP client no longer reads forged replies sent before the STARTTLS handshake, dot-stuffs bodies with bare CR or LF line endings, keeps a quoted local part in the envelope address, bounds SMTP reply buffering and no longer panics on a blank `EHLO` line or a CR or LF in a display name
