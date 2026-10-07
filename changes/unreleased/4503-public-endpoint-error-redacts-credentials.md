---
section: Security
issues: [#4503]
---
- **A rejected `S3_PUBLIC_ENDPOINT` or `AZURE_STORAGE_PUBLIC_ENDPOINT` no longer writes its credentials to the log** (#4503). A public endpoint that carries `user:password@` is refused at startup, but the error printed the value verbatim, so the credentials it was refused for ended up in the fatal startup error (primary backend) or the `Additional ... storage backend skipped` WARN (secondary backend). The value is now shown with its userinfo replaced by `***` (for example `http://***@192.168.42.150:32613`), for every reason a public endpoint can be rejected. Rotate any credentials that were logged this way.
