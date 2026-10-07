---
section: Security
issues: [#4503]
---
- **A rejected `S3_PUBLIC_ENDPOINT` or `AZURE_STORAGE_PUBLIC_ENDPOINT` no longer writes its credentials to the log** (#4503). A public endpoint that carries `user:password@` is refused at startup, but the error printed the value verbatim, so the credentials it was refused for ended up in the fatal startup error (primary backend) or the `Additional ... storage backend skipped` WARN (secondary backend). The value is now shown with everything between `scheme://` and its last `@` replaced by `***` (for example `http://***@192.168.42.150:32613`), whatever the reason it was rejected. This also covers a password pasted without percent-encoding that contains `/`, `?`, `#` or `\`, which ends the URL's authority early. Rotate any credentials that were logged this way.
