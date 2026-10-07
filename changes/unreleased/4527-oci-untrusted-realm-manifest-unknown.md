---
section: Fixed
issues: [#4527]
---
- **A credentialed OCI Remote whose bearer realm is not trusted reports a missing image as `MANIFEST_UNKNOWN` again, not as rejected credentials** (#4527). Such a Remote never sends its credentials to the cross-origin token service (#3591), so the token is anonymous, and the registry refusing it (Docker Hub answers 401 for an image that does not exist) said nothing about the credentials. Since #4453 / #4518 it was nevertheless reported as `502 DENIED` with a `security` warning. Now `502 DENIED` and the warning apply only when credentials were actually sent to the token service or the registry; otherwise the pull answers `404 MANIFEST_UNKNOWN` and the refusal is logged at INFO. The `security` warning that credentials were withheld from an untrusted realm (#3591), which fired on every pull, is now logged at most once a minute per Remote with a count of the suppressed ones.
