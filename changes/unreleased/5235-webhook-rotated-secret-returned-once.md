---
section: Fixed
issues: [#5235]
---
- **`POST /api/v1/webhooks/{id}/rotate-secret` now returns the new signing secret, once, so a rotated webhook stays verifiable** (#5235). The endpoint described the new secret as delivered out-of-band, but no route returned it: a receiver could only verify with the previous secret, and when the 24-hour overlap ended it could not verify at all unless the webhook was recreated. The 200 response now adds a `secret` field, sent with `Cache-Control: no-store`, the same contract `POST /api/v1/webhooks` has at create. Capture it from that response. It is stored only encrypted and no later call returns it: `GET` and `LIST` still expose only `secret_digest`, a repeat rotation inside the window still answers 409 without it, and it is not written to the audit log or to request logs. If the response is lost, the previous secret keeps verifying until the overlap ends, and a new rotation is accepted after that; to get a new secret sooner, delete and recreate the webhook.

  The admin requirement from GHSA-qcmj stays: non-admin callers and admin-owned tokens without the `admin` scope get 403. Rotation also takes the same token-scope check as `GET`, so a credential gets a secret only for a webhook it can read; any other webhook answers 404 and is not rotated.
