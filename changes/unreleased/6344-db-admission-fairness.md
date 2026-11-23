---
section: Changed
issues: [#6344, #4182]
---
- **An anonymous flood no longer gets authenticated requests shed by the database admission gate: a quarter of the slots is kept for requests that present a credential, and a client at its share yields to a waiting one** (#6344, #4182). The gate added in 1.13 handed slots to whoever arrived first, before authentication. One anonymous flood, from a single IP or a misbehaving CI job, could hold every slot, and every other client got `503 POOL_EXHAUSTED` while making up a tiny share of the load.

  Both rules apply only while the request pool is busy. Nothing changes while it has room, and the gate still does no database work before authentication.
  - **Reserved share.** `DATABASE_REQUEST_CREDENTIALED_RESERVE_PERCENT` (default 25) of the slots can only be taken by a request with an `Authorization` header, `X-API-Key`, `X-NuGet-ApiKey`, the session cookie or a `/t/<token>/` path. The credential is a hint, not a check: a forged header is still answered 401, and one address can hold at most its per-client share of the slots while others wait. A forged-header flood from many addresses can still fill the reserve, which leaves credentialed clients where they were before.
  - **Per-client share.** A client, keyed by best-effort client IP as for rate limiting (IPv6 by /64), that already holds or waits for `DATABASE_REQUEST_CLIENT_SHARE_PERCENT` (default 25) of the slots is shed at once while another client waits. A client alone on a busy pool is not limited.

  Sheds are also counted by `class` and `reason` in the new `ak_db_admission_sheds_total`. Default change: under saturation anonymous requests share 75% of the slots. Set both variables to `0` for first-come, first-served slots. See `docs/operations/load-shedding.md`.
