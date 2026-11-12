---
section: Fixed
issues: [#5825]
---
- **The webhook retry claim tests no longer miss their fixture deliveries on a busy test database** ([#5825]). The `retry_claim_tests` helpers and the round-robin fairness test claimed through the instance-wide fair claim batch, which other webhooks' due rows could fill on every pass, so `expired_webhook_claim_recovers_and_fences_stale_owner`, `retry_worker_sends_webhook_bound_v2_verifiable_against_jwks` and `claim_is_round_robin_across_webhooks_not_oldest_first` could fail. They now claim through the same claim statement restricted to their own webhooks. Test-only change; production claims are unchanged.
