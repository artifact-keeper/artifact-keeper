-- Atomic multi-replica claims for webhook retry deliveries (RowClaimedQueue).
--
-- The retry processor used to SELECT due rows (`next_retry_at <= NOW()`),
-- POST the webhook, and only then update the row, so with N replicas one
-- failed delivery could be re-POSTed N times per retry tick. Due rows are now
-- claimed with FOR UPDATE SKIP LOCKED before the send; result updates must
-- present the claim_token.
--
-- The claim is expressed through claim_expires_at (in-flight = unexpired
-- claim) rather than a new status enum: `success`/`attempts`/`next_retry_at`
-- keep their existing meanings, and a crashed replica's claim simply expires,
-- making the delivery due again.
ALTER TABLE webhook_deliveries
    ADD COLUMN claimed_by TEXT,
    ADD COLUMN claim_token UUID,
    ADD COLUMN claim_expires_at TIMESTAMPTZ;

COMMENT ON COLUMN webhook_deliveries.claimed_by IS
    'Diagnostic worker identity that claimed the retry; not the correctness guard';
COMMENT ON COLUMN webhook_deliveries.claim_token IS
    'Random per-claim token; delivery-result updates must match it';
COMMENT ON COLUMN webhook_deliveries.claim_expires_at IS
    'Retry-claim lease deadline; an expired claim makes the delivery due again';
