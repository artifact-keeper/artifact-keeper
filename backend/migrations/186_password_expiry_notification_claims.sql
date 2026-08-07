-- Claim password-expiry notifications before SMTP instead of recording the
-- deduplication row only after a successful send. Existing rows represent
-- completed sends, so the 'sent' default is the correct backfill.
ALTER TABLE password_expiry_notifications
    ADD COLUMN status TEXT NOT NULL DEFAULT 'sent'
        CHECK (status IN ('claimed', 'sent', 'failed')),
    ADD COLUMN claimed_by TEXT,
    ADD COLUMN claim_token UUID,
    ADD COLUMN claimed_at TIMESTAMPTZ,
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD COLUMN last_error TEXT;

ALTER TABLE password_expiry_notifications
    ALTER COLUMN sent_at DROP DEFAULT,
    ALTER COLUMN sent_at DROP NOT NULL;

ALTER TABLE password_expiry_notifications
    ADD CONSTRAINT password_expiry_notifications_state CHECK (
        (status = 'sent'
            AND sent_at IS NOT NULL
            AND claim_token IS NULL
            AND claim_expires_at IS NULL)
        OR
        (status = 'claimed'
            AND sent_at IS NULL
            AND claimed_by IS NOT NULL
            AND claim_token IS NOT NULL
            AND claimed_at IS NOT NULL
            AND claim_expires_at IS NOT NULL)
        OR
        (status = 'failed'
            AND sent_at IS NULL
            AND claim_token IS NULL
            AND claim_expires_at IS NOT NULL)
    );

CREATE INDEX idx_password_expiry_notifications_retry
    ON password_expiry_notifications (claim_expires_at)
    WHERE status IN ('claimed', 'failed');

COMMENT ON COLUMN password_expiry_notifications.status IS
    'claimed = SMTP attempt in flight; sent = terminal; failed = retryable after claim_expires_at';
COMMENT ON COLUMN password_expiry_notifications.claim_expires_at IS
    'Claim expiry while claimed; retry-not-before timestamp while failed';
COMMENT ON COLUMN password_expiry_notifications.claim_token IS
    'Random ownership proof required by sent/failed transitions while claimed';
