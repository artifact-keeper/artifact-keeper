ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 5;

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_retry
  ON webhook_deliveries (next_retry_at)
  WHERE success = false AND attempts < max_attempts AND next_retry_at IS NOT NULL;

COMMENT ON COLUMN webhook_deliveries.next_retry_at IS 'When to next attempt delivery. NULL = no more retries.';
COMMENT ON COLUMN webhook_deliveries.max_attempts IS 'Maximum delivery attempts (default 5).';
