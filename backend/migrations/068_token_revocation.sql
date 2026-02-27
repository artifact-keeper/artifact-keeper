ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS last_used_ip TEXT;
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS last_used_user_agent TEXT;

CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked ON api_tokens (revoked_at) WHERE revoked_at IS NOT NULL;

COMMENT ON COLUMN api_tokens.revoked_at IS 'When the token was revoked. NULL = active.';
COMMENT ON COLUMN api_tokens.last_used_ip IS 'IP address of the last request using this token.';
COMMENT ON COLUMN api_tokens.last_used_user_agent IS 'User-Agent header of the last request using this token.';
