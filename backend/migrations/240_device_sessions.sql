-- Device Authorization Grant (RFC 8628, #3461).
--
-- One row per device authorization. Both codes are bearer secrets, so only
-- their SHA-256 digests are stored: a database read does not yield a device
-- code that could be redeemed, or a user code that could be approved.
--
-- Lifecycle (enforced by the conditional UPDATEs in device_service.rs and by
-- the CHECKs below):
--   pending  -> approved -> consumed   (single redemption)
--   pending  -> denied
-- Rows past expires_at are deleted by the 60-second sweep in routes.rs.
CREATE TABLE IF NOT EXISTS device_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash TEXT NOT NULL UNIQUE,
    user_code_hash TEXT NOT NULL UNIQUE,
    -- Unregistered, client-chosen label. Never rendered to the approving
    -- user; kept for binding the token request to the device request and for
    -- the audit trail.
    client_id TEXT NOT NULL
        CHECK (char_length(client_id) BETWEEN 1 AND 128),
    requested_scopes TEXT[] NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    -- The user who approved or denied. Deleting the user deletes the row, so
    -- an approval can never be redeemed for an account that no longer exists.
    decided_by_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    -- Scopes actually granted: requested_scopes capped by the approver.
    granted_scopes TEXT[],
    -- Repository allow-list inherited from the approver (NULL = unrestricted).
    allowed_repo_ids UUID[],
    interval_secs INTEGER NOT NULL
        CHECK (interval_secs BETWEEN 1 AND 300),
    expires_at TIMESTAMPTZ NOT NULL,
    last_polled_at TIMESTAMPTZ,
    poll_count INTEGER NOT NULL DEFAULT 0,
    decided_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT device_sessions_decision_recorded CHECK (
        status = 'pending'
        OR (decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT device_sessions_grant_recorded CHECK (
        status NOT IN ('approved', 'consumed') OR granted_scopes IS NOT NULL
    ),
    CONSTRAINT device_sessions_consumed_at CHECK (
        (status = 'consumed') = (consumed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_device_sessions_expires_at
    ON device_sessions (expires_at);
