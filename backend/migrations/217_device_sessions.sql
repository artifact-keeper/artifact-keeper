CREATE TABLE IF NOT EXISTS device_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code TEXT NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    verification_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    interval_secs INTEGER NOT NULL DEFAULT 5,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    scopes TEXT[] NOT NULL DEFAULT '{}',
    client_id TEXT NOT NULL,
    approved_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    allowed_repo_ids UUID[],
    consumed_at TIMESTAMPTZ,
    last_polled_at TIMESTAMPTZ,
    poll_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS device_sessions_expires_at_idx
    ON device_sessions (expires_at);
