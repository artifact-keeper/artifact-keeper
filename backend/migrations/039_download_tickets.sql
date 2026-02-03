CREATE TABLE IF NOT EXISTS download_tickets (
    ticket VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    purpose VARCHAR(50) NOT NULL,
    resource_path TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 seconds'
);
CREATE INDEX IF NOT EXISTS idx_download_tickets_expires ON download_tickets(expires_at);
