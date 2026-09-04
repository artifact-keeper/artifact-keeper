CREATE TABLE oidc_device_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id     UUID NOT NULL REFERENCES oidc_configs(id) ON DELETE CASCADE,
    device_code     TEXT NOT NULL UNIQUE,
    user_code       TEXT NOT NULL UNIQUE,
    verification_uri TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    interval_secs   INTEGER NOT NULL DEFAULT 5,
    status          TEXT NOT NULL DEFAULT 'pending',
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    client_id       TEXT NOT NULL,
    oidc_user_sub   TEXT,
    oidc_user_email TEXT,
    oidc_user_name  TEXT,
    approved_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    last_polled_at  TIMESTAMPTZ,
    poll_count      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON oidc_device_sessions (user_code);
CREATE INDEX ON oidc_device_sessions (expires_at);
