-- #2155: system-wide maintenance / downtime banners.
--
-- Operator-authored notices shown to every user: the web UI renders the
-- active ones at the top of the page and API/CLI clients read them from the
-- public `GET /api/v1/banners`. A banner is "active" while `enabled` and
-- now() is inside the optional [starts_at, ends_at) window, so expiry needs no
-- background job -- the read query filters on the window.
--
-- A new, empty table: no lock on any existing table, nothing to backfill.
CREATE TABLE system_banners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'info'
        CHECK (severity IN ('info', 'warning', 'critical')),
    -- Which surface should display it: 'all', 'ui' (web only) or 'api'
    -- (CLI / API clients only).
    target VARCHAR(8) NOT NULL DEFAULT 'all'
        CHECK (target IN ('all', 'ui', 'api')),
    link_url VARCHAR(2048),
    starts_at TIMESTAMPTZ,
    ends_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT system_banners_window_order
        CHECK (starts_at IS NULL OR ends_at IS NULL OR ends_at > starts_at)
);
