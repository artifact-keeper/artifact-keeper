-- Password expiry notification tracking.
-- Records which warning-tier emails have been sent for each user so that
-- the background scheduler does not send duplicates.
CREATE TABLE IF NOT EXISTS password_expiry_notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    warning_days    INTEGER NOT NULL,
    password_changed_at TIMESTAMPTZ NOT NULL,
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, warning_days, password_changed_at)
);

CREATE INDEX IF NOT EXISTS idx_password_expiry_notifications_user
    ON password_expiry_notifications(user_id);
