-- Track password history to prevent reuse of recent passwords.
-- Each row stores a bcrypt hash of a previously used password along with the
-- user it belongs to and the timestamp when it was recorded. The application
-- layer is responsible for enforcing the reuse window (PASSWORD_HISTORY_COUNT).

CREATE TABLE password_history (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_history_user_id ON password_history (user_id, created_at DESC);
