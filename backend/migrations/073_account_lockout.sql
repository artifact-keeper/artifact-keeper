-- Add account lockout columns for brute-force protection.
-- failed_login_attempts tracks consecutive failures, locked_until stores
-- the timestamp when the lock expires, and last_failed_login_at records
-- the most recent failed attempt.

ALTER TABLE users
    ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN locked_until TIMESTAMP WITH TIME ZONE,
    ADD COLUMN last_failed_login_at TIMESTAMP WITH TIME ZONE;
