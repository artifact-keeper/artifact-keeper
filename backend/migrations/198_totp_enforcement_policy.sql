-- #2805: system-wide TOTP (2FA) enforcement policy.
--
-- Stored in the existing key/value `system_settings` table rather than a new
-- column so it can be read and written through the same path as every other
-- security setting. The seeded value is 'disabled', which is exactly the
-- historical opt-in behaviour, so applying this migration changes nothing about
-- how anyone logs in until an administrator explicitly tightens the policy.
--
-- Accepted values: 'disabled' | 'required_for_admins' | 'required_for_all'.
-- The `TOTP_POLICY` environment variable overrides this row when set; that is
-- the offline break-glass path (see services/totp_policy.rs).
INSERT INTO system_settings (key, value, description)
VALUES (
    'security.totp_policy',
    '"disabled"',
    'TOTP 2FA enforcement policy: disabled | required_for_admins | required_for_all'
)
ON CONFLICT (key) DO NOTHING;
