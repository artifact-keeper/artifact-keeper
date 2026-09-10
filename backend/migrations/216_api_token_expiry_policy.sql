-- #3460: admin-configurable API token expiration policy.
--
-- Stored in the existing key/value `system_settings` table (same path as the
-- TOTP enforcement policy, migration 198) so it can be read and written
-- through the same admin-settings machinery. The seeded value has
-- `require_expiration: false`, which is exactly the historical behaviour
-- (expires_in_days optional, None = never expires), so applying this
-- migration changes nothing until an administrator explicitly enables
-- enforcement via PUT /api/v1/admin/settings/token-policy.
--
-- Enforcement is mint-time only: rows already in `api_tokens` are never
-- retroactively expired by any policy value (see
-- backend/src/services/token_expiry_policy.rs for the upgrade-safety
-- rationale). The `API_TOKEN_EXPIRATION_*` environment variables override
-- this row when set; that is the offline break-glass path.
INSERT INTO system_settings (key, value, description)
VALUES (
    'security.api_token_expiry_policy',
    '{"require_expiration": false, "min_days": 1, "max_days": 90, "default_days": 90, "apply_to_service_accounts": false}',
    'API token expiration policy (#3460): mint-time enforcement of mandatory token expiry'
)
ON CONFLICT (key) DO NOTHING;
