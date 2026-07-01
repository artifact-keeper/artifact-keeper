-- Dedicated, non-login scanner service account (#2093).
--
-- Private-repo container-image scanning needs an authenticated identity so the
-- scanner (Harbor adapter + grype) can pull internal/private images that anon
-- pulls 401 on. Rather than reuse a human or admin account, seed a minimal,
-- purpose-built service account:
--   * password_hash NULL  -> cannot log in interactively (no password grant).
--   * is_service_account  -> excluded from human-user surfaces.
--   * is_admin = false     -> NOT privileged; least privilege.
--   * no role assignments, no API token -> not user-reachable / cannot pull-all
--     on its own. The only credential that ever leaves the process is an
--     ephemeral, single-repo-scoped JWT minted per scan (see
--     AuthService::generate_scan_token + the scan_pull_repo claim enforced on
--     the OCI pull handlers).
--
-- Idempotent: seeded by username so re-running the migration (or a second
-- replica applying it) is a no-op.
INSERT INTO users (
    username,
    email,
    auth_provider,
    is_active,
    is_admin,
    is_service_account,
    must_change_password,
    password_hash,
    display_name
)
VALUES (
    '_ak_scanner',
    'scanner@artifact-keeper.internal',
    'local',
    true,
    false,
    true,
    false,
    NULL,
    'Image Scanner (system)'
)
ON CONFLICT (username) DO NOTHING;
