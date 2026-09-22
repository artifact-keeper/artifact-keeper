-- CI OIDC: key CI service accounts on their identity mapping, not on the
-- token subject (#4031).
--
-- Earlier versions stored the CI JWT's `sub` in `users.external_id` while
-- deriving the username from the mapping (`ci-<first 8 hex of mapping id>`).
-- GitLab's `sub` embeds the ref, so the second branch or tag to reach a
-- mapping looked up a different key, tried to insert the same username and
-- failed with 409 "Username already exists". The code now keys the account on
-- `ci:<provider_id>:<mapping_id>`; this migration rewrites the existing rows
-- to that key.
--
-- Properties this migration is written to keep:
--
--  * `users.id` is never touched -- only `external_id` is updated in place --
--    so group memberships, role assignments and audit rows, which all
--    reference `users.id`, survive unchanged. `updated_at` is left alone too,
--    so a rollback restores each row byte for byte.
--  * It attributes a row only on a unique prefix. `ci-<8hex>` names exactly
--    the first group of a mapping UUID's text form, so the candidate mapping
--    is `id::text LIKE '<8hex>-%'`. A row is rewritten only when EXACTLY ONE
--    mapping matches; zero matches (mapping deleted) and several (prefix
--    collision) leave the row as it is. A unique match is effectively, not
--    provably, the original mapping: if that mapping was deleted and a later
--    one happens to share its 8-hex prefix (about 2^-32 per pair), the row
--    binds to the later mapping.
--    A skipped row is not broken: the exchange adopts it on first use when it
--    can be attributed unambiguously (CiOidcService::resolve_service_account).
--  * Every decision is recorded in `ci_oidc_service_account_rekey_log`
--    (rewritten / skipped_orphaned / skipped_ambiguous, plus `adopted` rows
--    written later by the exchange), with the previous `external_id`, and
--    raised as a NOTICE. The log is the report and the rollback input.
--  * Rows already carrying a `ci:` key are not considered, so re-running it
--    changes nothing that is already migrated.
--
-- Rollback (restores every rewritten or adopted row to its previous key):
--
--   UPDATE users u SET external_id = l.previous_external_id
--   FROM ci_oidc_service_account_rekey_log l
--   WHERE l.user_id = u.id
--     AND l.outcome IN ('rewritten', 'adopted')
--     AND u.external_id = l.new_external_id;
--
-- `users` is a configuration-sized table (not in migration_safety's
-- HOT_TABLES) and only `auth_provider = 'ci'` rows are visited.
--
-- During a rolling upgrade an old replica may hold a row lock on a CI account
-- it is syncing. The lock timeout makes the migration fail fast, leaving
-- nothing applied, instead of waiting on that transaction for as long as it
-- lasts; it is re-run on the next start. It is `SET LOCAL`, scoped to this
-- migration's transaction (sqlx runs the file in one, as it carries no
-- `-- no-transaction` header).

SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ci_oidc_service_account_rekey_log (
    id                   BIGSERIAL    PRIMARY KEY,
    -- No FK: the log must outlive any later cleanup of the user row.
    user_id              UUID         NOT NULL,
    username             VARCHAR(255) NOT NULL,
    previous_external_id VARCHAR(512),
    new_external_id      VARCHAR(512),
    mapping_id           UUID,
    outcome              TEXT         NOT NULL
        CHECK (outcome IN ('rewritten', 'skipped_orphaned', 'skipped_ambiguous', 'adopted')),
    recorded_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ci_oidc_rekey_log_user
    ON ci_oidc_service_account_rekey_log (user_id);

DO $$
DECLARE
    r        RECORD;
    short_id TEXT;
    n        INTEGER;
    m_id     UUID;
    p_id     UUID;
    new_key  TEXT;
BEGIN
    FOR r IN
        SELECT id, username, external_id
        FROM users
        WHERE auth_provider = 'ci'
          AND COALESCE(external_id, '') NOT LIKE 'ci:%'
        ORDER BY username
    LOOP
        short_id := substring(r.username FROM '^ci-([0-9a-f]{8})$');

        IF short_id IS NULL THEN
            n := 0;
        ELSE
            SELECT COUNT(*), MIN(id::text)::uuid
              INTO n, m_id
              FROM ci_oidc_identity_mappings
             WHERE id::text LIKE short_id || '-%';
        END IF;

        IF n = 1 THEN
            SELECT provider_id INTO p_id FROM ci_oidc_identity_mappings WHERE id = m_id;
            new_key := 'ci:' || p_id::text || ':' || m_id::text;

            UPDATE users SET external_id = new_key WHERE id = r.id;

            INSERT INTO ci_oidc_service_account_rekey_log
                (user_id, username, previous_external_id, new_external_id, mapping_id, outcome)
            VALUES (r.id, r.username, r.external_id, new_key, m_id, 'rewritten');

            RAISE NOTICE 'ci-oidc rekey: rewritten % -> mapping %', r.username, m_id;
        ELSIF n = 0 THEN
            INSERT INTO ci_oidc_service_account_rekey_log
                (user_id, username, previous_external_id, outcome)
            VALUES (r.id, r.username, r.external_id, 'skipped_orphaned');

            RAISE NOTICE 'ci-oidc rekey: skipped % (no identity mapping matches)', r.username;
        ELSE
            INSERT INTO ci_oidc_service_account_rekey_log
                (user_id, username, previous_external_id, outcome)
            VALUES (r.id, r.username, r.external_id, 'skipped_ambiguous');

            RAISE NOTICE 'ci-oidc rekey: skipped % (% identity mappings share its prefix)',
                r.username, n;
        END IF;
    END LOOP;
END
$$;
