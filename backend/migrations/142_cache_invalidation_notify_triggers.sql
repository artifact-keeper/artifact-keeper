-- Cross-replica cache-invalidation fanout (multi-replica stale-authorization
-- windows). Each backend process keeps authorization-sensitive caches in
-- process-local memory (API-token validations: 300 s TTL, repository
-- metadata: 60 s, fine-grained permissions: 30 s). A security-relevant write
-- handled by one replica was invisible to the others until their TTLs
-- expired. These triggers publish a JSON event on the
-- 'ak_cache_invalidation_v1' channel at COMMIT of each such write; every
-- replica runs a listener (backend/src/services/cache_invalidation.rs) that
-- maps events onto its local invalidation helpers.
--
-- Payload contract (versioned; keep in sync with InvalidationEvent):
--   {"v":1,"kind":"api_token_revoked","token_id":"..."}
--   {"v":1,"kind":"user_api_tokens_invalidated","user_id":"..."}
--   {"v":1,"kind":"repository_changed","old_key":"...","new_key":"..."}
--   {"v":1,"kind":"repository_deleted","key":"..."}
--   {"v":1,"kind":"permissions_changed"}
--
-- Triggers rather than app-level publishes: many handler paths mutate these
-- tables (profile/auth/users/service-account/token-service revocations, SSO
-- offboarding and group sync, permission CRUD, repo update/delete) and a
-- single missed publish silently reopens the stale window. pg_notify fires
-- at transaction commit, so listeners never observe rolled-back changes.
-- Notifications are delivered only to sessions currently LISTENing; the
-- listener conservatively flushes its caches on startup and reconnect, and
-- the existing TTLs remain the fallback bound when a replica is not
-- listening.

-- ---------------------------------------------------------------------------
-- api_tokens: revocation is the revoked_at NULL -> non-NULL transition.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_notify_api_token_revoked() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify(
        'ak_cache_invalidation_v1',
        json_build_object('v', 1, 'kind', 'api_token_revoked', 'token_id', NEW.id)::text
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_api_token_revoked_notify ON api_tokens;
CREATE TRIGGER ak_api_token_revoked_notify
    AFTER UPDATE OF revoked_at ON api_tokens
    FOR EACH ROW
    WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION ak_notify_api_token_revoked();

-- ---------------------------------------------------------------------------
-- users: deactivation (is_active true -> false) and hard delete both mean
-- every cached API-token validation for that user must be rejected.
-- Deliberately NOT fired on other user updates: profile edits are benign.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_notify_user_api_tokens_invalidated() RETURNS trigger AS $$
DECLARE
    affected_user_id UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        affected_user_id := OLD.id;
    ELSE
        affected_user_id := NEW.id;
    END IF;
    PERFORM pg_notify(
        'ak_cache_invalidation_v1',
        json_build_object('v', 1, 'kind', 'user_api_tokens_invalidated', 'user_id', affected_user_id)::text
    );
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_user_deactivated_notify ON users;
CREATE TRIGGER ak_user_deactivated_notify
    AFTER UPDATE OF is_active ON users
    FOR EACH ROW
    WHEN (OLD.is_active AND NOT NEW.is_active)
    EXECUTE FUNCTION ak_notify_user_api_tokens_invalidated();

DROP TRIGGER IF EXISTS ak_user_deleted_notify ON users;
CREATE TRIGGER ak_user_deleted_notify
    AFTER DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION ak_notify_user_api_tokens_invalidated();

-- ---------------------------------------------------------------------------
-- repositories: only the columns CachedRepo / auth decisions consume.
-- Deliberately NOT fired for updated_at-only writes: package activity bumps
-- updated_at constantly and must not flush repo metadata across the fleet.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_notify_repository_changed() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify(
        'ak_cache_invalidation_v1',
        json_build_object('v', 1, 'kind', 'repository_changed', 'old_key', OLD.key, 'new_key', NEW.key)::text
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_repository_changed_notify ON repositories;
CREATE TRIGGER ak_repository_changed_notify
    AFTER UPDATE ON repositories
    FOR EACH ROW
    WHEN (
        OLD.key IS DISTINCT FROM NEW.key
        OR OLD.format IS DISTINCT FROM NEW.format
        OR OLD.repo_type IS DISTINCT FROM NEW.repo_type
        OR OLD.upstream_url IS DISTINCT FROM NEW.upstream_url
        OR OLD.storage_backend IS DISTINCT FROM NEW.storage_backend
        OR OLD.storage_path IS DISTINCT FROM NEW.storage_path
        OR OLD.is_public IS DISTINCT FROM NEW.is_public
    )
    EXECUTE FUNCTION ak_notify_repository_changed();

CREATE OR REPLACE FUNCTION ak_notify_repository_deleted() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify(
        'ak_cache_invalidation_v1',
        json_build_object('v', 1, 'kind', 'repository_deleted', 'key', OLD.key)::text
    );
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_repository_deleted_notify ON repositories;
CREATE TRIGGER ak_repository_deleted_notify
    AFTER DELETE ON repositories
    FOR EACH ROW
    EXECUTE FUNCTION ak_notify_repository_deleted();

-- ---------------------------------------------------------------------------
-- permissions / user_group_members / groups: any change can grant or revoke
-- effective access (directly or via group membership), so all three fan out
-- the coarse permissions_changed event. The permission cache TTL is 30 s, so
-- a whole-cache flush costs at most one refill burst per change.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_notify_permissions_changed() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify(
        'ak_cache_invalidation_v1',
        json_build_object('v', 1, 'kind', 'permissions_changed')::text
    );
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_permissions_changed_notify ON permissions;
CREATE TRIGGER ak_permissions_changed_notify
    AFTER INSERT OR UPDATE OR DELETE ON permissions
    FOR EACH ROW
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_group_members_changed_notify ON user_group_members;
CREATE TRIGGER ak_group_members_changed_notify
    AFTER INSERT OR DELETE ON user_group_members
    FOR EACH ROW
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_group_deleted_notify ON groups;
CREATE TRIGGER ak_group_deleted_notify
    AFTER DELETE ON groups
    FOR EACH ROW
    EXECUTE FUNCTION ak_notify_permissions_changed();
