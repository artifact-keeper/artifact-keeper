-- #5608: deleting a user or group removes its permission rules.
--
-- `permissions` keys its principal by the polymorphic pair
-- `(principal_type, principal_id)` (018), so a foreign key cannot point at
-- `users` for some rows and `groups` for others. Deleting a principal
-- therefore left its rules behind: they granted nothing (ids are never
-- reused) but kept the repository reporting `has_any_rules_for_target`, made
-- every authorization check pay for the rules query, and listed as
-- `principal_name: null` in `GET /api/v1/permissions`.
--
-- The triggers below are the ON DELETE CASCADE the schema cannot express.
-- They run inside the deleting transaction, so a failed user or group delete
-- rolls the rule removal back with it, and they cover every delete path
-- (admin handlers, SSO offboarding, sync cleanup) instead of only the two
-- handlers that reported the bug. The existing
-- `ak_permissions_changed_notify` trigger (142) then fans the removal out to
-- every replica's permission cache.
--
-- `anonymous` names no table row; it is deliberately not touched.
--
-- The one-off DELETE clears the rows left by deletes that happened before
-- this migration. It runs after the trigger definitions so a concurrent
-- delete in the same window cannot leave a new orphan.
SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION ak_delete_principal_permission_rules() RETURNS trigger AS $$
BEGIN
    DELETE FROM permissions
    WHERE principal_type = ANY (TG_ARGV)
      AND principal_id = OLD.id;
    RETURN OLD;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_user_permission_rules_delete ON users;
CREATE TRIGGER ak_user_permission_rules_delete
    AFTER DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION ak_delete_principal_permission_rules('user', 'service_account');

DROP TRIGGER IF EXISTS ak_group_permission_rules_delete ON groups;
CREATE TRIGGER ak_group_permission_rules_delete
    AFTER DELETE ON groups
    FOR EACH ROW
    EXECUTE FUNCTION ak_delete_principal_permission_rules('group');

DELETE FROM permissions p
WHERE (p.principal_type IN ('user', 'service_account')
       AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = p.principal_id))
   OR (p.principal_type = 'group'
       AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.id = p.principal_id));
