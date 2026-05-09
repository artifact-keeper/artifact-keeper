-- Add ON DELETE CASCADE to download_tickets.user_id.
--
-- Migration 039 created the table with a plain `REFERENCES users(id)`, which
-- defaults to `ON DELETE NO ACTION`. That meant deleting a user with
-- outstanding (typically about-to-expire) tickets would fail with a foreign-key
-- violation. Tickets are short-lived (30s TTL) and single-use, so cascading on
-- delete is correct: the tickets become invalid the moment the user does.
--
-- We drop the old constraint by inspecting the system catalog rather than
-- naming it explicitly, because Postgres auto-generates the constraint name
-- (`download_tickets_user_id_fkey` is conventional but not guaranteed).
DO $$
DECLARE
    fk_name text;
BEGIN
    SELECT con.conname INTO fk_name
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY(con.conkey)
    WHERE rel.relname = 'download_tickets'
      AND att.attname = 'user_id'
      AND con.contype = 'f';

    IF fk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE download_tickets DROP CONSTRAINT %I', fk_name);
    END IF;
END $$;

ALTER TABLE download_tickets
    ADD CONSTRAINT download_tickets_user_id_fkey
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE;
