-- #5072: remember where each precomputed RPM repodata revision was written.
--
-- `rpm_repodata_roots` records one storage location per root, the current
-- revision's, and the builder deleted superseded revisions through it. When a
-- repository's `storage_backend` / `storage_path` changed, revisions written
-- to the previous location were never deleted there.
--
-- The claim of a revision now records the location it writes to, and the GC
-- deletes each revision through its own location, then forgets it. This also
-- finds the objects of a build that died before its swap.
--
-- The foreign key takes a brief lock on `rpm_repodata_roots`; bound the wait
-- (#4153) so a long transaction fails this migration (retried at the next
-- start) instead of queueing the builder behind it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE rpm_repodata_revisions (
    repository_id uuid NOT NULL,
    root text NOT NULL,
    revision bigint NOT NULL,
    storage_backend text NOT NULL,
    storage_path text NOT NULL,
    PRIMARY KEY (repository_id, root, revision),
    -- A root row is deleted only after its revisions were collected.
    FOREIGN KEY (repository_id, root) REFERENCES rpm_repodata_roots (repository_id, root)
        ON DELETE CASCADE
);

-- Revisions from before this migration: not yet collected, and written to the
-- location the root records. Numbers that were never stored are harmless,
-- since deleting an absent object is not an error. Where an earlier change of
-- location already moved the root's record, the older location is not known,
-- so objects left there stay behind.
INSERT INTO rpm_repodata_revisions (repository_id, root, revision, storage_backend, storage_path)
SELECT rr.repository_id, rr.root, revision.n, rr.storage_backend, rr.storage_path
  FROM rpm_repodata_roots rr
 CROSS JOIN LATERAL generate_series(rr.gc_floor, rr.next_revision) AS revision(n)
 WHERE rr.storage_backend IS NOT NULL AND rr.storage_path IS NOT NULL;
