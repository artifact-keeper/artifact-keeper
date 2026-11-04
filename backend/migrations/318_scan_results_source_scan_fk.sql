-- #5153: a copied verdict must not pin its source.
--
-- `source_scan_id` is provenance. With no ON DELETE action, a scan that had been
-- copied could not be deleted, so purging the source artifact or deleting its
-- repository failed. A cross-repository dedup copy could already cause that, and
-- promotion now copies the verdict every time, so a staging repository could
-- otherwise never be emptied. The copy keeps its findings and `is_reused`. NOT
-- VALID because the old constraint already enforced every existing row and this
-- must not scan the table under the ACCESS EXCLUSIVE lock. The catalogue update is
-- quick, but readers queue behind a waiting exclusive lock, so the wait is bounded:
-- under a long transaction this migration fails and is retried rather than stalling
-- every download behind it.
SET LOCAL lock_timeout = '5s';

ALTER TABLE scan_results DROP CONSTRAINT scan_results_source_scan_id_fkey;
ALTER TABLE scan_results
    ADD CONSTRAINT scan_results_source_scan_id_fkey
    FOREIGN KEY (source_scan_id) REFERENCES scan_results(id)
    ON DELETE SET NULL NOT VALID;

