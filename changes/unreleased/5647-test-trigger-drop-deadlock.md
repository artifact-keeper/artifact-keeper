---
section: Fixed
issues: [#5647]
---
- **Unit tests that inject a failing trigger no longer deadlock each other when they remove it** (#5647). A `DROP TRIGGER` takes a weak lock on its table and only then asks for the exclusive one, so two tests dropping triggers from the same shared table at once (`oci_blobs`, `artifacts`, `manifest_blob_refs` and others) could each hold the lock the other was waiting for, and Postgres aborted one with `40P01 deadlock detected`. That failed `whole_body_put_failed_commit_stays_retryable_5133`, and in the tests that ignored the error it could leave the trigger behind for other tests. The tests now remove their triggers through one helper that takes the exclusive table lock first, so concurrent removals wait in turn. Test-only change; no runtime behaviour changes.
