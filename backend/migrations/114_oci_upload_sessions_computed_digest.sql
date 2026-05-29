-- Cache the digest observed while streaming OCI blob upload bodies.
--
-- This lets final PUT ?digest=... promote a single-part upload without
-- re-reading the temporary object. Multi-part uploads still stream parts during
-- final digest verification.
ALTER TABLE oci_upload_sessions
    ADD COLUMN IF NOT EXISTS computed_digest TEXT;
