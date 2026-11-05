-- Issue #5253: admit `mcp_lint` as a scan_results.scan_type.
--
-- The MCP registry lint (`services::mcp_lint`) writes one completed
-- scan_results row per lint run of a server.json artifact, with its findings
-- in scan_findings, so the findings UI, the acknowledgement flow and the
-- scan-policy gate read MCP lint findings exactly as they read any scanner's.
--
-- It cannot reuse `external`: `artifact_current_scan_ids` grades every
-- `external` row and never supersedes one, so each re-lint would add to the
-- previous verdict instead of replacing it, and promotion refuses an artifact
-- with an external submission on record. A dedicated type gets the
-- "latest completed row per scan_type" baseline every in-tree scanner gets.
--
-- Same online shape as 220: the DROP and the NOT VALID ADD are catalog-only,
-- VALIDATE takes SHARE UPDATE EXCLUSIVE, and widening a CHECK cannot fail
-- against rows that satisfied the narrower one.
ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_scan_type_check;
ALTER TABLE scan_results ADD CONSTRAINT scan_results_scan_type_check
    CHECK (scan_type IN ('dependency', 'image', 'license', 'malware', 'filesystem', 'grype', 'openscap', 'incus', 'external', 'mcp_lint'))
    NOT VALID;
ALTER TABLE scan_results VALIDATE CONSTRAINT scan_results_scan_type_check;
