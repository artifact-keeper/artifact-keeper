-- Issue #5285: admit `model` as a scan_results.scan_type.
--
-- The model-file scanner is an in-process Rust scanner that inspects the files
-- a huggingface or mlmodel repository serves to a model loader: pickle opcode
-- streams (PyTorch `.bin`/`.pt`/`.ckpt`, `.pkl`, `.joblib`), safetensors
-- headers and GGUF headers. It is a first-party engine with its own verdicts
-- (findings of class `malicious` or `policy`), not an out-of-tree integration,
-- so it does not fit under `external` (220). The list restates every value
-- the constraint already admits, including `mcp_lint` (327).
--
-- Same online shape as 220: the DROP and the NOT VALID ADD are catalog-only,
-- and VALIDATE CONSTRAINT takes only SHARE UPDATE EXCLUSIVE. Widening a CHECK
-- cannot fail validation against rows that satisfy the narrower predicate.
ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_scan_type_check;
ALTER TABLE scan_results ADD CONSTRAINT scan_results_scan_type_check
    CHECK (scan_type IN ('dependency', 'image', 'license', 'malware', 'filesystem', 'grype', 'openscap', 'incus', 'external', 'mcp_lint', 'model'))
    NOT VALID;
ALTER TABLE scan_results VALIDATE CONSTRAINT scan_results_scan_type_check;
