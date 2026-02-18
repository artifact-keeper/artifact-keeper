-- Add incus scan type to the check constraint
ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_scan_type_check;
ALTER TABLE scan_results ADD CONSTRAINT scan_results_scan_type_check
    CHECK (scan_type IN ('dependency', 'image', 'license', 'malware', 'filesystem', 'grype', 'openscap', 'incus'));
