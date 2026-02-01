-- Hash-based scan deduplication: reuse scan results for identical artifacts
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS checksum_sha256 CHAR(64);
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS source_scan_id UUID REFERENCES scan_results(id);
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS is_reused BOOLEAN NOT NULL DEFAULT false;

-- Backfill existing scan results with artifact checksums
UPDATE scan_results sr SET checksum_sha256 = a.checksum_sha256
FROM artifacts a WHERE sr.artifact_id = a.id AND sr.checksum_sha256 IS NULL;

-- Index for dedup lookups: find completed scan by hash + type
CREATE INDEX IF NOT EXISTS idx_scan_results_dedup
ON scan_results(checksum_sha256, scan_type, status)
WHERE status = 'completed';
