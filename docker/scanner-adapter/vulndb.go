package main

// Vulnerability-database provenance (#3014).
//
// scanner.version names the trivy BINARY; the same binary returns different
// answers about identical bytes depending on how old its vulnerability DB is.
// The adapter therefore reports, with every scan result, which trivy DB the
// scan ran against so the backend can persist it on scan_results
// (vuln_db_version / vuln_db_published_at).
//
// The source is <cacheDir>/db/metadata.json, which is exactly the document
// `trivy version --format json` prints as its VulnerabilityDB block (verified
// against trivy 0.71.2):
//
//	{"Version":2,"NextUpdate":"2026-10-05T19:39:34.7Z","UpdatedAt":"2026-10-04T19:39:34.7Z","DownloadedAt":"2026-10-04T20:29:13.4Z"}
//
// Reading the file directly avoids a subprocess per scan, and reading it AFTER
// the scan reflects a DB that trivy refreshed during that scan.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// VulnDBInfo is the trivy vulnerability-DB metadata attached to scan results
// under `vulnerability_db`. An Artifact Keeper extension to the Harbor report;
// Harbor-spec consumers ignore unknown fields.
type VulnDBInfo struct {
	// Version is the trivy DB schema version (e.g. 2).
	Version int `json:"version"`
	// UpdatedAt is when the DB content was built upstream.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// NextUpdate is when trivy considers the DB stale.
	NextUpdate *time.Time `json:"next_update,omitempty"`
	// DownloadedAt is when this adapter fetched the DB.
	DownloadedAt *time.Time `json:"downloaded_at,omitempty"`
}

// trivyDBMetadata mirrors trivy's metadata.json field names.
type trivyDBMetadata struct {
	Version      int       `json:"Version"`
	NextUpdate   time.Time `json:"NextUpdate"`
	UpdatedAt    time.Time `json:"UpdatedAt"`
	DownloadedAt time.Time `json:"DownloadedAt"`
}

// nonZero returns a pointer to t, or nil for Go's zero time (field absent).
func nonZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// parseDBMetadata decodes a trivy metadata.json document. A document with no
// schema version is rejected: it does not identify a database.
func parseDBMetadata(raw []byte) (*VulnDBInfo, error) {
	var m trivyDBMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse trivy DB metadata: %w", err)
	}
	if m.Version <= 0 {
		return nil, fmt.Errorf("trivy DB metadata carries no schema version")
	}
	return &VulnDBInfo{
		Version:      m.Version,
		UpdatedAt:    nonZero(m.UpdatedAt),
		NextUpdate:   nonZero(m.NextUpdate),
		DownloadedAt: nonZero(m.DownloadedAt),
	}, nil
}

// ReadVulnDBInfo reads the trivy DB metadata from cacheDir. Errors are
// returned for the caller to log; provenance is best-effort and never fails a
// scan (DB presence itself is enforced by the readiness gate and the exit-0
// DB-failure markers).
func ReadVulnDBInfo(cacheDir string) (*VulnDBInfo, error) {
	raw, err := os.ReadFile(filepath.Join(cacheDir, "db", "metadata.json"))
	if err != nil {
		return nil, fmt.Errorf("read trivy DB metadata: %w", err)
	}
	return parseDBMetadata(raw)
}
