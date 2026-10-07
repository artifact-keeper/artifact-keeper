package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// realTrivyMetadata is <cache>/db/metadata.json as written by trivy 0.71.2,
// byte for byte; `trivy version --format json` prints the same document as
// its VulnerabilityDB block.
const realTrivyMetadata = `{"Version":2,"NextUpdate":"2026-10-05T19:39:34.715623193Z","UpdatedAt":"2026-10-04T19:39:34.715623444Z","DownloadedAt":"2026-10-04T20:29:13.47226236Z"}`

// cacheWithDBMetadata returns a temp trivy cache dir holding realTrivyMetadata.
func cacheWithDBMetadata(t *testing.T) string {
	t.Helper()
	cache := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache, "db"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cache, "db", "metadata.json"), []byte(realTrivyMetadata), 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	return cache
}

func TestReadVulnDBInfoParsesRealMetadata(t *testing.T) {
	info, err := ReadVulnDBInfo(cacheWithDBMetadata(t))
	if err != nil {
		t.Fatalf("ReadVulnDBInfo: %v", err)
	}
	if info.Version != 2 {
		t.Errorf("version = %d, want 2", info.Version)
	}
	checks := map[string]struct {
		got  *time.Time
		want time.Time
	}{
		"updated_at":    {info.UpdatedAt, time.Date(2026, 10, 4, 19, 39, 34, 715623444, time.UTC)},
		"next_update":   {info.NextUpdate, time.Date(2026, 10, 5, 19, 39, 34, 715623193, time.UTC)},
		"downloaded_at": {info.DownloadedAt, time.Date(2026, 10, 4, 20, 29, 13, 472262360, time.UTC)},
	}
	for name, c := range checks {
		if c.got == nil || !c.got.Equal(c.want) {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}
}

func TestReadVulnDBInfoMissingFile(t *testing.T) {
	if info, err := ReadVulnDBInfo(t.TempDir()); err == nil {
		t.Fatalf("expected error for a cache with no DB, got %+v", info)
	}
}

func TestParseDBMetadataRejectsUnidentifiedDB(t *testing.T) {
	for name, raw := range map[string]string{
		"no version":   `{"UpdatedAt":"2026-10-04T19:39:34Z"}`,
		"zero version": `{"Version":0}`,
		"not json":     `not json`,
	} {
		if info, err := parseDBMetadata([]byte(raw)); err == nil {
			t.Errorf("%s: expected error, got %+v", name, info)
		}
	}
}

func TestParseDBMetadataOmitsZeroTimes(t *testing.T) {
	info, err := parseDBMetadata([]byte(`{"Version":2}`))
	if err != nil {
		t.Fatalf("parseDBMetadata: %v", err)
	}
	if info.UpdatedAt != nil || info.NextUpdate != nil || info.DownloadedAt != nil {
		t.Errorf("absent timestamps must be nil, got %+v", info)
	}
}
