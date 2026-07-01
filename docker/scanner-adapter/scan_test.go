package main

import (
	"strings"
	"testing"
	"time"
)

func TestTrimRegistryHost(t *testing.T) {
	cases := map[string]string{
		"http://backend:8080":   "backend:8080",
		"https://backend:8080/": "backend:8080",
		"backend:8080":          "backend:8080",
		"http://host/":          "host",
	}
	for in, want := range cases {
		if got := trimRegistryHost(in); got != want {
			t.Errorf("trimRegistryHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildRefTag(t *testing.T) {
	ref, err := buildRef("http://backend:8080", "docker-local/library/nginx", "1.20", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != "backend:8080/docker-local/library/nginx:1.20" {
		t.Errorf("got %q", ref)
	}
}

func TestBuildRefDigestUsesAtSeparator(t *testing.T) {
	digest := "sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b"
	ref, err := buildRef("http://backend:8080", "oci-prod/org/app", "", digest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "backend:8080/oci-prod/org/app@" + digest
	if ref != want {
		t.Errorf("got %q, want %q", ref, want)
	}
}

func TestBuildRefErrors(t *testing.T) {
	if _, err := buildRef("http://backend:8080", "", "1.20", ""); err == nil {
		t.Error("expected error for empty repository")
	}
	if _, err := buildRef("http://backend:8080", "repo", "", ""); err == nil {
		t.Error("expected error when neither tag nor digest present")
	}
}

func TestRegistryToken(t *testing.T) {
	if got := registryToken("Bearer abc.def.ghi"); got != "abc.def.ghi" {
		t.Errorf("got %q", got)
	}
	if got := registryToken(""); got != "" {
		t.Errorf("anonymous should be empty, got %q", got)
	}
	if got := registryToken("Basic xyz"); got != "" {
		t.Errorf("non-bearer should be empty, got %q", got)
	}
}

func TestParseTrivyVersion(t *testing.T) {
	out := "Version: 0.71.2\nVulnerability DB:\n  Version: 2\n"
	if got := parseTrivyVersion(out); got != "0.71.2" {
		t.Errorf("got %q", got)
	}
	if got := parseTrivyVersion("no version here"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestBuildArgs(t *testing.T) {
	cfg := &Config{
		Severity:     "HIGH,CRITICAL",
		ScanTimeout:  5 * time.Minute,
		CacheDir:     "/cache",
		Insecure:     true,
		SkipDBUpdate: true,
	}
	args := strings.Join(NewScanner(cfg).buildArgs("backend:8080/repo:tag"), " ")
	for _, want := range []string{
		"image", "--format json", "--scanners vuln", "--severity HIGH,CRITICAL",
		"--timeout 5m0s", "--cache-dir /cache", "--quiet", "--insecure",
		"--skip-db-update", "backend:8080/repo:tag",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("args missing %q; got: %s", want, args)
		}
	}
}

func TestBuildArgsOmitsOptionalFlags(t *testing.T) {
	cfg := &Config{Severity: "LOW", ScanTimeout: time.Minute, CacheDir: "/c"}
	args := strings.Join(NewScanner(cfg).buildArgs("ref"), " ")
	if strings.Contains(args, "--insecure") {
		t.Error("--insecure should be absent when Insecure=false")
	}
	if strings.Contains(args, "--skip-db-update") {
		t.Error("--skip-db-update should be absent when SkipDBUpdate=false")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	// A clean environment yields the documented defaults.
	for _, k := range []string{
		"SCANNER_ADAPTER_ADDR", "SCANNER_TRIVY_PATH", "SCANNER_TRIVY_CACHE_DIR",
		"SCANNER_TRIVY_INSECURE", "SCANNER_TRIVY_SKIP_DB_UPDATE", "SCANNER_TRIVY_SEVERITY",
		"SCANNER_TRIVY_TIMEOUT", "SCANNER_JOB_TTL", "SCANNER_LOG_LEVEL", "SCANNER_SCANNER_VERSION",
	} {
		t.Setenv(k, "")
	}
	cfg := LoadConfig()
	if cfg.Addr != ":8080" || cfg.TrivyPath != "trivy" || !cfg.Insecure || cfg.SkipDBUpdate {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if cfg.ScanTimeout != 5*time.Minute || cfg.JobTTL != 30*time.Minute {
		t.Errorf("unexpected duration defaults: %+v", cfg)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("SCANNER_ADAPTER_ADDR", ":8090")
	t.Setenv("SCANNER_TRIVY_INSECURE", "false")
	t.Setenv("SCANNER_TRIVY_SKIP_DB_UPDATE", "true")
	t.Setenv("SCANNER_TRIVY_TIMEOUT", "90s")
	t.Setenv("SCANNER_SCANNER_VERSION", "0.71.2")
	cfg := LoadConfig()
	if cfg.Addr != ":8090" || cfg.Insecure || !cfg.SkipDBUpdate {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.ScanTimeout != 90*time.Second {
		t.Errorf("timeout override not applied: %v", cfg.ScanTimeout)
	}
	if cfg.ScannerVersion != "0.71.2" {
		t.Errorf("version override not applied: %q", cfg.ScannerVersion)
	}
}

func TestGetenvBadValuesFallBackToDefault(t *testing.T) {
	t.Setenv("SCANNER_TRIVY_INSECURE", "not-a-bool")
	t.Setenv("SCANNER_TRIVY_TIMEOUT", "not-a-duration")
	cfg := LoadConfig()
	if !cfg.Insecure {
		t.Error("bad bool should fall back to default true")
	}
	if cfg.ScanTimeout != 5*time.Minute {
		t.Error("bad duration should fall back to default 5m")
	}
}

func TestJobStoreLifecycle(t *testing.T) {
	store := NewJobStore(time.Hour)
	job, err := store.Create()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if job.Status != StatusPending {
		t.Errorf("new job should be Pending, got %s", job.Status)
	}
	if _, ok := store.Get("nope"); ok {
		t.Error("unknown id should not be found")
	}

	store.Running(job.ID)
	if got, _ := store.Get(job.ID); got.Status != StatusRunning {
		t.Errorf("expected Running, got %s", got.Status)
	}

	report := &HarborScanReport{Vulnerabilities: []HarborVulnerability{}}
	store.Succeed(job.ID, report)
	if got, _ := store.Get(job.ID); got.Status != StatusSucceeded || got.Report != report {
		t.Errorf("succeed not recorded: %+v", got)
	}

	job2, _ := store.Create()
	store.Fail(job2.ID, "boom")
	if got, _ := store.Get(job2.ID); got.Status != StatusFailed || got.Err != "boom" {
		t.Errorf("fail not recorded: %+v", got)
	}
}

func TestJobStoreSweep(t *testing.T) {
	store := NewJobStore(time.Hour)
	done, _ := store.Create()
	store.Succeed(done.ID, &HarborScanReport{})
	pending, _ := store.Create()

	// Not expired yet.
	if n := store.sweep(time.Now()); n != 0 {
		t.Errorf("nothing should be swept yet, got %d", n)
	}
	// Far in the future: the terminal job is evicted, the pending one retained.
	if n := store.sweep(time.Now().Add(2 * time.Hour)); n != 1 {
		t.Errorf("expected 1 swept, got %d", n)
	}
	if _, ok := store.Get(done.ID); ok {
		t.Error("terminal job should have been swept")
	}
	if _, ok := store.Get(pending.ID); !ok {
		t.Error("pending job should NOT be swept")
	}
}

func TestNewIDUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := newID()
		if err != nil {
			t.Fatalf("newID: %v", err)
		}
		if len(id) != 32 {
			t.Errorf("expected 32 hex chars, got %d (%q)", len(id), id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}
