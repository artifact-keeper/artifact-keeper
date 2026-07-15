package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// writeFakeTrivy writes a shell "trivy" that increments a counter file on each
// call and exits non-zero (simulating a rate-limited DB pull) until the
// failUntil-th call, then exits 0. Returns the binary path and counter path.
func writeFakeTrivy(t *testing.T, failUntil int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	counter := filepath.Join(dir, "count")
	bin := filepath.Join(dir, "trivy")
	script := "#!/bin/sh\n" +
		"c=$(cat " + counter + " 2>/dev/null || echo 0)\n" +
		"c=$((c+1))\n" +
		"echo $c > " + counter + "\n" +
		"if [ \"$c\" -lt " + itoa(failUntil) + " ]; then\n" +
		"  echo 'TOOMANYREQUESTS: too many requests to mirror.gcr.io' >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	return bin, counter
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func readCount(t *testing.T, counter string) int {
	t.Helper()
	b, err := os.ReadFile(counter)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// TestDownloadDBRetriesTransientFailure proves the #2167 resilience fix: a
// transient DB-pull failure (rate-limit) is retried with backoff and eventually
// succeeds, so the adapter becomes ready instead of hard-failing the gate.
func TestDownloadDBRetriesTransientFailure(t *testing.T) {
	bin, counter := writeFakeTrivy(t, 3) // fail on calls 1,2; succeed on 3
	cfg := &Config{TrivyPath: bin, CacheDir: t.TempDir(), DBUpdateRetries: 3, DBUpdateRetryDelay: time.Millisecond}
	if err := DownloadDB(context.Background(), cfg); err != nil {
		t.Fatalf("DownloadDB should succeed after retries, got: %v", err)
	}
	if got := readCount(t, counter); got != 3 {
		t.Errorf("expected 3 trivy invocations, got %d", got)
	}
}

// TestDownloadDBExhaustsRetries proves DownloadDB gives up after the configured
// attempts and surfaces a descriptive error (fail-closed at readiness).
func TestDownloadDBExhaustsRetries(t *testing.T) {
	bin, counter := writeFakeTrivy(t, 99) // always fails
	cfg := &Config{TrivyPath: bin, CacheDir: t.TempDir(), DBUpdateRetries: 2, DBUpdateRetryDelay: time.Millisecond}
	err := DownloadDB(context.Background(), cfg)
	if err == nil {
		t.Fatal("DownloadDB should fail when all attempts fail")
	}
	if !strings.Contains(err.Error(), "after 3 attempt(s)") {
		t.Errorf("error should report attempt count; got: %v", err)
	}
	if got := readCount(t, counter); got != 3 { // 1 initial + 2 retries
		t.Errorf("expected 3 trivy invocations, got %d", got)
	}
}

// TestDownloadDBNoRetriesWhenDisabled proves DBUpdateRetries=0 keeps the
// single-shot behaviour (one invocation, no retry loop).
func TestDownloadDBNoRetriesWhenDisabled(t *testing.T) {
	bin, counter := writeFakeTrivy(t, 99)
	cfg := &Config{TrivyPath: bin, CacheDir: t.TempDir(), DBUpdateRetries: 0, DBUpdateRetryDelay: time.Millisecond}
	if err := DownloadDB(context.Background(), cfg); err == nil {
		t.Fatal("expected failure")
	}
	if got := readCount(t, counter); got != 1 {
		t.Errorf("expected exactly 1 invocation with retries disabled, got %d", got)
	}
}

// TestBuildCredentialHostScopedConfig proves the target-image bearer is written
// to a host-scoped Docker config.json (keyed by trimRegistryHost(URL)) and
// exposed via DOCKER_CONFIG — and that the flat, host-unscoped
// TRIVY_REGISTRY_TOKEN is never set. This is the #2167 root fix: the bearer must
// not bleed to trivy's vuln-DB pull.
func TestBuildCredentialHostScopedConfig(t *testing.T) {
	const url = "http://backend:8080"
	const token = "abc.def.ghi"
	req := &ScanRequest{
		Registry: RegistryRef{URL: url, Authorization: "Bearer " + token},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", Tag: "3.14"},
	}
	cred, err := buildCredential(req)
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}
	defer cred.cleanup()

	// DOCKER_CONFIG is set; TRIVY_REGISTRY_TOKEN is NOT.
	var dockerConfigDir string
	for _, e := range cred.env {
		if strings.HasPrefix(e, "TRIVY_REGISTRY_TOKEN=") {
			t.Fatalf("flat TRIVY_REGISTRY_TOKEN must not be set; got env %q", e)
		}
		if v, ok := strings.CutPrefix(e, "DOCKER_CONFIG="); ok {
			dockerConfigDir = v
		}
	}
	if dockerConfigDir == "" {
		t.Fatalf("DOCKER_CONFIG not set; env=%v", cred.env)
	}

	// The generated config.json is host-keyed to trimRegistryHost(URL) with the
	// bearer as registrytoken, and no other host entry exists.
	raw, err := os.ReadFile(filepath.Join(dockerConfigDir, "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config.json: %v", err)
	}
	wantHost := trimRegistryHost(url)
	if len(cfg.Auths) != 1 {
		t.Fatalf("expected exactly 1 auth entry, got %d: %v", len(cfg.Auths), cfg.Auths)
	}
	entry, ok := cfg.Auths[wantHost]
	if !ok {
		t.Fatalf("config missing host key %q; auths=%v", wantHost, cfg.Auths)
	}
	if entry.RegistryToken != token {
		t.Fatalf("registrytoken = %q, want %q", entry.RegistryToken, token)
	}
}

// TestBuildCredentialAnonymous proves an anonymous request writes no config and
// sets no DOCKER_CONFIG (the DB pull and the image pull both go anonymously).
func TestBuildCredentialAnonymous(t *testing.T) {
	cred, err := buildCredential(&ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", Tag: "3.14"},
	})
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}
	defer cred.cleanup()
	if len(cred.env) != 0 {
		t.Fatalf("anonymous request must add no env; got %v", cred.env)
	}
}

// TestBuildCredentialHostKeyWithPort proves the config key preserves the port so
// private-image pulls keep authenticating (the key must equal the target host).
func TestBuildCredentialHostKeyWithPort(t *testing.T) {
	cred, err := buildCredential(&ScanRequest{
		Registry: RegistryRef{URL: "https://registry.example.com:5000/", Authorization: "Bearer tkn"},
		Artifact: ArtifactRef{Repository: "team/app", Tag: "1.0"},
	})
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}
	defer cred.cleanup()
	dir := strings.TrimPrefix(cred.env[0], "DOCKER_CONFIG=")
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := cfg.Auths["registry.example.com:5000"]; !ok {
		t.Fatalf("host key missing port; auths=%v", cfg.Auths)
	}
}

func TestDockerConfigJSONShape(t *testing.T) {
	raw, err := dockerConfigJSON("host:8080", "tok")
	if err != nil {
		t.Fatalf("dockerConfigJSON: %v", err)
	}
	want := `{"auths":{"host:8080":{"registrytoken":"tok"}}}`
	if string(raw) != want {
		t.Fatalf("config json = %s, want %s", raw, want)
	}
}

func TestTrivyOutputIndicatesDBFailure(t *testing.T) {
	fires := []string{
		"2024-01-01 UNAUTHORIZED: authentication required",
		"FATAL failed to download vulnerability DB",
		"error: vulnerability DB does not exist",
		"trivy: DB error occurred",
		"pull rejected: unauthorized: invalid token", // case-insensitive
	}
	for _, s := range fires {
		if !trivyOutputIndicatesDBFailure(s) {
			t.Errorf("expected DB-failure marker to fire on %q", s)
		}
	}
	benign := []string{
		"",
		"2024-01-01 INFO Vulnerability scanning is enabled",
		"2024-01-01 INFO Detected OS: alpine",
		"2024-01-01 INFO Number of language-specific files: 0",
		"warn: no vulnerabilities found",
	}
	for _, s := range benign {
		if trivyOutputIndicatesDBFailure(s) {
			t.Errorf("DB-failure marker false-fired on benign output %q", s)
		}
	}
}

func TestDBPresent(t *testing.T) {
	cache := t.TempDir()
	if dbPresent(cache) {
		t.Fatal("empty cache should not be DB-present")
	}
	dbDir := filepath.Join(cache, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Empty metadata file -> still not present.
	meta := filepath.Join(dbDir, "metadata.json")
	if err := os.WriteFile(meta, nil, 0o644); err != nil {
		t.Fatalf("write empty meta: %v", err)
	}
	if dbPresent(cache) {
		t.Fatal("empty metadata.json should not count as DB-present")
	}
	// Non-empty metadata file -> present.
	if err := os.WriteFile(meta, []byte(`{"Version":2}`), 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	if !dbPresent(cache) {
		t.Fatal("non-empty metadata.json should count as DB-present")
	}
}

// TestMarkReadyIfDBPresentGate proves the readiness flag (and /probe/ready) stays
// 503 while the DB-presence check fails, and flips to 200 once it passes.
func TestMarkReadyIfDBPresentGate(t *testing.T) {
	srv := NewServer(LoadConfig())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if srv.markReadyIfDBPresent(func() bool { return false }) {
		t.Fatal("markReadyIfDBPresent returned true on failing DB check")
	}
	if code := getStatus(t, ts.URL+"/probe/ready"); code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d, want 503", code)
	}

	if !srv.markReadyIfDBPresent(func() bool { return true }) {
		t.Fatal("markReadyIfDBPresent returned false on passing DB check")
	}
	if code := getStatus(t, ts.URL+"/probe/ready"); code != http.StatusOK {
		t.Fatalf("ready status = %d, want 200", code)
	}
}

func getStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// dbErrorStub emits a trivy that exits 0 with empty Results but logs a DB-auth
// failure to stderr — the exact false-clean shape #2167 must fail closed on.
func dbErrorStub(t *testing.T) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
echo '{"Results":[]}'
echo "2024-01-01 FATAL UNAUTHORIZED: failed to download vulnerability DB" 1>&2
exit 0
`)
}

// TestScanExit0DBErrorFailsClosed proves a trivy run that exits 0 while logging a
// DB failure returns an error (job Failed -> report 500), not an empty report.
func TestScanExit0DBErrorFailsClosed(t *testing.T) {
	ts := newTestServer(t, dbErrorStub(t))
	defer ts.Close()

	id := submitScan(t, ts.URL, ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", Tag: "3.14"},
	})
	status, body := pollReport(t, ts.URL, id)
	if status != http.StatusInternalServerError {
		t.Fatalf("exit-0 DB-error scan status = %d, want 500; body=%s", status, body)
	}
}

// TestScanExit0DBErrorUnitLevel exercises Scan directly (no HTTP) for the same
// exit-0-with-DB-error contract.
func TestScanExit0DBErrorUnitLevel(t *testing.T) {
	cfg := LoadConfig()
	cfg.TrivyPath = dbErrorStub(t)
	cfg.CacheDir = t.TempDir()
	cfg.ScanTimeout = 10 * time.Second
	_, err := NewScanner(cfg).Scan(context.Background(), &ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080", Authorization: "Bearer tkn"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", Tag: "3.14"},
	})
	if err == nil {
		t.Fatal("expected exit-0-with-DB-error to return an error, got nil")
	}
	if !strings.Contains(err.Error(), "vulnerability-DB failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}
