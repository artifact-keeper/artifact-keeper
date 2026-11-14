package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// scanAuthCall sends one request with an optional Authorization header and
// returns the status code.
func scanAuthCall(t *testing.T, method, url, contentType string, body []byte, auth string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func scanAuthImageBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", MimeType: dockerManifestMimeType, Tag: "3.14"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// scanAuthSubmit submits an image scan with auth and returns its id.
func scanAuthSubmit(t *testing.T, base, auth string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/scan", bytes.NewReader(scanAuthImageBody(t)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post scan: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("authorized scan submit = %d, want 202", resp.StatusCode)
	}
	var sr ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil || sr.ID == "" {
		t.Fatalf("decode scan response: %v %+v", err, sr)
	}
	return sr.ID
}

func newScanAuthServer(t *testing.T, tweak func(*Config)) *httptest.Server {
	t.Helper()
	ts := newTestServerWithConfig(t, succeedStub(t), t.TempDir(), tweak)
	t.Cleanup(ts.Close)
	return ts
}

// assertScanRoutesGated checks every scan and report route: no token and a
// wrong token are 401, the right token is accepted.
func assertScanRoutesGated(t *testing.T, ts *httptest.Server, good string) {
	t.Helper()
	tarBody := tarOf(t, map[string]string{"composer.lock": "{}"})
	for _, auth := range []string{"", "Bearer wrong-token", "Basic " + good, "Bearer"} {
		if got := scanAuthCall(t, http.MethodPost, ts.URL+"/api/v1/scan", "application/json", scanAuthImageBody(t), auth); got != http.StatusUnauthorized {
			t.Errorf("POST /api/v1/scan with %q = %d, want 401", auth, got)
		}
		if got := scanAuthCall(t, http.MethodPost, ts.URL+"/api/v1/filesystem/scan", "application/x-tar", tarBody, auth); got != http.StatusUnauthorized {
			t.Errorf("POST /api/v1/filesystem/scan with %q = %d, want 401", auth, got)
		}
		if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/scan/anything/report", "", nil, auth); got != http.StatusUnauthorized {
			t.Errorf("GET scan report with %q = %d, want 401", auth, got)
		}
		if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/filesystem/scan/anything/report", "", nil, auth); got != http.StatusUnauthorized {
			t.Errorf("GET fs report with %q = %d, want 401", auth, got)
		}
	}

	bearer := "Bearer " + good
	if got := scanAuthCall(t, http.MethodPost, ts.URL+"/api/v1/filesystem/scan", "application/x-tar", tarBody, bearer); got != http.StatusAccepted {
		t.Errorf("POST /api/v1/filesystem/scan with the token = %d, want 202", got)
	}
	id := scanAuthSubmit(t, ts.URL, bearer)
	// The report route answers with the token (302 pending or 200 done),
	// never 401; without it, 401 even for a real id.
	if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/scan/"+id+"/report", "", nil, bearer); got == http.StatusUnauthorized || got >= 400 {
		t.Errorf("GET report with the token = %d, want 200 or 302", got)
	}
	if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/scan/"+id+"/report", "", nil, ""); got != http.StatusUnauthorized {
		t.Errorf("GET report of a real id without the token = %d, want 401", got)
	}
	// An unknown id with the token reaches the handler (404), not the gate.
	if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/filesystem/scan/deadbeef/report", "", nil, bearer); got != http.StatusNotFound {
		t.Errorf("GET unknown fs report with the token = %d, want 404", got)
	}

	// Probes and metadata stay open.
	for _, path := range []string{"/probe/ready", "/probe/healthy", "/api/v1/metadata"} {
		if got := scanAuthCall(t, http.MethodGet, ts.URL+path, "", nil, ""); got != http.StatusOK {
			t.Errorf("GET %s without a token = %d, want 200", path, got)
		}
	}
}

func TestScanTokenGatesScanAndReportRoutes(t *testing.T) {
	ts := newScanAuthServer(t, func(c *Config) { c.ScanToken = "scan-secret-1" })
	assertScanRoutesGated(t, ts, "scan-secret-1")
	// The scheme is case-insensitive (RFC 7235).
	if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/scan/nope/report", "", nil, "bearer scan-secret-1"); got != http.StatusNotFound {
		t.Errorf("lower-case scheme = %d, want 404 from the handler", got)
	}
}

// The DB-import credential is not a scan credential, and vice versa.
func TestScanTokenIsSeparateFromAdapterToken(t *testing.T) {
	ts := newScanAuthServer(t, func(c *Config) {
		c.ScanToken = "scan-secret-1"
		c.AdapterToken = "db-secret-1"
	})
	if got := scanAuthCall(t, http.MethodPost, ts.URL+"/api/v1/scan", "application/json", scanAuthImageBody(t), "Bearer db-secret-1"); got != http.StatusUnauthorized {
		t.Errorf("scan with the DB token = %d, want 401", got)
	}
	if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/vulndb", "", nil, "Bearer scan-secret-1"); got != http.StatusUnauthorized {
		t.Errorf("vulndb with the scan token = %d, want 401", got)
	}
}

// Unset keeps today's behaviour: the scan routes are open.
func TestScanRoutesOpenWithoutScanToken(t *testing.T) {
	ts := newScanAuthServer(t, nil)
	if got := scanAuthCall(t, http.MethodPost, ts.URL+"/api/v1/scan", "application/json", scanAuthImageBody(t), ""); got != http.StatusAccepted {
		t.Errorf("scan without a configured token = %d, want 202", got)
	}
	if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/scan/nope/report", "", nil, ""); got != http.StatusNotFound {
		t.Errorf("report without a configured token = %d, want 404", got)
	}
}

func writeTokens(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// Explicit mtimes so a rewrite within the filesystem's timestamp
	// granularity is still seen as a change.
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestScanTokensFileAcceptsEachTokenAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	base := time.Now().Add(-time.Hour)
	writeTokens(t, path, "# one per instance\ninstance-a-token\n\n  instance-b-token  \n", base)
	ts := newScanAuthServer(t, func(c *Config) { c.ScanTokensFile = path })

	assertScanRoutesGated(t, ts, "instance-a-token")
	assertScanRoutesGated(t, ts, "instance-b-token")
	if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/scan/x/report", "", nil, "Bearer # one per instance"); got != http.StatusUnauthorized {
		t.Errorf("a comment line is not a token: %d", got)
	}

	// Drop instance-a, add instance-c: picked up without a restart.
	writeTokens(t, path, "instance-b-token\ninstance-c-token\n", base.Add(time.Minute))
	report := func(tok string) int {
		return scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/scan/nope/report", "", nil, "Bearer "+tok)
	}
	if got := report("instance-a-token"); got != http.StatusUnauthorized {
		t.Errorf("dropped token = %d, want 401", got)
	}
	if got := report("instance-b-token"); got != http.StatusNotFound {
		t.Errorf("kept token = %d, want 404 from the handler", got)
	}
	if got := report("instance-c-token"); got != http.StatusNotFound {
		t.Errorf("added token = %d, want 404 from the handler", got)
	}

	// A file that disappears keeps the last set (a Secret mid-swap).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := report("instance-c-token"); got != http.StatusNotFound {
		t.Errorf("token after the file vanished = %d, want 404 (last good set kept)", got)
	}
}

// Both forms together: either is accepted.
func TestScanTokenAndTokensFileCombine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "from-file\n", time.Now().Add(-time.Hour))
	ts := newScanAuthServer(t, func(c *Config) {
		c.ScanToken = "from-env"
		c.ScanTokensFile = path
	})
	for _, tok := range []string{"from-env", "from-file"} {
		if got := scanAuthCall(t, http.MethodGet, ts.URL+"/api/v1/scan/nope/report", "", nil, "Bearer "+tok); got != http.StatusNotFound {
			t.Errorf("%s = %d, want 404 from the handler", tok, got)
		}
	}
}

// A configured tokens file that cannot be read fails closed: no token is
// accepted, the routes are not left open.
func TestScanTokensFileMissingFailsClosed(t *testing.T) {
	ts := newScanAuthServer(t, func(c *Config) { c.ScanTokensFile = filepath.Join(t.TempDir(), "absent") })
	if got := scanAuthCall(t, http.MethodPost, ts.URL+"/api/v1/scan", "application/json", scanAuthImageBody(t), ""); got != http.StatusUnauthorized {
		t.Errorf("scan with an unreadable tokens file = %d, want 401", got)
	}
	if got := scanAuthCall(t, http.MethodGet, ts.URL+"/probe/healthy", "", nil, ""); got != http.StatusOK {
		t.Errorf("probe = %d, want 200", got)
	}
}

func TestLoadConfigScanTokens(t *testing.T) {
	t.Setenv("SCANNER_SCAN_TOKEN", "  tok  ")
	t.Setenv("SCANNER_SCAN_TOKENS_FILE", " /run/secrets/scan-tokens ")
	cfg := LoadConfig()
	if cfg.ScanToken != "tok" || cfg.ScanTokensFile != "/run/secrets/scan-tokens" {
		t.Errorf("got %q %q", cfg.ScanToken, cfg.ScanTokensFile)
	}
}

// Compatibility (#5948): a backend that sends a token to an adapter with no
// scan token configured (or an older adapter, which never reads the header on
// these routes) is served as before: the header is ignored.
func TestScanRoutesIgnoreTokenWhenUnset(t *testing.T) {
	ts := newScanAuthServer(t, nil)
	tarBody := tarOf(t, map[string]string{"composer.lock": "{}"})
	for _, auth := range []string{"", "Bearer some-backend-token"} {
		if got := scanAuthCall(t, http.MethodPost, ts.URL+"/api/v1/scan", "application/json", scanAuthImageBody(t), auth); got != http.StatusAccepted {
			t.Errorf("POST /api/v1/scan with %q = %d, want 202", auth, got)
		}
		if got := scanAuthCall(t, http.MethodPost, ts.URL+"/api/v1/filesystem/scan", "application/x-tar", tarBody, auth); got != http.StatusAccepted {
			t.Errorf("POST /api/v1/filesystem/scan with %q = %d, want 202", auth, got)
		}
	}
	// A whole scan, polled to its report without any header, as an older
	// backend does.
	id := submitScan(t, ts.URL, ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", MimeType: dockerManifestMimeType, Tag: "3.14"},
	})
	if status, body := pollReport(t, ts.URL, id); status != http.StatusOK {
		t.Fatalf("report without a token = %d: %s", status, body)
	}
}

// Compatibility (#5948): SCANNER_ADAPTER_TOKEN alone keeps guarding and
// serving the vulnerability-DB routes, with or without a scan token beside it.
func TestVulnDBImportWorksWithAdapterTokenAlongsideScanToken(t *testing.T) {
	for _, scanToken := range []string{"", "scan-secret-2"} {
		cache := t.TempDir()
		_, ts := newImportServer(t, cache, func(c *Config) { c.ScanToken = scanToken })
		if code, _ := getDB(t, ts, ""); code != http.StatusUnauthorized {
			t.Errorf("scan token %q: GET vulndb without a token = %d, want 401", scanToken, code)
		}
		code, resp := putDB(t, ts, "", dbTarball(t, 2, time.Now().Add(-time.Hour).UTC(), 'b'), testToken)
		if code != http.StatusOK {
			t.Fatalf("scan token %q: PUT with SCANNER_ADAPTER_TOKEN = %d: %s", scanToken, code, resp)
		}
		if code, _ := getDB(t, ts, testToken); code != http.StatusOK {
			t.Errorf("scan token %q: GET vulndb with SCANNER_ADAPTER_TOKEN = %d, want 200", scanToken, code)
		}
	}
}
