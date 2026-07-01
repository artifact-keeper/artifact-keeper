package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeStub writes an executable fake `trivy` at a temp path whose body is the
// given shell script, and returns its path. The script must handle both
// `--version` (startup probe) and `image ...` (scan) invocations so every path
// is deterministic without a network or a real trivy.
func writeStub(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trivy")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return path
}

const stubVersion = `if [ "$1" = "--version" ]; then echo "Version: 0.71.2"; exit 0; fi`

// succeedStub emits a canned trivy JSON report with one HIGH finding.
func succeedStub(t *testing.T) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
cat <<'JSON'
{"Results":[{"Target":"alpine:3.14","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[
  {"VulnerabilityID":"CVE-2021-3711","PkgName":"openssl","InstalledVersion":"1.1.1k","FixedVersion":"1.1.1l","Severity":"CRITICAL","Description":"SM2 overflow","PrimaryURL":"https://avd.aquasec.com/CVE-2021-3711"}
]}]}
JSON
`)
}

// failStub exits non-zero (simulating a failed pull / trivy error).
func failStub(t *testing.T) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
echo "FATAL: failed to pull image" 1>&2
exit 1
`)
}

// slowStub sleeps before emitting a report so the report can be polled while
// still Pending/Running.
func slowStub(t *testing.T) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
sleep 1
echo '{"Results":[]}'
`)
}

// newTestServer builds a ready Server whose scanner execs the given stub trivy.
func newTestServer(t *testing.T, trivyPath string) *httptest.Server {
	t.Helper()
	cfg := LoadConfig()
	cfg.TrivyPath = trivyPath
	cfg.CacheDir = t.TempDir()
	cfg.ScanTimeout = 10 * time.Second
	// Exercise the real probe against the stub.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := ProbeVersion(ctx, cfg)
	if err != nil {
		t.Fatalf("probe version: %v", err)
	}
	if version != "0.71.2" {
		t.Fatalf("stub version = %q, want 0.71.2", version)
	}
	cfg.ScannerVersion = version
	srv := NewServer(cfg)
	srv.MarkReady()
	return httptest.NewServer(srv.Handler())
}

// noRedirectClient returns an http client that surfaces 302s instead of
// following them (the backend polls with redirects disabled).
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// submitScan POSTs a scan and returns the assigned id.
func submitScan(t *testing.T, base string, req ScanRequest) string {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(base+"/api/v1/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post scan: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("scan submit status = %d, want 202", resp.StatusCode)
	}
	var sr ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		t.Fatalf("decode scan response: %v", err)
	}
	if sr.ID == "" {
		t.Fatal("empty scan id")
	}
	return sr.ID
}

// pollReport polls the report endpoint until it is no longer Pending (302) or
// the deadline passes, returning the final response status and body.
func pollReport(t *testing.T, base, id string) (int, []byte) {
	t.Helper()
	client := noRedirectClient()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/scan/"+id+"/report", nil)
		req.Header.Set("Accept", reportMimeType)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("get report: %v", err)
		}
		if resp.StatusCode == http.StatusFound {
			if ra := resp.Header.Get("Refresh-After"); ra != "5" {
				t.Errorf("pending Refresh-After = %q, want 5", ra)
			}
			resp.Body.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		body := readAll(t, resp)
		return resp.StatusCode, body
	}
	t.Fatal("report never left pending state")
	return 0, nil
}

func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return buf.Bytes()
}

func TestScanSucceedsWithFindings(t *testing.T) {
	ts := newTestServer(t, succeedStub(t))
	defer ts.Close()

	id := submitScan(t, ts.URL, ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", MimeType: dockerManifestMimeType, Tag: "3.14"},
	})

	status, body := pollReport(t, ts.URL, id)
	if status != http.StatusOK {
		t.Fatalf("report status = %d, want 200; body=%s", status, body)
	}
	var report HarborScanReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Scanner.Name != "Trivy" || report.Scanner.Version != "0.71.2" {
		t.Errorf("scanner block = %+v", report.Scanner)
	}
	if len(report.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(report.Vulnerabilities))
	}
	v := report.Vulnerabilities[0]
	if v.ID != "CVE-2021-3711" || v.Severity != "Critical" || v.Package != "openssl" {
		t.Errorf("finding mapped incorrectly: %+v", v)
	}
}

func TestScanFailsClosed(t *testing.T) {
	ts := newTestServer(t, failStub(t))
	defer ts.Close()

	id := submitScan(t, ts.URL, ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", Tag: "3.14"},
	})

	status, body := pollReport(t, ts.URL, id)
	// Fail-closed: a trivy error must be a 500, NEVER a 200-with-empty-report.
	if status != http.StatusInternalServerError {
		t.Fatalf("failed scan status = %d, want 500; body=%s", status, body)
	}
}

func TestReportPendingReturns302(t *testing.T) {
	ts := newTestServer(t, slowStub(t))
	defer ts.Close()

	id := submitScan(t, ts.URL, ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", Tag: "3.14"},
	})

	// Immediately after submit the job is Pending/Running -> 302 + Refresh-After.
	client := noRedirectClient()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/scan/"+id+"/report", nil)
	req.Header.Set("Accept", reportMimeType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get report: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("pending status = %d, want 302", resp.StatusCode)
	}
	if ra := resp.Header.Get("Refresh-After"); ra != "5" {
		t.Errorf("Refresh-After = %q, want integer 5", ra)
	}
}

func TestReportUnknownIDReturns404(t *testing.T) {
	ts := newTestServer(t, succeedStub(t))
	defer ts.Close()

	client := noRedirectClient()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/scan/deadbeef/report", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get report: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id status = %d, want 404", resp.StatusCode)
	}
}

func TestScanRequestValidation(t *testing.T) {
	ts := newTestServer(t, succeedStub(t))
	defer ts.Close()

	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{not json`},
		{"missing repository", `{"registry":{"url":"http://b"},"artifact":{"tag":"1"}}`},
		{"both tag and digest", `{"artifact":{"repository":"r","tag":"1","digest":"sha256:x"}}`},
		{"neither tag nor digest", `{"artifact":{"repository":"r"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(ts.URL+"/api/v1/scan", "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestProbeReady(t *testing.T) {
	// A not-yet-ready server returns 503 until MarkReady.
	cfg := LoadConfig()
	srv := NewServer(cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/probe/ready")
	if err != nil {
		t.Fatalf("get ready: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d, want 503", resp.StatusCode)
	}

	srv.MarkReady()
	resp2, err := http.Get(ts.URL + "/probe/ready")
	if err != nil {
		t.Fatalf("get ready: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("ready status = %d, want 200", resp2.StatusCode)
	}
}

func TestHealthyProbe(t *testing.T) {
	ts := newTestServer(t, succeedStub(t))
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/probe/healthy")
	if err != nil {
		t.Fatalf("get healthy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthy status = %d, want 200", resp.StatusCode)
	}
}

func TestMetadata(t *testing.T) {
	ts := newTestServer(t, succeedStub(t))
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/v1/metadata")
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	body := readAll(t, resp)
	var meta ScannerMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.Scanner.Name != "Trivy" || meta.Scanner.Vendor != "Aqua Security" {
		t.Errorf("scanner info = %+v", meta.Scanner)
	}
	if len(meta.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(meta.Capabilities))
	}
	cap0 := meta.Capabilities[0]
	if len(cap0.ProducesMimeTypes) != 1 || cap0.ProducesMimeTypes[0] != reportMimeType {
		t.Errorf("produces = %v", cap0.ProducesMimeTypes)
	}
	if len(cap0.ConsumesMimeTypes) != 2 {
		t.Errorf("consumes = %v", cap0.ConsumesMimeTypes)
	}
}

func TestScanWithDigestReference(t *testing.T) {
	ts := newTestServer(t, succeedStub(t))
	defer ts.Close()
	id := submitScan(t, ts.URL, ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080", Authorization: "Bearer test.jwt.token"},
		Artifact: ArtifactRef{
			Repository: "oci-prod/app",
			MimeType:   ociManifestMimeType,
			Digest:     "sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b",
		},
	})
	status, body := pollReport(t, ts.URL, id)
	if status != http.StatusOK {
		t.Fatalf("digest scan status = %d, want 200; body=%s", status, body)
	}
}
