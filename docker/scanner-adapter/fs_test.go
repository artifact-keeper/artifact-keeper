package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tarOf builds an uncompressed in-memory tar from name->content pairs.
func tarOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write body %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func TestBuildFsArgs(t *testing.T) {
	cfg := LoadConfig()
	cfg.CacheDir = "/cache"
	cfg.FsScanTimeout = 10 * time.Minute
	s := NewScanner(cfg)
	got := strings.Join(s.buildFsArgs("/work"), " ")
	for _, want := range []string{
		"filesystem",
		"--format json",
		"--list-all-pkgs", // #903: SBOM package inventory
		"--severity CRITICAL,HIGH,MEDIUM,LOW",
		"--timeout 10m0s",
		"--cache-dir /cache",
		"--quiet",
		"/work",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fs args missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "image") {
		t.Errorf("fs args must not carry image mode: %s", got)
	}
}

func TestUntarWorkspaceExtractsRegularFiles(t *testing.T) {
	dst := t.TempDir()
	data := tarOf(t, map[string]string{
		"composer.lock":     `{"packages":[]}`,
		"nested/go.sum":     "example.com/x v1.0.0 h1:abc\n",
		"deep/a/b/c/d.json": "{}",
	})
	if err := untarWorkspace(bytes.NewReader(data), dst); err != nil {
		t.Fatalf("untar: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "nested", "go.sum"))
	if err != nil || !strings.Contains(string(got), "example.com/x") {
		t.Fatalf("nested file not extracted: %v %q", err, got)
	}
	if _, err := os.Stat(filepath.Join(dst, "deep/a/b/c/d.json")); err != nil {
		t.Fatalf("deep file not extracted: %v", err)
	}
}

func TestUntarWorkspaceRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: "../evil.txt", Mode: 0o600, Size: 4, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("pwnd")); err != nil {
		t.Fatal(err)
	}
	tw.Close()

	dst := t.TempDir()
	if err := untarWorkspace(bytes.NewReader(buf.Bytes()), dst); err == nil {
		t.Fatal("a ../-escaping tar entry must be rejected")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evil.txt")); err == nil {
		t.Fatal("escaping entry was materialized outside the workspace")
	}
}

func TestUntarWorkspaceSkipsSymlinks(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "escape", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink, Mode: 0o777,
	}); err != nil {
		t.Fatal(err)
	}
	tw.Close()

	dst := t.TempDir()
	if err := untarWorkspace(bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("symlink entries should be skipped, not fatal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "escape")); err == nil {
		t.Fatal("symlink must not be materialized")
	}
}

// fsSucceedStub emits a native trivy filesystem JSON report (with a Packages
// block, #903) on stdout and a warning on stderr, exit 0.
func fsSucceedStub(t *testing.T) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
echo "WARN unable to parse composer.json" 1>&2
cat <<'JSON'
{"Results":[{"Target":"composer.lock","Class":"lang-pkgs","Type":"composer",
  "Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1234","PkgName":"acme/lib","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Severity":"HIGH"}],
  "Packages":[{"Name":"acme/lib","Version":"1.0.0"}]}]}
JSON
`)
}

// submitFsScan POSTs a workspace tar and returns the assigned job id.
func submitFsScan(t *testing.T, base string, tarBody []byte) string {
	t.Helper()
	resp, err := http.Post(base+"/api/v1/filesystem/scan", "application/x-tar", bytes.NewReader(tarBody))
	if err != nil {
		t.Fatalf("post filesystem scan: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("fs scan submit status = %d, want 202", resp.StatusCode)
	}
	var sr ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		t.Fatalf("decode fs scan response: %v", err)
	}
	if sr.ID == "" {
		t.Fatal("empty fs scan id")
	}
	return sr.ID
}

// pollFsReport polls the fs report endpoint until it leaves pending, asserting
// the pending contract (302 + integer Refresh-After) along the way.
func pollFsReport(t *testing.T, base, id string) (int, []byte) {
	t.Helper()
	client := noRedirectClient()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(base + "/api/v1/filesystem/scan/" + id + "/report")
		if err != nil {
			t.Fatalf("get fs report: %v", err)
		}
		if resp.StatusCode == http.StatusFound {
			if ra := resp.Header.Get("Refresh-After"); ra != "5" {
				t.Errorf("pending Refresh-After = %q, want 5", ra)
			}
			resp.Body.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return resp.StatusCode, readAll(t, resp)
	}
	t.Fatal("fs report never left pending state")
	return 0, nil
}

// TestFsScanSucceedsWithNativeReport proves the full fs flow: tar upload ->
// untar -> trivy filesystem -> report body carrying the NATIVE trivy JSON
// (Packages included, #903) plus stderr (#1153) and the scanner version.
func TestFsScanSucceedsWithNativeReport(t *testing.T) {
	ts := newTestServer(t, fsSucceedStub(t))
	defer ts.Close()

	id := submitFsScan(t, ts.URL, tarOf(t, map[string]string{"composer.lock": "{}"}))
	status, body := pollFsReport(t, ts.URL, id)
	if status != http.StatusOK {
		t.Fatalf("fs report status = %d, want 200; body=%s", status, body)
	}

	var res FsScanResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("unmarshal fs result: %v", err)
	}
	if res.ScannerVersion != "0.71.2" {
		t.Errorf("scanner_version = %q, want 0.71.2", res.ScannerVersion)
	}
	if !strings.Contains(res.Stderr, "unable to parse composer.json") {
		t.Errorf("stderr not passed through: %q", res.Stderr)
	}
	// The report must be trivy's NATIVE shape including the Packages block.
	var report struct {
		Results []struct {
			Vulnerabilities []struct{ VulnerabilityID string } `json:"Vulnerabilities"`
			Packages        []struct{ Name string }            `json:"Packages"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(res.Report, &report); err != nil {
		t.Fatalf("unmarshal native report: %v", err)
	}
	if len(report.Results) != 1 || len(report.Results[0].Vulnerabilities) != 1 {
		t.Fatalf("native report vulns lost: %s", res.Report)
	}
	if len(report.Results[0].Packages) != 1 || report.Results[0].Packages[0].Name != "acme/lib" {
		t.Fatalf("Packages block (SBOM inventory, #903) lost: %s", res.Report)
	}
}

// TestFsScanTrivyErrorFailsClosed: a non-zero trivy exit must surface as a 500
// on the report endpoint, never a 200 with an empty report.
func TestFsScanTrivyErrorFailsClosed(t *testing.T) {
	ts := newTestServer(t, failStub(t))
	defer ts.Close()

	id := submitFsScan(t, ts.URL, tarOf(t, map[string]string{"go.sum": ""}))
	status, body := pollFsReport(t, ts.URL, id)
	if status != http.StatusInternalServerError {
		t.Fatalf("failed fs scan status = %d, want 500; body=%s", status, body)
	}
}

// TestFsScanExit0DBFailureFailsClosed: trivy exiting 0 while its stderr carries
// a DB-fatal marker is a FALSE CLEAN; the job must fail (report 500).
func TestFsScanExit0DBFailureFailsClosed(t *testing.T) {
	stub := writeStub(t, "#!/bin/sh\n"+stubVersion+`
echo "FATAL failed to download vulnerability DB" 1>&2
echo '{"Results":[]}'
exit 0
`)
	ts := newTestServer(t, stub)
	defer ts.Close()

	id := submitFsScan(t, ts.URL, tarOf(t, map[string]string{"go.sum": ""}))
	status, body := pollFsReport(t, ts.URL, id)
	if status != http.StatusInternalServerError {
		t.Fatalf("exit-0 DB failure must fail closed: status = %d; body=%s", status, body)
	}
}

// TestFsScanInvalidTarRejected: a non-tar body is a 400 at submit time.
func TestFsScanInvalidTarRejected(t *testing.T) {
	ts := newTestServer(t, fsSucceedStub(t))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/filesystem/scan", "application/x-tar",
		strings.NewReader("this is not a tar archive at all, padded to look like one ............"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid tar status = %d, want 400", resp.StatusCode)
	}
}

// TestFsReportUnknownID: an unknown/expired id is a terminal 404.
func TestFsReportUnknownID(t *testing.T) {
	ts := newTestServer(t, fsSucceedStub(t))
	defer ts.Close()

	resp, err := noRedirectClient().Get(ts.URL + "/api/v1/filesystem/scan/deadbeef/report")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id status = %d, want 404", resp.StatusCode)
	}
}
