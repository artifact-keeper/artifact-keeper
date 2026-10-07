package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTrivyServer serves a trivy-server-shaped GET /version.
func fakeTrivyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

const versionWithDB = `{"Version":"0.74.0","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-09-30T00:00:00Z"}}`

func TestLoadConfigClientModeDefaultsOff(t *testing.T) {
	t.Setenv("SCANNER_TRIVY_SERVER", "")
	t.Setenv("SCANNER_TRIVY_CACHE_PARTITION", "")
	cfg := LoadConfig()
	if cfg.TrivyServer != "" || cfg.CachePartition != "" {
		t.Fatalf("client mode must be off by default, got server=%q partition=%q", cfg.TrivyServer, cfg.CachePartition)
	}
	if args := cfg.clientArgs(); len(args) != 0 {
		t.Fatalf("standalone mode must add no client args, got %v", args)
	}
}

func TestLoadConfigClientModeTrimsServer(t *testing.T) {
	t.Setenv("SCANNER_TRIVY_SERVER", " http://trivy.scan:4954/ ")
	t.Setenv("SCANNER_TRIVY_CACHE_PARTITION", "team-a")
	cfg := LoadConfig()
	if cfg.TrivyServer != "http://trivy.scan:4954" {
		t.Errorf("TrivyServer = %q", cfg.TrivyServer)
	}
	if cfg.CachePartition != "team-a" {
		t.Errorf("CachePartition = %q", cfg.CachePartition)
	}
}

func TestBuildArgsClientMode(t *testing.T) {
	cfg := LoadConfig()
	cfg.TrivyServer = "http://trivy.scan:4954"
	cfg.CachePartition = "team-a"
	s := NewScanner(cfg)
	for name, args := range map[string][]string{
		"image":      s.buildArgs("backend:8080/repo/app:1"),
		"filesystem": s.buildFsArgs("/tmp/ws"),
	} {
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--server http://trivy.scan:4954") {
			t.Errorf("%s args missing --server: %v", name, args)
		}
		if !strings.Contains(joined, "--skip-dirs "+cachePartitionDir("team-a")) {
			t.Errorf("%s args missing partition: %v", name, args)
		}
	}
	// The target stays the last argument.
	if args := s.buildArgs("backend:8080/repo/app:1"); args[len(args)-1] != "backend:8080/repo/app:1" {
		t.Errorf("image ref not last: %v", args)
	}
	if args := s.buildFsArgs("/tmp/ws"); args[len(args)-1] != "/tmp/ws" {
		t.Errorf("fs dir not last: %v", args)
	}
}

func TestCachePartitionDirIsStableDistinctAndGlobSafe(t *testing.T) {
	a, b := cachePartitionDir("team-a"), cachePartitionDir("team-b")
	if a != cachePartitionDir("team-a") {
		t.Error("partition dir must be deterministic")
	}
	if a == b {
		t.Error("distinct partitions must yield distinct dirs")
	}
	weird := cachePartitionDir("a*b?[c]/../{d}")
	if strings.ContainsAny(strings.TrimPrefix(weird, "/"), "*?[]{}/") {
		t.Errorf("partition dir must be glob-safe, got %q", weird)
	}
}

func TestCheckTrivyServer(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	ok := fakeTrivyServer(t, http.StatusOK, versionWithDB)
	defer ok.Close()
	if err := checkTrivyServer(ctx, client, ok.URL, "0.74.0"); err != nil {
		t.Errorf("matching server with DB: %v", err)
	}
	if err := checkTrivyServer(ctx, client, ok.URL+"/", "v0.74.0"); err != nil {
		t.Errorf("v-prefix and trailing slash must be tolerated: %v", err)
	}
	if err := checkTrivyServer(ctx, client, ok.URL, ""); err == nil {
		t.Error("unknown client version must fail closed, not skip the comparison")
	}
	if err := checkTrivyServer(ctx, client, ok.URL, "0.62.1"); err == nil || !strings.Contains(err.Error(), "matching releases") {
		t.Errorf("version mismatch must fail, got %v", err)
	}

	for name, body := range map[string]string{
		"null DB":    `{"Version":"0.74.0","VulnerabilityDB":null}`,
		"missing DB": `{"Version":"0.74.0"}`,
	} {
		srv := fakeTrivyServer(t, http.StatusOK, body)
		if err := checkTrivyServer(ctx, client, srv.URL, "0.74.0"); err == nil {
			t.Errorf("%s must fail closed", name)
		}
		srv.Close()
	}

	bad := fakeTrivyServer(t, http.StatusInternalServerError, "boom")
	defer bad.Close()
	if err := checkTrivyServer(ctx, client, bad.URL, "0.74.0"); err == nil {
		t.Error("non-200 must fail")
	}
	if err := checkTrivyServer(ctx, client, "trivy.scan:4954", "0.74.0"); err == nil {
		t.Error("URL without scheme must fail")
	}
	down := fakeTrivyServer(t, http.StatusOK, versionWithDB)
	down.Close()
	if err := checkTrivyServer(ctx, client, down.URL, "0.74.0"); err == nil {
		t.Error("unreachable server must fail")
	}
}

func TestRemoteGateCachesWithinTTL(t *testing.T) {
	var calls atomic.Int32
	fail := true
	g := newRemoteGate(time.Hour, func(context.Context) error {
		calls.Add(1)
		if fail {
			return errors.New("down")
		}
		return nil
	})
	if fresh, err := g.Ready(); err == nil || !fresh {
		t.Fatalf("first check must run and report the failure, got fresh=%v err=%v", fresh, err)
	}
	fail = false
	if fresh, err := g.Ready(); err == nil || fresh {
		t.Fatalf("cached failure must persist within ttl, got fresh=%v err=%v", fresh, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("check ran %d times within ttl, want 1", calls.Load())
	}
	g.checked = time.Now().Add(-2 * time.Hour)
	if fresh, err := g.Ready(); err != nil || !fresh {
		t.Fatalf("expired cache must re-check: fresh=%v err=%v", fresh, err)
	}
}

// TestProbeReadyClientModeFollowsServer: in client mode /probe/ready is 200 only
// while the trivy server answers with a DB and the same version.
func TestProbeReadyClientModeFollowsServer(t *testing.T) {
	var body atomic.Value
	body.Store(versionWithDB)
	trivy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer trivy.Close()

	cfg := LoadConfig()
	cfg.TrivyServer = trivy.URL
	// The gate compares against the probed binary, not the reported pin.
	cfg.ScannerVersion = "9.9.9"
	cfg.ClientVersion = "0.74.0"
	srv := NewServer(cfg)
	srv.remote.ttl = 0 // re-check on every probe for the test
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if code := getStatus(t, ts.URL+"/probe/ready"); code != http.StatusServiceUnavailable {
		t.Fatalf("before MarkReady status = %d, want 503", code)
	}
	srv.MarkReady()
	if code := getStatus(t, ts.URL+"/probe/ready"); code != http.StatusOK {
		t.Fatalf("server with DB status = %d, want 200", code)
	}
	body.Store(`{"Version":"0.74.0","VulnerabilityDB":null}`)
	if code := getStatus(t, ts.URL+"/probe/ready"); code != http.StatusServiceUnavailable {
		t.Fatalf("server without DB status = %d, want 503", code)
	}
	body.Store(`{"Version":"0.63.0","VulnerabilityDB":{"Version":2}}`)
	if code := getStatus(t, ts.URL+"/probe/ready"); code != http.StatusServiceUnavailable {
		t.Fatalf("mismatched server status = %d, want 503", code)
	}
}

func TestStandaloneModeHasNoRemoteGate(t *testing.T) {
	cfg := LoadConfig()
	cfg.TrivyServer = ""
	if NewServer(cfg).remote != nil {
		t.Fatal("standalone mode must not consult a trivy server")
	}
}

// TestRemoteGateIgnoresCallerContext: the check runs on its own short deadline,
// so a backend that abandons a slow probe cannot cache "context canceled".
func TestRemoteGateIgnoresCallerContext(t *testing.T) {
	var deadline time.Time
	g := newRemoteGate(time.Hour, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline, _ = ctx.Deadline()
		return nil
	})
	if _, err := g.Ready(); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if left := time.Until(deadline); left <= 0 || left > readinessCheckTimeout {
		t.Fatalf("check deadline %v away, want within %v", left, readinessCheckTimeout)
	}
	if readinessCheckTimeout >= 5*time.Second {
		t.Fatalf("readiness check timeout %v must stay under the backend's 5s probe timeout", readinessCheckTimeout)
	}
}

func TestValidateClientMode(t *testing.T) {
	cases := []struct {
		name           string
		server         string
		insecure       bool
		serverInsecure bool
		wantErr        string
	}{
		{"http with registry --insecure", "http://trivy:4954", true, false, ""},
		{"https verified", "https://trivy:4954", false, false, ""},
		{"https with --insecure, no opt-in", "https://trivy:4954", true, false, "SCANNER_TRIVY_SERVER_INSECURE"},
		{"https with --insecure, opted in", "https://trivy:4954", true, true, ""},
		{"no scheme", "trivy:4954", false, false, "absolute http(s) URL"},
		{"ftp scheme", "ftp://trivy:4954", false, false, "absolute http(s) URL"},
		{"path prefix", "http://proxy/trivy", false, false, "no path"},
		{"query", "http://trivy:4954?x=1", false, false, "no path"},
		{"userinfo", "http://u:secret@trivy:4954", false, false, "credentials"},
	}
	for _, c := range cases {
		cfg := &Config{TrivyServer: c.server, Insecure: c.insecure, TrivyServerInsecure: c.serverInsecure}
		err := cfg.validateClientMode()
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: error %v, want one mentioning %q", c.name, err, c.wantErr)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: error leaks the URL password: %v", c.name, err)
		}
	}
}

// TestStartClientModeHTTPSInsecureFailsClosed: an https server with the default
// SCANNER_TRIVY_INSECURE=true and no opt-in keeps the adapter not-ready; the
// explicit SCANNER_TRIVY_SERVER_INSECURE=true opt-in lets it start, and the
// readiness client then skips verification like the trivy subprocess does.
func TestStartClientModeHTTPSInsecureFailsClosed(t *testing.T) {
	stub := succeedStub(t)
	newCfg := func(optIn bool) *Config {
		cfg := LoadConfig()
		cfg.TrivyPath = stub
		cfg.TrivyServer = "https://trivy.scan:4954"
		cfg.Insecure = true
		cfg.TrivyServerInsecure = optIn
		cfg.ScannerVersion = ""
		return cfg
	}

	srv := NewServer(newCfg(false))
	if err := srv.startClientMode(context.Background()); err == nil || !strings.Contains(err.Error(), "SCANNER_TRIVY_SERVER_INSECURE") {
		t.Fatalf("https + --insecure without opt-in must refuse, got %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if code := getStatus(t, ts.URL+"/probe/ready"); code != http.StatusServiceUnavailable {
		t.Fatalf("refused client mode /probe/ready = %d, want 503", code)
	}

	optedIn := NewServer(newCfg(true))
	if err := optedIn.startClientMode(context.Background()); err != nil {
		t.Fatalf("opted-in client mode: %v", err)
	}
	if !optedIn.ready.Load() {
		t.Fatal("opted-in client mode must mark the adapter ready")
	}
	tr, ok := newServerHTTPClient(optedIn.cfg).Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("opted-in readiness client must match trivy's unverified TLS")
	}
	if newServerHTTPClient(newCfg(false)).Transport != nil {
		t.Fatal("without the opt-in the readiness client must use verified default TLS")
	}
}

// TestStartClientModeProbesBinaryDespitePin: SCANNER_SCANNER_VERSION stays the
// reported version, but the server is matched against the probed binary.
func TestStartClientModeProbesBinaryDespitePin(t *testing.T) {
	cfg := LoadConfig()
	cfg.TrivyPath = succeedStub(t)
	cfg.TrivyServer = "http://trivy.scan:4954"
	cfg.ScannerVersion = "9.9.9"
	srv := NewServer(cfg)
	if err := srv.startClientMode(context.Background()); err != nil {
		t.Fatalf("startClientMode: %v", err)
	}
	if cfg.ClientVersion != "0.71.2" || cfg.ScannerVersion != "9.9.9" {
		t.Fatalf("ClientVersion=%q ScannerVersion=%q, want probed 0.71.2 and pin 9.9.9 kept", cfg.ClientVersion, cfg.ScannerVersion)
	}

	broken := LoadConfig()
	broken.TrivyPath = filepath.Join(t.TempDir(), "no-trivy")
	broken.TrivyServer = "http://trivy.scan:4954"
	broken.ScannerVersion = "9.9.9"
	bsrv := NewServer(broken)
	if err := bsrv.startClientMode(context.Background()); err == nil || bsrv.ready.Load() {
		t.Fatal("a pinned version must not hide a broken bundled trivy")
	}
}

// realClientReportTrivy is the `Trivy` block of a real trivy 0.74.0
// `fs --server` report, captured against a 0.74.0 `trivy server`.
const realClientReportTrivy = `{"Version":"0.74.0","Server":{"Version":"0.74.0","VulnerabilityDB":{"Version":2,"NextUpdate":"2026-10-06T07:14:49.216148168Z","UpdatedAt":"2026-10-05T07:14:49.216148418Z","DownloadedAt":"2026-10-05T12:27:34.522438333Z"}}}`

func TestClientModeProvenanceFromRealReport(t *testing.T) {
	var info trivyReportInfo
	if err := json.Unmarshal([]byte(realClientReportTrivy), &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	db, err := clientModeProvenance(info, "0.74.0")
	if err != nil {
		t.Fatalf("clientModeProvenance: %v", err)
	}
	want := time.Date(2026, 10, 5, 7, 14, 49, 216148418, time.UTC)
	if db == nil || db.Version != 2 || db.UpdatedAt == nil || !db.UpdatedAt.Equal(want) {
		t.Fatalf("provenance = %+v, want version 2 updated %v", db, want)
	}
}

func TestClientModeProvenanceFailsClosed(t *testing.T) {
	for name, raw := range map[string]string{
		"standalone-shaped report (no Server)": `{"Version":"0.74.0"}`,
		"server version fetch failed":          `{"Version":"0.74.0","Server":{}}`,
		"server without DB":                    `{"Version":"0.74.0","Server":{"Version":"0.74.0"}}`,
		"server DB null":                       `{"Version":"0.74.0","Server":{"Version":"0.74.0","VulnerabilityDB":null}}`,
		"release mismatch":                     `{"Version":"0.74.0","Server":{"Version":"0.73.1","VulnerabilityDB":{"Version":2}}}`,
	} {
		var info trivyReportInfo
		if err := json.Unmarshal([]byte(raw), &info); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if db, err := clientModeProvenance(info, "0.74.0"); err == nil {
			t.Errorf("%s: expected the scan to fail closed, got %+v", name, db)
		}
	}
	// A DB block that is present but unidentifiable only omits provenance.
	var info trivyReportInfo
	_ = json.Unmarshal([]byte(`{"Server":{"Version":"0.74.0","VulnerabilityDB":{"UpdatedAt":"2026-10-05T00:00:00Z"}}}`), &info)
	if db, err := clientModeProvenance(info, "0.74.0"); err != nil || db != nil {
		t.Errorf("malformed DB block: got db=%+v err=%v, want omitted without failing", db, err)
	}
}

// clientStub is a trivy stub for client mode: it prints the given report
// `Trivy` block on top of the usual image or fs results.
func clientStub(t *testing.T, trivyBlock string, fs bool) string {
	results := `"Results":[{"Target":"alpine:3.14","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2021-3711","PkgName":"openssl","InstalledVersion":"1.1.1k","FixedVersion":"1.1.1l","Severity":"CRITICAL"}]}]`
	if fs {
		results = `"Results":[{"Target":"composer.lock","Class":"lang-pkgs","Type":"composer","Packages":[{"Name":"acme/lib","Version":"1.0.0"}]}]`
	}
	return writeStub(t, "#!/bin/sh\n"+stubVersion+"\ncat <<'JSON'\n{\"SchemaVersion\":2,\"Trivy\":"+trivyBlock+","+results+"}\nJSON\n")
}

// stubServerBlock is a report Trivy block from a server matching the stub
// client (0.71.2) whose DB is newer than the cache's stale metadata.json.
const stubServerBlock = `{"Version":"0.71.2","Server":{"Version":"0.71.2","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-10-05T01:00:00.5Z"}}}`

var serverDBUpdatedAt = time.Date(2026, 10, 5, 1, 0, 0, 500000000, time.UTC)

// clientModeServer is an adapter test server in client mode over a cache that
// still holds a (stale) local metadata.json, as a persistent cache volume from
// an earlier standalone deployment would. The scan path never contacts the
// server URL: everything it checks comes from the (stubbed) trivy report.
func clientModeServer(t *testing.T, stub string) *httptest.Server {
	t.Helper()
	return newTestServerWithConfig(t, stub, cacheWithDBMetadata(t), func(cfg *Config) {
		cfg.TrivyServer = "http://trivy.scan:4954"
		cfg.ClientVersion = cfg.ScannerVersion
	})
}

func runClientImageScan(t *testing.T, stub string) (int, []byte) {
	t.Helper()
	ts := clientModeServer(t, stub)
	defer ts.Close()
	id := submitScan(t, ts.URL, ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "docker-local/alpine", MimeType: dockerManifestMimeType, Tag: "3.14"},
	})
	return pollReport(t, ts.URL, id)
}

func runClientFsScan(t *testing.T, stub string) (int, []byte) {
	t.Helper()
	ts := clientModeServer(t, stub)
	defer ts.Close()
	id := submitFsScan(t, ts.URL, tarOf(t, map[string]string{"composer.lock": "{}"}))
	return pollFsReport(t, ts.URL, id)
}

// TestClientModeTakesDBFromReport: on both paths the provenance is the server
// DB named in the scan's own report, not the stale local metadata.json.
func TestClientModeTakesDBFromReport(t *testing.T) {
	status, body := runClientImageScan(t, clientStub(t, stubServerBlock, false))
	if status != http.StatusOK {
		t.Fatalf("image report status = %d, want 200; body=%s", status, body)
	}
	var report HarborScanReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if db := report.VulnerabilityDB; db == nil || db.UpdatedAt == nil || !db.UpdatedAt.Equal(serverDBUpdatedAt) {
		t.Errorf("image vulnerability_db = %+v, want the server's DB (updated %v)", db, serverDBUpdatedAt)
	}
	if len(report.Vulnerabilities) != 1 {
		t.Errorf("image findings = %d, want 1", len(report.Vulnerabilities))
	}

	status, body = runClientFsScan(t, clientStub(t, stubServerBlock, true))
	if status != http.StatusOK {
		t.Fatalf("fs report status = %d, want 200; body=%s", status, body)
	}
	var res FsScanResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("unmarshal fs result: %v", err)
	}
	if db := res.VulnerabilityDB; db == nil || db.UpdatedAt == nil || !db.UpdatedAt.Equal(serverDBUpdatedAt) {
		t.Errorf("fs vulnerability_db = %+v, want the server's DB", db)
	}
	if !strings.Contains(string(res.Report), `"Packages"`) {
		t.Errorf("fs report must still pass through verbatim: %s", res.Report)
	}
}

// TestClientModeScanFailsClosedOnServerMismatch: a scan whose report shows a
// different server release, or no server info at all, fails (500) on both
// paths instead of returning possibly incomplete findings.
func TestClientModeScanFailsClosedOnServerMismatch(t *testing.T) {
	for name, block := range map[string]string{
		"mismatch":       `{"Version":"0.71.2","Server":{"Version":"0.74.0","VulnerabilityDB":{"Version":2}}}`,
		"no server info": `{"Version":"0.71.2"}`,
	} {
		if status, body := runClientImageScan(t, clientStub(t, block, false)); status != http.StatusInternalServerError {
			t.Errorf("%s: image report status = %d, want 500; body=%s", name, status, body)
		}
		if status, body := runClientFsScan(t, clientStub(t, block, true)); status != http.StatusInternalServerError {
			t.Errorf("%s: fs report status = %d, want 500; body=%s", name, status, body)
		}
	}
}

// TestClientModeMalformedDBOmitsVulnDB: a verified server whose DB block cannot
// be parsed keeps the scan result and omits the field on both paths (never
// filled from the local cache).
func TestClientModeMalformedDBOmitsVulnDB(t *testing.T) {
	block := `{"Version":"0.71.2","Server":{"Version":"0.71.2","VulnerabilityDB":{"UpdatedAt":"2026-10-05T01:00:00Z"}}}`
	for name, run := range map[string]func(*testing.T, string) (int, []byte){
		"image": runClientImageScan,
		"fs":    runClientFsScan,
	} {
		status, body := run(t, clientStub(t, block, name == "fs"))
		if status != http.StatusOK {
			t.Fatalf("%s report status = %d, want 200; body=%s", name, status, body)
		}
		if strings.Contains(string(body), "vulnerability_db") {
			t.Errorf("%s: vulnerability_db must be omitted: %s", name, body)
		}
	}
}
