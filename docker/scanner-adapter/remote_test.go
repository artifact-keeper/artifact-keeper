package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	if err := checkTrivyServer(ctx, client, ok.URL, ""); err != nil {
		t.Errorf("unknown local version skips the version comparison: %v", err)
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
	if g.Ready(context.Background()) == nil {
		t.Fatal("first check must report the failure")
	}
	fail = false
	if g.Ready(context.Background()) == nil {
		t.Fatal("cached failure must persist within ttl")
	}
	if calls.Load() != 1 {
		t.Fatalf("check ran %d times within ttl, want 1", calls.Load())
	}
	g.checked = time.Now().Add(-2 * time.Hour)
	if err := g.Ready(context.Background()); err != nil {
		t.Fatalf("expired cache must re-check: %v", err)
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
	cfg.ScannerVersion = "0.74.0"
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
