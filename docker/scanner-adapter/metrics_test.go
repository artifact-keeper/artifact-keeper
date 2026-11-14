package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, m *Metrics, s *Scheduler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler(s).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	return rec.Body.String()
}

func wantLine(t *testing.T, body, line string) {
	t.Helper()
	for _, l := range strings.Split(body, "\n") {
		if l == line {
			return
		}
	}
	t.Errorf("metrics lack %q:\n%s", line, body)
}

func TestMetricsExposition(t *testing.T) {
	s, clock := testSched(1, nil, 30*time.Minute)
	m := NewMetrics(false)
	s.onGrant = m.ObserveWait
	a := s.Enqueue("a.example", PriorityInteractive) // starts at once: wait 0
	s.Enqueue("b.example", PriorityInteractive)
	s.Enqueue("c.example", PriorityBackground)
	body := scrape(t, m, s)
	for _, l := range []string{
		"# TYPE scanner_adapter_jobs_queued gauge",
		`scanner_adapter_jobs_queued{priority="interactive"} 1`,
		`scanner_adapter_jobs_queued{priority="background"} 1`,
		"scanner_adapter_jobs_running 1",
		"scanner_adapter_slots_capacity 1",
		"# TYPE scanner_adapter_queue_wait_seconds histogram",
		`scanner_adapter_queue_wait_seconds_bucket{le="0.1"} 1`,
		`scanner_adapter_queue_wait_seconds_bucket{le="+Inf"} 1`,
		"scanner_adapter_queue_wait_seconds_count 1",
		"# TYPE scanner_adapter_jobs_total counter",
		`scanner_adapter_jobs_total{outcome="succeeded"} 0`,
		`scanner_adapter_jobs_total{outcome="failed"} 0`,
	} {
		wantLine(t, body, l)
	}
	if strings.Contains(body, "client") {
		t.Errorf("per-client series must be opt-in:\n%s", body)
	}

	clock.Advance(90 * time.Second)
	a.Release() // b waited 90s
	m.JobDone(outcomeSucceeded)
	body = scrape(t, m, s)
	wantLine(t, body, `scanner_adapter_queue_wait_seconds_bucket{le="60"} 1`)
	wantLine(t, body, `scanner_adapter_queue_wait_seconds_bucket{le="120"} 2`)
	wantLine(t, body, "scanner_adapter_queue_wait_seconds_sum 90")
	wantLine(t, body, `scanner_adapter_jobs_total{outcome="succeeded"} 1`)
}

func TestMetricsPerClientLabelOptIn(t *testing.T) {
	s, _ := testSched(1, nil, 0)
	m := NewMetrics(true)
	s.Enqueue("a.example:8080", PriorityInteractive)
	s.Enqueue("b\"x.example", PriorityBackground)
	body := scrape(t, m, s)
	wantLine(t, body, `scanner_adapter_client_jobs_running{client="a.example:8080"} 1`)
	wantLine(t, body, `scanner_adapter_client_jobs_queued{client="b\"x.example",priority="background"} 1`)
	wantLine(t, body, `scanner_adapter_client_jobs_queued{client="a.example:8080",priority="interactive"} 0`)
}

// countingStub is a trivy stub that reports a clean image; a scan of a
// repository named "fail" exits non-zero.
func countingStub(t *testing.T) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
case " $* " in *"/fail:"*) echo "boom" >&2; exit 1;; esac
echo '{"Results":[]}'
`)
}

// TestMetricsReadZeroAfterQueueDrains drives scans through the HTTP API
// with one slot, so most of them queue, and checks the gauges are back to 0
// once every report is in, with every job counted by outcome.
func TestMetricsReadZeroAfterQueueDrains(t *testing.T) {
	cfg := LoadConfig()
	cfg.TrivyPath = countingStub(t)
	cfg.CacheDir = t.TempDir()
	cfg.ScannerVersion = "0.71.2"
	cfg.MaxConcurrentScans = 1
	srv := NewServer(cfg)
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var ids []string
	for i, repo := range []string{"app", "app", "fail", "app", "app", "app"} {
		req := ScanRequest{
			Registry: RegistryRef{URL: "http://ak-" + itoa(i%2) + ".example:8080"},
			Artifact: ArtifactRef{Repository: repo, Tag: "v" + itoa(i)},
		}
		if i%3 == 0 {
			req.Priority = "background"
		}
		ids = append(ids, submitScan(t, ts.URL, req))
	}
	for _, id := range ids {
		pollReport(t, ts.URL, id)
	}
	// A job's slot is released just after its report is stored, so wait
	// for the last release rather than sleep a fixed time.
	deadline := time.Now().Add(5 * time.Second)
	for srv.sched.Snapshot(false).running != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	body := scrape(t, srv.metrics, srv.sched)
	for _, l := range []string{
		`scanner_adapter_jobs_queued{priority="interactive"} 0`,
		`scanner_adapter_jobs_queued{priority="background"} 0`,
		"scanner_adapter_jobs_running 0",
		"scanner_adapter_slots_capacity 1",
		"scanner_adapter_queue_wait_seconds_count 6",
		`scanner_adapter_jobs_total{outcome="succeeded"} 5`,
		`scanner_adapter_jobs_total{outcome="failed"} 1`,
	} {
		wantLine(t, body, l)
	}
	if n := len(srv.sched.clients); n != 0 {
		t.Errorf("%d idle clients left in the scheduler", n)
	}
}

func TestScanRejectsUnknownPriority(t *testing.T) {
	ts := newTestServer(t, countingStub(t))
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/api/v1/scan", "application/json", strings.NewReader(
		`{"registry":{"url":"http://ak.example"},"artifact":{"repository":"app","tag":"1"},"priority":"urgent"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/filesystem/scan", bytes.NewReader(tarOf(t, map[string]string{"a": "b"})))
	req.Header.Set(scanPriorityHeader, "urgent")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), scanPriorityHeader) {
		t.Fatalf("fs status %d (%s), want 400 naming the header", resp.StatusCode, b)
	}
}

func TestWatchClientLimitsReloadsOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "limits.yaml")
	if err := os.WriteFile(path, []byte("a.example: {max_concurrent: 1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applied := make(chan *ClientLimits, 4)
	stop := make(chan struct{})
	defer close(stop)
	go watchClientLimits(path, statClientLimits(path), 5*time.Millisecond, func(l *ClientLimits) { applied <- l }, stop)

	write := func(content string, mtime time.Time) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(time.Hour)
	// An invalid edit is ignored (the previous limits stay)...
	write("a.example: {max_concurrent: -1}\n", base)
	// ...and the next valid one is applied.
	write("a.example: {max_concurrent: 3}\n", base.Add(time.Minute))
	select {
	case l := <-applied:
		if got := l.For("a.example").MaxConcurrent; got != 3 {
			t.Fatalf("reloaded max_concurrent = %d, want 3", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("limits file change was not picked up")
	}
}

// TestWatchClientLimitsSeesEditBeforeFirstCheck: the stamp is taken before
// the initial load, so an edit made between the load and the watcher's first
// check is applied.
func TestWatchClientLimitsSeesEditBeforeFirstCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "limits.yaml")
	if err := os.WriteFile(path, []byte("a.example: {max_concurrent: 1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := statClientLimits(path)
	if _, err := loadClientLimitsFile(path); err != nil {
		t.Fatal(err)
	}
	// Edited right after the initial load, before the watcher starts.
	if err := os.WriteFile(path, []byte("a.example: {max_concurrent: 2}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	applied := make(chan *ClientLimits, 1)
	stop := make(chan struct{})
	defer close(stop)
	go watchClientLimits(path, stamp, 5*time.Millisecond, func(l *ClientLimits) { applied <- l }, stop)
	select {
	case l := <-applied:
		if got := l.For("a.example").MaxConcurrent; got != 2 {
			t.Fatalf("max_concurrent = %d, want 2", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the edit made before the first check was missed")
	}
}
