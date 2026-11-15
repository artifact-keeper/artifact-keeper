package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Backward-compatibility tests (#5944): with no limits file, no priority and
// no client headers, the adapter schedules exactly as before: up to
// SCANNER_MAX_CONCURRENT_SCANS at once, the rest in arrival order.

// TestCompatSingleClientNoLimitsIsFIFOAtFullCapacity: one client, no limits:
// the first N jobs start at once (no per-client cap) and the rest start in
// arrival order, one per released slot.
func TestCompatSingleClientNoLimitsIsFIFOAtFullCapacity(t *testing.T) {
	for _, capacity := range []int{1, 4} {
		s, _ := testSched(capacity, nil, 30*time.Minute)
		s.fair = false // no limits file: the default path
		tr := newTracker(t, s)
		for i := 0; i < 20; i++ {
			tr.add("ak.example:8080", PriorityInteractive, fmt.Sprintf("J%02d", i))
		}
		first := tr.newlyGranted()
		if len(first) != capacity {
			t.Fatalf("capacity %d: %d jobs started at once, want %d", capacity, len(first), capacity)
		}
		order := append(first, func() []string {
			var out []string
			for _, tk := range tr.tickets {
				tk.Release()
				out = append(out, tr.newlyGranted()...)
			}
			return out
		}()...)
		for i, l := range order {
			if l != fmt.Sprintf("J%02d", i) {
				t.Fatalf("capacity %d: order %v is not arrival order", capacity, order)
			}
		}
	}
}

// TestCompatNoLimitsFileIsGlobalArrivalOrder: without a limits file there
// is no per-client scheduling at all: several clients' jobs start in global
// arrival order, as before #5944.
func TestCompatNoLimitsFileIsGlobalArrivalOrder(t *testing.T) {
	s, _ := testSched(1, nil, 30*time.Minute)
	s.fair = false
	tr := newTracker(t, s)
	for i := 0; i < 10; i++ {
		tr.add("a.example", PriorityInteractive, fmt.Sprintf("A%d", i))
	}
	tr.add("b.example", PriorityInteractive, "B0")
	if got := fmt.Sprint(tr.runOrder()); got != "[A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 B0]" {
		t.Fatalf("order %s, want arrival order", got)
	}
	cfg := LoadConfig()
	cfg.ClientLimitsFile = ""
	if NewServer(cfg).sched.fair {
		t.Fatal("fair queueing must be off without SCANNER_CLIENT_LIMITS_FILE")
	}
}

// TestCompatUnboundedNoLimitsStartsEverything: SCANNER_MAX_CONCURRENT_SCANS=0
// and no limits still start every job at once, across clients and bands.
func TestCompatUnboundedNoLimitsStartsEverything(t *testing.T) {
	s, _ := testSched(0, nil, 30*time.Minute)
	tr := newTracker(t, s)
	for i := 0; i < 30; i++ {
		tr.add(fmt.Sprintf("c%d", i%3), Priority(i%2), "x")
	}
	if got := tr.newlyGranted(); len(got) != 30 {
		t.Fatalf("%d of 30 started", len(got))
	}
}

// oldStyleImageScanBody is a POST /api/v1/scan body as a 1.11.x backend sends it:
// no priority field.
const oldStyleImageScanBody = `{"registry":{"url":"http://ak-backend:8080","authorization":"Bearer t0k"},"artifact":{"repository":"library/app","mime_type":"application/vnd.docker.distribution.manifest.v2+json","tag":"1"}}`

// TestCompatOldStyleRequestsRunInInteractiveBand: an old-style image request
// and a header-less filesystem upload are accepted with the same responses
// as before and are scheduled in the interactive band (so they are never
// held back as background work).
func TestCompatOldStyleRequestsRunInInteractiveBand(t *testing.T) {
	var req ScanRequest
	if err := json.Unmarshal([]byte(oldStyleImageScanBody), &req); err != nil {
		t.Fatal(err)
	}
	if band, err := parsePriority(req.Priority); err != nil || band != PriorityInteractive {
		t.Fatalf("old-style request band = %v, %v; want interactive", band, err)
	}

	// Hold the only slot so the requests below queue and their band is
	// visible in the scheduler.
	cfg := LoadConfig()
	cfg.TrivyPath = countingStub(t)
	cfg.CacheDir = t.TempDir()
	cfg.ScannerVersion = "0.71.2"
	cfg.MaxConcurrentScans = 1
	srv := NewServer(cfg)
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	hold := srv.sched.Enqueue("holder", PriorityInteractive)

	resp, err := http.Post(ts.URL+"/api/v1/scan", "application/json", strings.NewReader(oldStyleImageScanBody))
	if err != nil {
		t.Fatal(err)
	}
	var sr ScanResponse
	if resp.StatusCode != http.StatusAccepted || json.NewDecoder(resp.Body).Decode(&sr) != nil || sr.ID == "" {
		t.Fatalf("old-style image request: status %d", resp.StatusCode)
	}
	resp.Body.Close()
	fresp, err := http.Post(ts.URL+"/api/v1/filesystem/scan", "application/x-tar", bytes.NewReader(tarOf(t, map[string]string{"a": "b"})))
	if err != nil {
		t.Fatal(err)
	}
	var fr ScanResponse
	if fresp.StatusCode != http.StatusAccepted || json.NewDecoder(fresp.Body).Decode(&fr) != nil || fr.ID == "" {
		t.Fatalf("header-less fs request: status %d", fresp.StatusCode)
	}
	fresp.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	var snap schedSnapshot
	for time.Now().Before(deadline) {
		if snap = srv.sched.Snapshot(true); snap.queued[PriorityInteractive] == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if snap.queued[PriorityInteractive] != 2 || snap.queued[PriorityBackground] != 0 {
		t.Fatalf("queued = %v, want both requests in the interactive band", snap.queued)
	}
	// While queued the report route answers as before (302, Queued).
	if code, status := reportStatus(t, ts.URL, sr.ID); code != http.StatusFound || status != string(StatusQueued) {
		t.Fatalf("queued report: %d %q", code, status)
	}
	hold.Release()
	if code, body := pollReport(t, ts.URL, sr.ID); code != http.StatusOK {
		t.Fatalf("old-style report: %d %s", code, body)
	}
}

// blockingStub is a trivy stub whose image scans run until releaseFile
// exists, so a test can hold scans in their slots.
func blockingStub(t *testing.T, releaseFile string) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
while [ ! -e '`+releaseFile+`' ]; do sleep 0.02; done
echo '{"Results":[]}'
`)
}

// TestHandlerSchedulesByRegistryHost checks the handler wiring: with a
// limits file capping a.example at 1 and 4 global slots, two scans for
// a.example and one for b.example run as two (a's second waits on a's cap
// while b runs), so the scheduler must see the request's registry host as
// the client.
func TestHandlerSchedulesByRegistryHost(t *testing.T) {
	dir := t.TempDir()
	limits := dir + "/limits.yaml"
	if err := os.WriteFile(limits, []byte("a.example:8080: {max_concurrent: 1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release := dir + "/release"
	cfg := LoadConfig()
	cfg.TrivyPath = blockingStub(t, release)
	cfg.CacheDir = t.TempDir()
	cfg.ScannerVersion = "0.71.2"
	cfg.MaxConcurrentScans = 4
	cfg.ClientLimitsFile = limits
	srv := NewServer(cfg)
	l, err := loadClientLimitsFile(limits)
	if err != nil {
		t.Fatal(err)
	}
	srv.sched.SetLimits(l)
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var ids []string
	for i, host := range []string{"http://a.example:8080", "http://a.example:8080", "http://b.example:8080"} {
		ids = append(ids, submitScan(t, ts.URL, ScanRequest{
			Registry: RegistryRef{URL: host},
			Artifact: ArtifactRef{Repository: "app", Tag: "v" + itoa(i)},
		}))
	}
	deadline := time.Now().Add(5 * time.Second)
	var snap schedSnapshot
	for time.Now().Before(deadline) {
		snap = srv.sched.Snapshot(true)
		if snap.running+snap.queued[PriorityInteractive] == 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if snap.running != 2 || snap.queued[PriorityInteractive] != 1 {
		t.Fatalf("running=%d queued=%d, want 2 running (one per host) and a's second scan queued on its cap", snap.running, snap.queued[PriorityInteractive])
	}
	byClient := map[string]clientSnapshot{}
	for _, c := range snap.clients {
		byClient[c.name] = c
	}
	if a, b := byClient["a.example:8080"], byClient["b.example:8080"]; a.running != 1 || a.queued[PriorityInteractive] != 1 || b.running != 1 {
		t.Fatalf("per-client state %+v", byClient)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if code, body := pollReport(t, ts.URL, id); code != http.StatusOK {
			t.Fatalf("scan %s: %d %s", id, code, body)
		}
	}
}

// TestFsHandlerSchedulesByClientHeader is the filesystem counterpart: the
// X-Scan-Client header names the client, so its cap applies to uploads.
func TestFsHandlerSchedulesByClientHeader(t *testing.T) {
	dir := t.TempDir()
	release := dir + "/release"
	cfg := LoadConfig()
	cfg.TrivyPath = blockingStub(t, release)
	cfg.CacheDir = t.TempDir()
	cfg.ScannerVersion = "0.71.2"
	cfg.MaxConcurrentScans = 4
	cfg.ClientLimitsFile = dir + "/limits.yaml"
	srv := NewServer(cfg)
	srv.sched.SetLimits(mustLimits(t, "a.example:8080: {max_concurrent: 1}\n"))
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	for _, client := range []string{"http://a.example:8080", "http://a.example:8080", "http://b.example:8080"} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/filesystem/scan", bytes.NewReader(tarOf(t, map[string]string{"a": "b"})))
		req.Header.Set(scanClientHeader, client)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("fs submit: %d", resp.StatusCode)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	var snap schedSnapshot
	for time.Now().Before(deadline) {
		if snap = srv.sched.Snapshot(false); snap.running+snap.queued[PriorityInteractive] == 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if snap.running != 2 || snap.queued[PriorityInteractive] != 1 {
		t.Fatalf("running=%d queued=%d, want 2 and 1", snap.running, snap.queued[PriorityInteractive])
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); srv.sched.Snapshot(false).running+srv.sched.Snapshot(false).queued[PriorityInteractive] != 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
}
