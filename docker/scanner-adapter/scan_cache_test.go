package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lockingStub emulates trivy's on-disk analysis cache (#5657): a run without
// `--cache-backend memory` takes an exclusive lock in <cache-dir> for its whole
// duration, and a run that finds the lock taken fails with trivy's own error
// text instead of scanning. A memory-backend run takes no lock. When
// alwaysLocked is set the lock is permanently held, as by another process
// sharing the cache volume.
func lockingStub(t *testing.T, alwaysLocked bool) string {
	held := ""
	if alwaysLocked {
		held = `mkdir -p "$cache/fanal.lock"` + "\n"
	}
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
case " $* " in *" --cache-backend memory "*) sleep 1; echo '{"Results":[]}'; exit 0;; esac
prev=""; cache=""
for a in "$@"; do [ "$prev" = "--cache-dir" ] && cache="$a"; prev="$a"; done
`+held+`if ! mkdir "$cache/fanal.lock" 2>/dev/null; then
  echo "FATAL	Fatal error	run error: image scan error: scan error: unable to initialize a scan service: unable to initialize cache: unable to initialize fs cache: cache may be in use by another process: timeout" >&2
  exit 1
fi
sleep 1
echo '{"Results":[]}'
rmdir "$cache/fanal.lock"
`)
}

// TestConcurrentImageScansDoNotFailOnTheCacheLock is the #5657 regression:
// six image scans fired at once against one adapter must all succeed. Before
// the fix every scan used the on-disk cache, so all but the one holding its
// lock failed with "cache may be in use by another process".
func TestConcurrentImageScansDoNotFailOnTheCacheLock(t *testing.T) {
	ts := newTestServer(t, lockingStub(t, false))
	defer ts.Close()

	const scans = 6
	ids := make([]string, scans)
	for i := range ids {
		ids[i] = submitScan(t, ts.URL, ScanRequest{
			Registry: RegistryRef{URL: "http://backend:8080"},
			Artifact: ArtifactRef{Repository: "library/app", Tag: "v" + itoa(i)},
		})
	}
	// The adapter runs the six jobs concurrently; polling them in turn is
	// enough to see every outcome.
	for i, id := range ids {
		if code, body := pollReport(t, ts.URL, id); code != http.StatusOK {
			t.Errorf("scan %d: status %d, want 200: %s", i, code, body)
		}
	}
}

// TestImageScanFallsBackWhenAnotherProcessHoldsTheCache: the in-process lock
// cannot see a lock held outside the adapter (another replica on a shared
// cache volume); a scan that hits trivy's lock error reruns on the memory
// backend instead of failing.
func TestImageScanFallsBackWhenAnotherProcessHoldsTheCache(t *testing.T) {
	cfg := LoadConfig()
	cfg.TrivyPath = lockingStub(t, true)
	cfg.CacheDir = t.TempDir()
	cfg.TrivyServer = ""
	report, err := NewScanner(cfg).Scan(context.Background(), &ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: "library/app", Tag: "1"},
	})
	if err != nil {
		t.Fatalf("scan with a foreign cache lock must fall back, got: %v", err)
	}
	if report == nil {
		t.Fatal("nil report")
	}
}

func TestWithMemoryCacheKeepsTargetLast(t *testing.T) {
	got := strings.Join(withMemoryCache([]string{"image", "--quiet", "ref"}), " ")
	if got != "image --quiet --cache-backend memory ref" {
		t.Errorf("withMemoryCache = %q", got)
	}
	if len(withMemoryCache(nil)) != 0 {
		t.Error("empty args must stay empty")
	}
}

func TestTrivyCacheLocked(t *testing.T) {
	if !trivyCacheLocked("FATAL ... unable to initialize fs cache: Cache may be in use by another process: timeout") {
		t.Error("lock error not recognised")
	}
	if trivyCacheLocked("FATAL failed to pull image") {
		t.Error("unrelated failure recognised as the lock")
	}
}

// gatedStub blocks every scan until gate exists, appending a line to started
// as each one begins, so a test can count how many trivy runs are in flight.
func gatedStub(t *testing.T, gate, started string) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
echo x >> "`+started+`"
while [ ! -f "`+gate+`" ]; do sleep 0.05; done
echo '{"Results":[]}'
`)
}

func countLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\n")
}

// reportStatus fetches a report once and returns the HTTP status and the
// X-Scan-Status header.
func reportStatus(t *testing.T, base, id string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/scan/"+id+"/report", nil)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("get report: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get(scanStatusHeader)
}

// TestScansBeyondTheLimitAreQueuedNotFailed is the #5657 queueing half: with
// SCANNER_MAX_CONCURRENT_SCANS=2, a third scan does not start trivy, is
// reported Queued (302 + X-Scan-Status), and runs once a slot frees.
func TestScansBeyondTheLimitAreQueuedNotFailed(t *testing.T) {
	dir := t.TempDir()
	gate, started := filepath.Join(dir, "gate"), filepath.Join(dir, "started")
	ts := newTestServerWithConfig(t, gatedStub(t, gate, started), t.TempDir(), func(c *Config) {
		c.MaxConcurrentScans = 2
	})
	defer ts.Close()

	ids := make([]string, 3)
	for i := range ids {
		ids[i] = submitScan(t, ts.URL, ScanRequest{
			Registry: RegistryRef{URL: "http://backend:8080"},
			Artifact: ArtifactRef{Repository: "library/app", Tag: "q" + itoa(i)},
		})
	}

	// Wait until two scans run and the third reports Queued.
	queued := ""
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		states := map[string]int{}
		for _, id := range ids {
			code, state := reportStatus(t, ts.URL, id)
			if code != http.StatusFound {
				t.Fatalf("scan %s finished while the gate is closed: %d", id, code)
			}
			states[state]++
			if state == string(StatusQueued) {
				queued = id
			}
		}
		if states[string(StatusRunning)] == 2 && states[string(StatusQueued)] == 1 && countLines(started) == 2 {
			break
		}
		queued = ""
		time.Sleep(20 * time.Millisecond)
	}
	if queued == "" {
		t.Fatalf("want 2 Running + 1 Queued with 2 trivy runs, got %d trivy runs", countLines(started))
	}
	// Still exactly two trivy runs: the queued job has not started one.
	time.Sleep(200 * time.Millisecond)
	if n := countLines(started); n != 2 {
		t.Fatalf("trivy runs in flight = %d, want 2", n)
	}

	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if code, body := pollReport(t, ts.URL, id); code != http.StatusOK {
			t.Errorf("scan %s: status %d, want 200: %s", id, code, body)
		}
	}
	if n := countLines(started); n != 3 {
		t.Errorf("trivy runs = %d, want 3", n)
	}
}

// TestMaxConcurrentScansConfig: default 4, 0 is unbounded.
func TestMaxConcurrentScansConfig(t *testing.T) {
	t.Setenv("SCANNER_MAX_CONCURRENT_SCANS", "")
	if got := LoadConfig().MaxConcurrentScans; got != 4 {
		t.Errorf("default MaxConcurrentScans = %d, want 4", got)
	}
	t.Setenv("SCANNER_MAX_CONCURRENT_SCANS", "0")
	cfg := LoadConfig()
	if cfg.MaxConcurrentScans != 0 || NewServer(cfg).scanSlots != nil {
		t.Errorf("SCANNER_MAX_CONCURRENT_SCANS=0 must be unbounded")
	}
}
