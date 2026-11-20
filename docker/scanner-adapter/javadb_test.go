package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// javaDBStub emulates trivy's Java DB handling (#5913), verified against
// trivy 0.76.0:
//
//   - `image --download-java-db-only --cache-dir D` appends a line to
//     countFile and writes D/java-db/{trivy-java.db,metadata.json}, or, when
//     failFile exists, fails like an unreachable registry.
//   - A scan whose target contains "jar" needs the Java DB. With
//     --skip-java-db-update and no Java DB it fails with trivy's error. Without
//     the flag it downloads the DB in place, unserialized, the way concurrent
//     trivy processes raced before the fix.
//   - Any other target never touches the Java DB and reports a clean image.
func javaDBStub(t *testing.T, countFile, failFile string) string {
	t.Helper()
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
prev=""; cache=""; target=""
for a in "$@"; do [ "$prev" = "--cache-dir" ] && cache="$a"; prev="$a"; target="$a"; done
meta='{"Version":1,"NextUpdate":"2999-01-01T00:00:00Z","UpdatedAt":"2026-01-01T00:00:00Z","DownloadedAt":"2026-01-01T00:00:00Z"}'
case " $* " in
  *" --download-java-db-only "*)
    echo x >> '`+countFile+`'
    if [ -e '`+failFile+`' ]; then
      echo "FATAL failed to download artifact from mirror.gcr.io/aquasec/trivy-java-db:1: dial tcp: lookup mirror.gcr.io: no such host" >&2
      exit 1
    fi
    sleep 0.3
    mkdir -p "$cache/java-db"
    printf db > "$cache/java-db/trivy-java.db"
    printf '%s' "$meta" > "$cache/java-db/metadata.json"
    exit 0;;
esac
case "$target" in
  *jar*)
    case " $* " in
      *" --skip-java-db-update "*)
        if [ ! -s "$cache/java-db/metadata.json" ] || [ ! -s "$cache/java-db/trivy-java.db" ]; then
          echo "FATAL Fatal error run error: image scan error: scan error: scan failed: failed analysis: post analysis error: post analysis error: Unable to initialize the Java DB: Java DB update failed: '--skip-java-db-update' cannot be specified on the first run" >&2
          exit 1
        fi;;
      *)
        if [ ! -s "$cache/java-db/metadata.json" ]; then
          rm -rf "$cache/java-db"; mkdir -p "$cache/java-db"
          printf db > "$cache/java-db/trivy-java.db.part"; sleep 0.3
          if ! mv "$cache/java-db/trivy-java.db.part" "$cache/java-db/trivy-java.db" 2>/dev/null; then
            echo "FATAL post analysis error: Unable to initialize the Java DB: Java DB update failed: chmod $cache/java-db/trivy-java.db: no such file or directory" >&2
            exit 1
          fi
          printf '%s' "$meta" > "$cache/java-db/metadata.json"
        fi;;
    esac;;
esac
echo '{"Results":[]}'
`)
}

type javaDBFixture struct {
	cfg       *Config
	s         *Scanner
	countFile string
	failFile  string
}

func newJavaDBFixture(t *testing.T) *javaDBFixture {
	t.Helper()
	dir := t.TempDir()
	f := &javaDBFixture{countFile: filepath.Join(dir, "downloads"), failFile: filepath.Join(dir, "fail")}
	cfg := LoadConfig()
	cfg.TrivyPath = javaDBStub(t, f.countFile, f.failFile)
	cfg.CacheDir = t.TempDir()
	cfg.TrivyServer = ""
	cfg.Offline = false
	cfg.SkipDBUpdate = false
	cfg.DBUpdateRetries = 0
	f.cfg = cfg
	f.s = NewScanner(cfg)
	return f
}

func (f *javaDBFixture) downloads(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(f.countFile)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

func (f *javaDBFixture) scan(repo string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := f.s.Scan(ctx, &ScanRequest{
		Registry: RegistryRef{URL: "http://backend:8080"},
		Artifact: ArtifactRef{Repository: repo, Tag: "1"},
	})
	return err
}

func writeJavaDB(t *testing.T, cacheDir, meta string) {
	t.Helper()
	dir := filepath.Join(cacheDir, javaDBDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, javaDBFile), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, trivyMetaFile), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentFirstJarScansDownloadTheJavaDBOnce is the #5913 regression:
// eight scans of JAR-bearing images on an empty cache, all at once, all
// succeed, and the Java DB is downloaded exactly once. Before the fix each
// trivy process downloaded it into the same directory and most failed.
func TestConcurrentFirstJarScansDownloadTheJavaDBOnce(t *testing.T) {
	f := newJavaDBFixture(t)
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = f.scan("library/jar-app-" + itoa(i))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("scan %d: %v", i, err)
		}
	}
	if got := f.downloads(t); got != 1 {
		t.Errorf("Java DB downloads = %d, want 1", got)
	}
	if javaDBMeta(f.cfg.CacheDir) == nil {
		t.Error("Java DB not in place after the scans")
	}
	if left, _ := filepath.Glob(filepath.Join(f.cfg.CacheDir, ".java-db-*")); len(left) != 0 {
		t.Errorf("staging dirs left behind: %v", left)
	}
}

// TestJavaDBDownloadFailureOnlyFailsJarScans: with the Java DB unreachable
// (an air-gapped install with SCANNER_TRIVY_SKIP_DB_UPDATE but not
// SCANNER_OFFLINE, or a registry outage), an image with no JAR still scans;
// a JAR image fails with the recorded reason, and further JAR scans inside
// the backoff do not reach for the registry again.
func TestJavaDBDownloadFailureOnlyFailsJarScans(t *testing.T) {
	for _, skip := range []bool{false, true} {
		f := newJavaDBFixture(t)
		f.cfg.SkipDBUpdate = skip
		if err := os.WriteFile(f.failFile, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		f.s.javaDB.Startup()
		if err := f.scan("library/alpine"); err != nil {
			t.Errorf("skip=%v: non-JAR scan failed without a Java DB: %v", skip, err)
		}
		err := f.scan("library/jar-app")
		if err == nil || !strings.Contains(err.Error(), "JAR files") || !strings.Contains(err.Error(), "no such host") {
			t.Errorf("skip=%v: JAR scan error = %v, want the Java DB download failure", skip, err)
		}
		before := f.downloads(t)
		if err := f.scan("library/jar-app-2"); err == nil || !strings.Contains(err.Error(), "next attempt after") {
			t.Errorf("skip=%v: JAR scan inside the backoff: %v", skip, err)
		}
		if got := f.downloads(t); got != before {
			t.Errorf("skip=%v: download retried inside the backoff (%d -> %d)", skip, before, got)
		}
		if err := f.scan("library/alpine"); err != nil {
			t.Errorf("skip=%v: non-JAR scan after the failure: %v", skip, err)
		}

		// After the backoff, a JAR scan tries again and succeeds once the
		// registry is back.
		_ = os.Remove(f.failFile)
		f.s.javaDB.now = func() time.Time { return time.Now().Add(javaDBRetryBackoff + time.Second) }
		if err := f.scan("library/jar-app"); err != nil {
			t.Errorf("skip=%v: JAR scan after the backoff: %v", skip, err)
		}
	}
}

// TestJavaDBStartupHonoursSettings: a connected install fetches the Java DB
// at startup; SCANNER_TRIVY_SKIP_DB_UPDATE does not (the first JAR scan does,
// on demand); SCANNER_OFFLINE never does, and a JAR scan then fails closed.
func TestJavaDBStartupHonoursSettings(t *testing.T) {
	f := newJavaDBFixture(t)
	f.s.javaDB.Startup()
	if err := f.s.javaDB.ensure(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if f.downloads(t) != 1 {
		t.Errorf("connected startup downloads = %d, want 1", f.downloads(t))
	}

	f = newJavaDBFixture(t)
	f.cfg.SkipDBUpdate = true
	f.s.javaDB.Startup()
	time.Sleep(100 * time.Millisecond)
	if f.downloads(t) != 0 {
		t.Error("SCANNER_TRIVY_SKIP_DB_UPDATE startup downloaded the Java DB")
	}
	if err := f.scan("library/jar-app"); err != nil {
		t.Errorf("JAR scan with SKIP_DB_UPDATE and a reachable registry: %v", err)
	}
	if f.downloads(t) != 1 {
		t.Errorf("on-demand downloads = %d, want 1", f.downloads(t))
	}

	f = newJavaDBFixture(t)
	f.cfg.Offline = true
	f.cfg.SkipDBUpdate = true
	f.s.javaDB.Startup()
	if err := f.scan("library/alpine"); err != nil {
		t.Errorf("offline non-JAR scan: %v", err)
	}
	if err := f.scan("library/jar-app"); err == nil || !strings.Contains(err.Error(), "SCANNER_OFFLINE") {
		t.Errorf("offline JAR scan without a Java DB: %v", err)
	}
	if f.downloads(t) != 0 {
		t.Error("offline mode downloaded the Java DB")
	}
	writeJavaDB(t, f.cfg.CacheDir, `{"Version":1,"NextUpdate":"2000-01-01T00:00:00Z"}`)
	if err := f.scan("library/jar-app"); err != nil {
		t.Errorf("offline JAR scan with a pre-seeded Java DB: %v", err)
	}
	if f.downloads(t) != 0 {
		t.Error("offline mode refreshed a stale Java DB")
	}
}

// TestJavaDBRefreshFollowsNextUpdate: a stale Java DB is refreshed in the
// background on the next scan (as trivy refreshes the vulnerability DB once
// its NextUpdate passes), a fresh one is not, and SKIP_DB_UPDATE refreshes
// neither DB.
func TestJavaDBRefreshFollowsNextUpdate(t *testing.T) {
	const stale = `{"Version":1,"NextUpdate":"2000-01-01T00:00:00Z","DownloadedAt":"2000-01-01T00:00:00Z"}`
	const fresh = `{"Version":1,"NextUpdate":"2999-01-01T00:00:00Z","DownloadedAt":"2000-01-01T00:00:00Z"}`

	f := newJavaDBFixture(t)
	writeJavaDB(t, f.cfg.CacheDir, fresh)
	if err := f.scan("library/jar-app"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if f.downloads(t) != 0 {
		t.Error("a fresh Java DB was refreshed")
	}

	f = newJavaDBFixture(t)
	writeJavaDB(t, f.cfg.CacheDir, stale)
	if err := f.scan("library/jar-app"); err != nil {
		t.Fatalf("scan with a stale Java DB: %v", err)
	}
	// The scan does not wait for the refresh; wait for it here.
	if err := f.s.javaDB.ensure(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if f.downloads(t) != 1 {
		t.Errorf("stale Java DB refreshes = %d, want 1", f.downloads(t))
	}
	if m := javaDBMeta(f.cfg.CacheDir); m == nil || m.NextUpdate == nil || m.NextUpdate.Year() != 2999 {
		t.Errorf("Java DB not replaced: %+v", m)
	}

	// Fetched within the last hour: not refreshed even past NextUpdate.
	f = newJavaDBFixture(t)
	writeJavaDB(t, f.cfg.CacheDir, `{"Version":1,"NextUpdate":"2000-01-01T00:00:00Z","DownloadedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"}`)
	if err := f.s.javaDB.ensure(context.Background(), true); err != nil || f.downloads(t) != 0 {
		t.Errorf("refreshed a Java DB downloaded minutes ago: err=%v downloads=%d", err, f.downloads(t))
	}

	f = newJavaDBFixture(t)
	f.cfg.SkipDBUpdate = true
	writeJavaDB(t, f.cfg.CacheDir, stale)
	if err := f.scan("library/jar-app"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if f.downloads(t) != 0 {
		t.Error("SCANNER_TRIVY_SKIP_DB_UPDATE refreshed the Java DB")
	}

	// A failed refresh keeps the old DB and the scans that use it.
	f = newJavaDBFixture(t)
	writeJavaDB(t, f.cfg.CacheDir, stale)
	if err := os.WriteFile(f.failFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.s.javaDB.ensure(context.Background(), true); err != nil {
		t.Errorf("failed refresh with an old DB in place: %v", err)
	}
	if err := f.scan("library/jar-app"); err != nil {
		t.Errorf("JAR scan after a failed refresh: %v", err)
	}
}

// TestJavaDBDownloadWaitsForAnotherProcess: a replica sharing the cache
// volume holds the lock and installs the Java DB; this adapter waits for the
// lock, finds the DB, and does not download it again.
func TestJavaDBDownloadWaitsForAnotherProcess(t *testing.T) {
	f := newJavaDBFixture(t)
	unlock, err := lockFile(context.Background(), filepath.Join(f.cfg.CacheDir, javaDBLockFile), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.s.javaDB.ensure(context.Background(), false) }()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("ensure returned while another process held the lock: %v", err)
	default:
	}
	writeJavaDB(t, f.cfg.CacheDir, `{"Version":1,"NextUpdate":"2999-01-01T00:00:00Z"}`)
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.downloads(t) != 0 {
		t.Errorf("downloaded although another process installed the Java DB")
	}
}

func TestJavaDBStartupCleansLeftovers(t *testing.T) {
	f := newJavaDBFixture(t)
	f.cfg.Offline = true
	for _, d := range []string{".java-db-staging-1/java-db", ".java-db-old-2/java-db", ".vulndb-keep"} {
		if err := os.MkdirAll(filepath.Join(f.cfg.CacheDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.s.javaDB.Startup()
	left, _ := filepath.Glob(filepath.Join(f.cfg.CacheDir, ".*"))
	if len(left) != 1 || filepath.Base(left[0]) != ".vulndb-keep" {
		t.Errorf("after startup: %v", left)
	}
}

func TestEveryScanSkipsTheJavaDBUpdate(t *testing.T) {
	for _, cfg := range []*Config{
		{CacheDir: "/c"},
		{CacheDir: "/c", SkipDBUpdate: true},
		{CacheDir: "/c", Offline: true, SkipDBUpdate: true},
		{CacheDir: "/c", TrivyServer: "http://trivy:4954"},
	} {
		s := NewScanner(cfg)
		for name, args := range map[string][]string{"image": s.buildArgs("r/x:1", ""), "fs": s.buildFsArgs("/w")} {
			if !strings.Contains(strings.Join(args, " "), "--skip-java-db-update") {
				t.Errorf("%s args without --skip-java-db-update (%+v): %v", name, cfg, args)
			}
		}
	}
}
