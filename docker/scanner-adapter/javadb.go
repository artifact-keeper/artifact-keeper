package main

// The trivy Java DB (#5913).
//
// trivy needs a second database, the Java DB (mirror.gcr.io/aquasec/
// trivy-java-db:1, ~1 GiB compressed, ~1.5 GiB unpacked), to identify the
// JAR files it finds in an image. Left to itself, every trivy process that
// meets a JAR downloads it into <CacheDir>/java-db on demand, so two
// concurrent first JAR scans unpacked over each other and one failed
// ("chmod .../java-db/trivy-java.db: no such file or directory"), each
// staging its own ~1.9 GiB copy in TMPDIR on the way.
//
// The adapter therefore owns the download, and every scan runs with
// --skip-java-db-update:
//
//   - One download at a time. Callers in this process share one in-flight
//     download (single flight); adapter replicas sharing the cache volume
//     take an flock on <CacheDir>/java-db.lock, and the holder re-checks
//     whether another process already did the work.
//   - The download goes to a staging --cache-dir inside CacheDir and is
//     renamed into place, so <CacheDir>/java-db is never half-written.
//   - Connected installs fetch it in the background at startup; a scan never
//     waits for it unless the scan itself needs it.
//   - A scan that needs it and finds it missing fails with trivy's
//     "Unable to initialize the Java DB". The adapter then downloads it (or
//     joins the download in flight) and runs the scan once more. A scan
//     whose image has no JAR never opens the Java DB, so it succeeds whether
//     or not the Java DB could be fetched.
//   - When the download fails the adapter logs it, keeps scanning without the
//     Java DB, and does not try again for javaDBRetryBackoff: a JAR scan in
//     that window fails at once with the recorded reason instead of each one
//     reaching for an unreachable registry.
//   - Refresh follows the vulnerability DB: once metadata.json's NextUpdate
//     has passed (and the DB was not fetched within the last hour, trivy's own
//     rule), the next scan starts a background refresh, unless DB updates are
//     off (SCANNER_TRIVY_SKIP_DB_UPDATE), where neither DB is refreshed.
//   - SCANNER_OFFLINE never downloads. SCANNER_TRIVY_SKIP_DB_UPDATE alone does
//     not download at startup or refresh, but a JAR scan that finds no Java DB
//     still fetches it on demand, as trivy did before.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	javaDBDir         = "java-db"
	javaDBFile        = "trivy-java.db"
	javaDBLockFile    = "java-db.lock"
	javaDBStagingGlob = ".java-db-staging-"
	javaDBOldGlob     = ".java-db-old-"
	// javaDBDownloadTimeout bounds one download (all retries). It is
	// detached from the scan that started it, so a scan that gives up does
	// not abort a download other scans are waiting on.
	javaDBDownloadTimeout = 30 * time.Minute
	// javaDBRetryBackoff is how long after a failed download the adapter
	// reports that failure instead of trying again.
	javaDBRetryBackoff = 5 * time.Minute
	// javaDBRedownloadGuard: like trivy, never refresh a DB fetched within
	// the last hour, even if its NextUpdate has passed.
	javaDBRedownloadGuard = time.Hour
	// javaDBLockPoll is how often a waiter retries the cross-process lock.
	javaDBLockPoll = 500 * time.Millisecond
)

// javaDBInitMarker is in trivy's error when a scan that found a JAR could not
// open the Java DB, e.g. "post analysis error: Unable to initialize the Java
// DB: Java DB update failed: '--skip-java-db-update' cannot be specified on
// the first run" when it is missing.
const javaDBInitMarker = "unable to initialize the java db"

// trivyJavaDBMissing reports whether trivy stderr carries javaDBInitMarker.
func trivyJavaDBMissing(stderr string) bool {
	return strings.Contains(strings.ToLower(stderr), javaDBInitMarker)
}

// javaDBCall is one in-flight download that callers wait on.
type javaDBCall struct {
	done chan struct{}
	err  error
}

// javaDB serializes and records the adapter's Java DB downloads.
type javaDB struct {
	cfg *Config

	mu       sync.Mutex
	inflight *javaDBCall
	// lastErr/lastFailure record the most recent failed download; cleared by
	// a successful one.
	lastErr     error
	lastFailure time.Time
	// now is time.Now; tests replace it.
	now func() time.Time
}

func newJavaDB(cfg *Config) *javaDB { return &javaDB{cfg: cfg, now: time.Now} }

// javaDBMeta reads <cacheDir>/java-db/metadata.json. It returns nil when the
// Java DB is missing or incomplete (no metadata, or no non-empty DB file).
func javaDBMeta(cacheDir string) *VulnDBInfo {
	dir := filepath.Join(cacheDir, javaDBDir)
	info, err := os.Stat(filepath.Join(dir, javaDBFile))
	if err != nil || info.IsDir() || info.Size() == 0 {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, trivyMetaFile))
	if err != nil {
		return nil
	}
	meta, err := parseDBMetadata(raw)
	if err != nil {
		return nil
	}
	return meta
}

// javaDBStale reports whether a present Java DB is due for a refresh: its
// NextUpdate has passed and it was not downloaded within the last hour.
func javaDBStale(meta *VulnDBInfo, now time.Time) bool {
	if meta.NextUpdate != nil && now.Before(*meta.NextUpdate) {
		return false
	}
	if meta.DownloadedAt != nil && now.Before(meta.DownloadedAt.Add(javaDBRedownloadGuard)) {
		return false
	}
	return true
}

// autoUpdate reports whether the adapter fetches and refreshes the Java DB
// without being asked by a scan: DB updates on, not offline.
func (j *javaDB) autoUpdate() bool { return !j.cfg.Offline && !j.cfg.SkipDBUpdate }

// Startup fetches the Java DB in the background when it is missing or stale
// and DB updates are on. It never blocks readiness: a scan that does not need
// the Java DB should not wait ~1 GiB for it.
func (j *javaDB) Startup() {
	j.cleanLeftovers()
	if !j.autoUpdate() {
		if j.cfg.SkipDBUpdate && !j.cfg.Offline && javaDBMeta(j.cfg.CacheDir) == nil {
			log.Printf("SCANNER_TRIVY_SKIP_DB_UPDATE: the trivy Java DB is not in the cache and is not fetched at startup; the first scan of an image containing JAR files fetches it")
		}
		return
	}
	if meta := javaDBMeta(j.cfg.CacheDir); meta != nil && !javaDBStale(meta, j.now()) {
		log.Printf("trivy Java DB present (next update %s)", fmtTime(meta.NextUpdate))
		return
	}
	go func() { _ = j.ensure(context.Background(), true) }()
}

// MaybeRefresh starts a background refresh when the Java DB is present but
// stale and DB updates are on. Called before each scan; never blocks it. A
// missing Java DB is left to Startup and to the scan that needs it.
func (j *javaDB) MaybeRefresh() {
	if !j.autoUpdate() {
		return
	}
	meta := javaDBMeta(j.cfg.CacheDir)
	if meta == nil || !javaDBStale(meta, j.now()) {
		return
	}
	go func() { _ = j.ensure(context.Background(), true) }()
}

// EnsureForScan is called after a scan failed with javaDBInitMarker. It
// returns nil when the Java DB is (now) present and the scan should be run
// again, or the reason it is unavailable.
func (j *javaDB) EnsureForScan(ctx context.Context) error {
	if j.cfg.Offline {
		if javaDBMeta(j.cfg.CacheDir) != nil {
			return nil
		}
		return errors.New("SCANNER_OFFLINE is set and no trivy Java DB is in the cache; images containing JAR files cannot be scanned until one is placed in " + filepath.Join(j.cfg.CacheDir, javaDBDir))
	}
	return j.ensure(ctx, false)
}

// ensure makes sure a Java DB is present, downloading it when it is missing
// (or, with refresh, stale). Concurrent callers share one download. The
// download outlives ctx; ctx only bounds how long this caller waits.
func (j *javaDB) ensure(ctx context.Context, refresh bool) error {
	j.mu.Lock()
	call := j.inflight
	if call == nil {
		if meta := javaDBMeta(j.cfg.CacheDir); meta != nil && (!refresh || !javaDBStale(meta, j.now())) {
			j.mu.Unlock()
			return nil
		}
		if j.lastErr != nil && j.now().Before(j.lastFailure.Add(javaDBRetryBackoff)) {
			err := j.lastErr
			present := javaDBMeta(j.cfg.CacheDir) != nil
			j.mu.Unlock()
			if present {
				// A failed refresh leaves the old DB in place.
				return nil
			}
			return fmt.Errorf("trivy Java DB unavailable (last download failed %s ago; next attempt after %s): %w",
				j.now().Sub(j.lastFailure).Round(time.Second), javaDBRetryBackoff, err)
		}
		call = &javaDBCall{done: make(chan struct{})}
		j.inflight = call
		go j.run(call, refresh)
	}
	j.mu.Unlock()

	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return fmt.Errorf("waiting for the trivy Java DB download: %w", ctx.Err())
	}
}

// run performs one download for call and records its outcome.
func (j *javaDB) run(call *javaDBCall, refresh bool) {
	ctx, cancel := context.WithTimeout(context.Background(), javaDBDownloadTimeout)
	defer cancel()
	err := j.downloadLocked(ctx, refresh)

	j.mu.Lock()
	if err != nil {
		j.lastErr, j.lastFailure = err, j.now()
		if javaDBMeta(j.cfg.CacheDir) != nil {
			log.Printf("trivy Java DB refresh failed (keeping the current one; next attempt after %s): %v", javaDBRetryBackoff, err)
			err = nil
		} else {
			log.Printf("trivy Java DB download failed; scanning without it (images with no JAR files are unaffected; images containing JAR files fail until it is available; next attempt after %s): %v", javaDBRetryBackoff, err)
		}
	} else {
		j.lastErr, j.lastFailure = nil, time.Time{}
	}
	call.err = err
	j.inflight = nil
	j.mu.Unlock()
	close(call.done)
}

// downloadLocked takes the cross-process lock, re-checks the cache (another
// replica may have fetched the DB meanwhile), then downloads into a staging
// directory and swaps it into place.
func (j *javaDB) downloadLocked(ctx context.Context, refresh bool) error {
	cacheDir := j.cfg.CacheDir
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	unlock, err := lockFile(ctx, filepath.Join(cacheDir, javaDBLockFile), javaDBLockPoll)
	if err != nil {
		return fmt.Errorf("lock %s: %w", javaDBLockFile, err)
	}
	defer unlock()

	if meta := javaDBMeta(cacheDir); meta != nil && (!refresh || !javaDBStale(meta, j.now())) {
		return nil
	}
	// Holding the lock, any staging or old directory left behind is from a
	// download that died; nobody else is using it.
	cleanJavaDBLeftovers(cacheDir)

	staging, err := os.MkdirTemp(cacheDir, javaDBStagingGlob)
	if err != nil {
		return fmt.Errorf("create Java DB staging dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	log.Printf("downloading the trivy Java DB into %s", cacheDir)
	start := j.now()
	if err := retryDownload(ctx, j.cfg, "trivy Java DB", func(ctx context.Context) error {
		return downloadJavaDBOnce(ctx, j.cfg, staging)
	}); err != nil {
		return err
	}
	if javaDBMeta(staging) == nil {
		return fmt.Errorf("trivy --download-java-db-only left no complete Java DB in %s", filepath.Join(staging, javaDBDir))
	}
	if err := swapJavaDB(cacheDir, filepath.Join(staging, javaDBDir)); err != nil {
		return err
	}
	meta := javaDBMeta(cacheDir)
	log.Printf("trivy Java DB ready after %s (updated %s, next update %s)",
		j.now().Sub(start).Round(time.Second), fmtTime(meta.UpdatedAt), fmtTime(meta.NextUpdate))
	return nil
}

// downloadJavaDBArgs builds the `trivy image --download-java-db-only` argument
// list for a download into cacheDir. --java-db-repository is left to trivy's
// TRIVY_JAVA_DB_REPOSITORY, which the subprocess inherits.
func downloadJavaDBArgs(cacheDir string) []string {
	return []string{"image", "--download-java-db-only", "--cache-dir", cacheDir,
		"--no-progress", "--quiet", "--skip-version-check", "--disable-telemetry"}
}

// downloadJavaDBOnce runs a single `trivy --download-java-db-only`.
func downloadJavaDBOnce(ctx context.Context, cfg *Config, cacheDir string) error {
	cmd := exec.CommandContext(ctx, cfg.TrivyPath, downloadJavaDBArgs(cacheDir)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("trivy --download-java-db-only failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// swapJavaDB moves newDir to <cacheDir>/java-db, replacing any current one.
// Two renames: a trivy process that opens the Java DB between them finds it
// missing and fails with javaDBInitMarker, and the adapter's scan retry then
// finds the new one. A process that already has the old DB open keeps
// reading it until it closes the file.
func swapJavaDB(cacheDir, newDir string) error {
	cur := filepath.Join(cacheDir, javaDBDir)
	var old string
	if _, err := os.Lstat(cur); err == nil {
		d, err := os.MkdirTemp(cacheDir, javaDBOldGlob)
		if err != nil {
			return fmt.Errorf("create Java DB swap dir: %w", err)
		}
		old = filepath.Join(d, javaDBDir)
		if err := os.Rename(cur, old); err != nil {
			_ = os.RemoveAll(d)
			return fmt.Errorf("move the old Java DB aside: %w", err)
		}
		defer func() { _ = os.RemoveAll(d) }()
	}
	if err := os.Rename(newDir, cur); err != nil {
		if old != "" {
			_ = os.Rename(old, cur)
		}
		return fmt.Errorf("move the new Java DB into place: %w", err)
	}
	return nil
}

// cleanLeftovers removes what a download killed with the process left in
// CacheDir (up to ~1.5 GiB), if no other replica is downloading right now.
func (j *javaDB) cleanLeftovers() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := lockFile(ctx, filepath.Join(j.cfg.CacheDir, javaDBLockFile), 100*time.Millisecond)
	if err != nil {
		return
	}
	defer unlock()
	cleanJavaDBLeftovers(j.cfg.CacheDir)
}

// cleanJavaDBLeftovers removes staging and swap directories of a download
// that did not finish. Call it only while holding the Java DB lock.
func cleanJavaDBLeftovers(cacheDir string) {
	for _, g := range []string{javaDBStagingGlob, javaDBOldGlob} {
		matches, _ := filepath.Glob(filepath.Join(cacheDir, g+"*"))
		for _, m := range matches {
			_ = os.RemoveAll(m)
		}
	}
}
