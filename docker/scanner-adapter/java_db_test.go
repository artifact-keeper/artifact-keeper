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

func javaDBStub(t *testing.T, countPath string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trivy")
	script := "#!/bin/sh\n" + stubVersion + `
case " $* " in
  *--download-java-db-only*)
    echo x >> "` + countPath + `"
    mkdir -p "$prev_cache/java-db"
    : > "$prev_cache/java-db/trivy-java.db"
    : > "$prev_cache/java-db/metadata.json"
    exit 0
    ;;
esac
echo '{"Results":[]}'
exit 0
`
	// capture --cache-dir value for the download case
	script = "#!/bin/sh\n" + stubVersion + `
prev=""; prev_cache=""
for a in "$@"; do [ "$prev" = "--cache-dir" ] && prev_cache="$a"; prev="$a"; done
case " $* " in
  *--download-java-db-only*)
    echo x >> "` + countPath + `"
    sleep 0.1
    mkdir -p "$prev_cache/java-db"
    printf db > "$prev_cache/java-db/trivy-java.db"
    printf '{}' > "$prev_cache/java-db/metadata.json"
    exit 0
    ;;
esac
echo '{"Results":[]}'
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnsureJavaDBSerializedAndSkipsUpdates(t *testing.T) {
	countPath := filepath.Join(t.TempDir(), "count")
	cfg := LoadConfig()
	cfg.TrivyPath = javaDBStub(t, countPath)
	cfg.CacheDir = t.TempDir()
	cfg.Offline = false
	s := NewScanner(cfg)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.EnsureJavaDB(ctx); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("EnsureJavaDB: %v", err)
		}
	}
	b, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatalf("count file: %v", err)
	}
	if got := strings.Count(string(b), "\n"); got != 1 {
		t.Errorf("download-java-db-only runs = %d, want 1", got)
	}
	if !s.javaDBReady.Load() {
		t.Error("javaDBReady not set after successful ensure")
	}
	joined := strings.Join(s.buildArgs("backend:8080/repo:tag", ""), " ")
	if !strings.Contains(joined, "--skip-java-db-update") {
		t.Errorf("args missing --skip-java-db-update after ensure: %s", joined)
	}
	if got := strings.Join(s.buildFsArgs("/work"), " "); !strings.Contains(got, "--skip-java-db-update") {
		t.Errorf("fs args missing --skip-java-db-update after ensure: %s", got)
	}
}

func TestEnsureJavaDBOfflineSkipsDownload(t *testing.T) {
	countPath := filepath.Join(t.TempDir(), "count")
	cfg := LoadConfig()
	cfg.TrivyPath = javaDBStub(t, countPath)
	cfg.CacheDir = t.TempDir()
	cfg.Offline = true
	s := NewScanner(cfg)
	if err := s.EnsureJavaDB(context.Background()); err != nil {
		t.Fatalf("EnsureJavaDB: %v", err)
	}
	if _, err := os.Stat(countPath); err == nil {
		t.Error("offline mode must not download the Java DB")
	}
	if s.javaDBReady.Load() {
		t.Error("offline mode must not mark Java DB ready")
	}
}
