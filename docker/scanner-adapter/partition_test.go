package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// skipDirsOf returns every --skip-dirs value in a trivy argument list.
func skipDirsOf(args []string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--skip-dirs" {
			out = append(out, args[i+1])
		}
	}
	return out
}

func registryModeConfig(prefix string) *Config {
	cfg := LoadConfig()
	cfg.CachePartitionMode = partitionModeRegistry
	cfg.CachePartition = prefix
	return cfg
}

func TestPartitionModeDefaultsToStaticAndValidates(t *testing.T) {
	t.Setenv("SCANNER_TRIVY_CACHE_PARTITION_MODE", "")
	cfg := LoadConfig()
	if cfg.CachePartitionMode != partitionModeStatic {
		t.Fatalf("default mode = %q, want static", cfg.CachePartitionMode)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}
	t.Setenv("SCANNER_TRIVY_CACHE_PARTITION_MODE", " Registry ")
	if cfg := LoadConfig(); cfg.CachePartitionMode != partitionModeRegistry || cfg.Validate() != nil {
		t.Fatalf("mode %q must parse as registry", cfg.CachePartitionMode)
	}
	// An unknown mode is refused, never read as static: static would put
	// every client's layer analysis into one partition.
	t.Setenv("SCANNER_TRIVY_CACHE_PARTITION_MODE", "per-host")
	if err := LoadConfig().Validate(); err == nil {
		t.Fatal("an unknown partition mode must fail validation")
	}
}

func TestStaticModeUsesOnePartitionForEveryRegistry(t *testing.T) {
	cfg := LoadConfig()
	cfg.CachePartitionMode = partitionModeStatic
	cfg.CachePartition = "fleet-1"
	for _, u := range []string{"http://a.example:8080", "https://b.example", ""} {
		if got := cfg.imagePartition(u); got != "fleet-1" {
			t.Errorf("static imagePartition(%q) = %q, want the configured value", u, got)
		}
	}
	cfg.CachePartition = ""
	if got := cfg.imagePartition("http://a.example"); got != "" {
		t.Errorf("static mode without a partition must add none, got %q", got)
	}
}

// TestRegistryModeTwoHostsNeverSharePartition: two requests with different
// registry.url values produce different --skip-dirs entries (#5943).
func TestRegistryModeTwoHostsNeverSharePartition(t *testing.T) {
	for _, prefix := range []string{"", "fleet-1"} {
		cfg := registryModeConfig(prefix)
		s := NewScanner(cfg)
		hosts := []string{
			"http://ak-one.example:8080",
			"http://ak-two.example:8080",
			"http://ak-one.example:8081", // same name, other port: other registry
			"http://ak-one.example",
			"http://10.0.0.5:8080",
			"http://10.0.0.6:8080",
		}
		seen := map[string]string{}
		for _, h := range hosts {
			dirs := skipDirsOf(s.buildArgs(h+"/repo:tag", cfg.imagePartition(h)))
			if len(dirs) != 1 {
				t.Fatalf("prefix %q, %s: want exactly one partition entry, got %v", prefix, h, dirs)
			}
			if other, dup := seen[dirs[0]]; dup {
				t.Errorf("prefix %q: %s and %s share partition %s", prefix, other, h, dirs[0])
			}
			seen[dirs[0]] = h
		}
	}
}

// TestRegistryModeSameHostSamePartition: the same host with and without a
// scheme or a trailing slash (or in other letter case) maps to one entry.
func TestRegistryModeSameHostSamePartition(t *testing.T) {
	cfg := registryModeConfig("fleet-1")
	want := cachePartitionDir(cfg.imagePartition("ak-one.example:8080"))
	for _, u := range []string{
		"ak-one.example:8080",
		"ak-one.example:8080/",
		"http://ak-one.example:8080",
		"https://ak-one.example:8080/",
		" http://AK-One.Example:8080 ",
	} {
		if got := cachePartitionDir(cfg.imagePartition(u)); got != want {
			t.Errorf("%q -> %s, want %s", u, got, want)
		}
	}
}

// TestRegistryModePrefixKeepsFleetsApart: the operator-set value stays a
// prefix, so two adapter fleets scanning the same registry host do not share.
func TestRegistryModePrefixKeepsFleetsApart(t *testing.T) {
	a := registryModeConfig("fleet-1").imagePartition("http://ak.example")
	b := registryModeConfig("fleet-2").imagePartition("http://ak.example")
	none := registryModeConfig("").imagePartition("http://ak.example")
	if a == b || a == none || b == none {
		t.Fatalf("prefixes must separate partitions: %q %q %q", a, b, none)
	}
	// Registry mode never collapses to the static partition of the same
	// prefix, so turning the mode on never reuses the old shared entries.
	if a == "fleet-1" {
		t.Fatal("registry partition must differ from the bare prefix")
	}
}

// TestFsScansKeepStaticPartition: a filesystem upload carries no registry,
// so its partition is the configured value in both modes.
func TestFsScansKeepStaticPartition(t *testing.T) {
	for _, mode := range []string{partitionModeStatic, partitionModeRegistry} {
		cfg := LoadConfig()
		cfg.CachePartitionMode = mode
		cfg.CachePartition = "fleet-1"
		dirs := skipDirsOf(NewScanner(cfg).buildFsArgs("/work"))
		if len(dirs) != 1 || dirs[0] != cachePartitionDir("fleet-1") {
			t.Errorf("%s mode fs partition entries = %v", mode, dirs)
		}
		cfg.CachePartition = ""
		if dirs := skipDirsOf(NewScanner(cfg).buildFsArgs("/work")); len(dirs) != 0 {
			t.Errorf("%s mode without a partition must add none to fs scans, got %v", mode, dirs)
		}
	}
}

// argsRecordingStub is a trivy stub that appends its arguments (one line per
// run) to argsFile and reports a clean image.
func argsRecordingStub(t *testing.T, argsFile string) string {
	return writeStub(t, "#!/bin/sh\n"+stubVersion+`
echo "$*" >> '`+argsFile+`'
echo '{"Results":[]}'
`)
}

// TestRegistryModePartitionReachesTrivyPerRequest drives two scan requests
// through the HTTP API and checks that each trivy run carried the partition
// of its own request's registry host.
func TestRegistryModePartitionReachesTrivyPerRequest(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	cfg := registryModeConfig("fleet-1")
	cfg.TrivyPath = argsRecordingStub(t, argsFile)
	cfg.CacheDir = t.TempDir()
	cfg.MaxConcurrentScans = 1
	srv := NewServer(cfg)
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	hosts := []string{"http://ak-one.example:8080", "http://ak-two.example:8080"}
	for _, h := range hosts {
		id := submitScan(t, ts.URL, ScanRequest{
			Registry: RegistryRef{URL: h},
			Artifact: ArtifactRef{Repository: "library/app", Tag: "1"},
		})
		if code, body := pollReport(t, ts.URL, id); code != http.StatusOK {
			t.Fatalf("scan via %s: status %d: %s", h, code, body)
		}
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	runs := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(runs) != len(hosts) {
		t.Fatalf("want %d trivy runs, got %d: %q", len(hosts), len(runs), raw)
	}
	for i, h := range hosts {
		want := "--skip-dirs " + cachePartitionDir(cfg.imagePartition(h)) + " "
		if !strings.Contains(runs[i], want) {
			t.Errorf("run %d (%s) lacks its partition %q: %s", i, h, want, runs[i])
		}
	}
	if skipDirsOf(strings.Fields(runs[0]))[0] == skipDirsOf(strings.Fields(runs[1]))[0] {
		t.Error("two registry hosts shared a partition")
	}
}

// TestMetadataReportsPartitionModeOnly: /api/v1/metadata names the mode and
// never a partition value or its hash.
func TestMetadataReportsPartitionModeOnly(t *testing.T) {
	cfg := registryModeConfig("secret-fleet-name")
	srv := NewServer(cfg)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata: %d", rec.Code)
	}
	var meta ScannerMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if got := meta.Properties[cachePartitionModeProperty]; got != partitionModeRegistry {
		t.Errorf("mode property = %q, want registry", got)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret-fleet-name") || strings.Contains(body, strings.TrimPrefix(cachePartitionDir("secret-fleet-name"), "/")) {
		t.Errorf("metadata leaks the partition: %s", body)
	}
	line := partitionModeLogLine(cfg)
	if !strings.Contains(line, "registry") || strings.Contains(line, "secret-fleet-name") || strings.Contains(line, "scanner-cache-partition-") {
		t.Errorf("startup line must name the mode only: %s", line)
	}
}

// TestUntarWorkspaceDropsRootGit: in registry mode a root .git is not
// materialized, so trivy
// cannot take the workspace for a clean git repository and reuse a cached
// analysis keyed by a claimed commit (#5943). Nested .git dirs, and names
// that merely start with .git, are kept.
func TestUntarWorkspaceDropsRootGit(t *testing.T) {
	dst := t.TempDir()
	data := tarOf(t, map[string]string{
		".git/HEAD":               "ref: refs/heads/main\n",
		".git/objects/ab/cdef":    "x",
		"package-lock.json":       "{}",
		"vendor/lib/.git/HEAD":    "ref: refs/heads/main\n",
		".github/workflows/a.yml": "on: push\n",
		".gitignore":              "node_modules\n",
	})
	if err := untarWorkspaceOpts(bytes.NewReader(data), dst, true); err != nil {
		t.Fatalf("untar: %v", err)
	}
	for _, gone := range []string{".git"} {
		if _, err := os.Stat(filepath.Join(dst, gone)); !os.IsNotExist(err) {
			t.Errorf("%s must not be extracted (err=%v)", gone, err)
		}
	}
	for _, kept := range []string{"package-lock.json", "vendor/lib/.git/HEAD", ".github/workflows/a.yml", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(dst, kept)); err != nil {
			t.Errorf("%s must be extracted: %v", kept, err)
		}
	}

	// A root .git given as a file (a gitdir pointer) is dropped too.
	dst2 := t.TempDir()
	if err := untarWorkspaceOpts(bytes.NewReader(tarOf(t, map[string]string{".git": "gitdir: /elsewhere\n", "a": "b"})), dst2, true); err != nil {
		t.Fatalf("untar: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst2, ".git")); !os.IsNotExist(err) {
		t.Errorf(".git file must not be extracted (err=%v)", err)
	}
}

// oldStyleScanBody is a POST /api/v1/scan body exactly as a 1.11.x backend
// (or any other Harbor-API client) sends it: no field this change added.
const oldStyleScanBody = `{"registry":{"url":"http://ak-backend:8080","authorization":"Bearer t0k"},"artifact":{"repository":"library/app","mime_type":"application/vnd.docker.distribution.manifest.v2+json","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}`

// TestCompatOldStyleRequestStaticModeUnchanged: with the mode unset (static),
// an old-style request runs trivy with exactly the arguments it got before
// this change: the SCANNER_TRIVY_CACHE_PARTITION entry when set, none
// otherwise, and nothing else added.
func TestCompatOldStyleRequestStaticModeUnchanged(t *testing.T) {
	for _, partition := range []string{"", "fleet-1"} {
		t.Setenv("SCANNER_TRIVY_CACHE_PARTITION_MODE", "")
		t.Setenv("SCANNER_TRIVY_CACHE_PARTITION", partition)
		argsFile := filepath.Join(t.TempDir(), "args")
		cfg := LoadConfig()
		cfg.TrivyPath = argsRecordingStub(t, argsFile)
		cfg.CacheDir = t.TempDir()
		cfg.ScannerVersion = "0.71.2"
		srv := NewServer(cfg)
		srv.MarkReady()
		ts := httptest.NewServer(srv.Handler())

		resp, err := http.Post(ts.URL+"/api/v1/scan", "application/json", strings.NewReader(oldStyleScanBody))
		if err != nil {
			t.Fatal(err)
		}
		var sr ScanResponse
		if resp.StatusCode != http.StatusAccepted || json.NewDecoder(resp.Body).Decode(&sr) != nil || sr.ID == "" {
			t.Fatalf("old-style request: status %d", resp.StatusCode)
		}
		resp.Body.Close()
		code, body := pollReport(t, ts.URL, sr.ID)
		ts.Close()
		if code != http.StatusOK {
			t.Fatalf("old-style report: %d %s", code, body)
		}
		// The report keeps the Harbor shape the backend deserializes.
		var report map[string]json.RawMessage
		if err := json.Unmarshal(body, &report); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"scanner", "vulnerabilities"} {
			if _, ok := report[k]; !ok {
				t.Errorf("report lacks %q: %s", k, body)
			}
		}

		raw, _ := os.ReadFile(argsFile)
		got := skipDirsOf(strings.Fields(strings.TrimSpace(string(raw))))
		var want []string
		if partition != "" {
			want = []string{cachePartitionDir(partition)} // the pre-change entry
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("partition %q: --skip-dirs %v, want %v (unchanged from before)", partition, got, want)
		}
		// buildArgs in static mode equals the pre-change argument list.
		before := NewScanner(cfg).buildArgs("ref", cfg.CachePartition)
		if after := NewScanner(cfg).buildArgs("ref", cfg.imagePartition("http://any.example")); strings.Join(before, " ") != strings.Join(after, " ") {
			t.Errorf("static mode must not depend on the registry: %v vs %v", before, after)
		}
	}
}

// TestCompatRegistryModeNoHostFallsBackToStaticPartition: a request without
// a registry host carries no per-request partition and gets the configured
// SCANNER_TRIVY_CACHE_PARTITION, as today.
func TestCompatRegistryModeNoHostFallsBackToStaticPartition(t *testing.T) {
	for _, u := range []string{"", "  ", "http://", "https:///"} {
		if got := registryModeConfig("fleet-1").imagePartition(u); got != "fleet-1" {
			t.Errorf("registry mode, url %q: partition %q, want the configured fleet-1", u, got)
		}
		if got := registryModeConfig("").imagePartition(u); got != "" {
			t.Errorf("registry mode, no prefix, url %q: partition %q, want none", u, got)
		}
	}
}

// TestCompatMetadataShapeUnchanged: /api/v1/metadata keeps its scanner and
// capabilities fields; properties is the spec's optional map.
func TestCompatMetadataShapeUnchanged(t *testing.T) {
	cfg := LoadConfig()
	cfg.ScannerVersion = "0.71.2"
	rec := httptest.NewRecorder()
	NewServer(cfg).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil))
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"scanner", "capabilities", "properties"} {
		if _, ok := meta[k]; !ok {
			t.Errorf("metadata lacks %q: %s", k, rec.Body.String())
		}
	}
	var props map[string]string
	_ = json.Unmarshal(meta["properties"], &props)
	if props[cachePartitionModeProperty] != partitionModeStatic {
		t.Errorf("default mode property = %q", props[cachePartitionModeProperty])
	}
}

// TestCompatStaticModeKeepsRootGit: in the default static mode the workspace
// is extracted exactly as before, root .git included.
func TestCompatStaticModeKeepsRootGit(t *testing.T) {
	dst := t.TempDir()
	if err := untarWorkspace(bytes.NewReader(tarOf(t, map[string]string{".git/HEAD": "ref: refs/heads/main\n"})), dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git", "HEAD")); err != nil {
		t.Fatalf("static mode must extract a root .git as before: %v", err)
	}
}
