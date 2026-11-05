package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testToken = "s3cret-adapter-token"

// fakeBoltDB is a trivy.db stand-in: one page with the bbolt meta magic.
func fakeBoltDB(fill byte) []byte {
	b := bytes.Repeat([]byte{fill}, 4096)
	binary.LittleEndian.PutUint32(b[16:20], bboltMagic)
	return b
}

func metaJSON(version int, updated time.Time) []byte {
	return []byte(fmt.Sprintf(`{"Version":%d,"NextUpdate":%q,"UpdatedAt":%q,"DownloadedAt":"0001-01-01T00:00:00Z"}`,
		version, updated.Add(24*time.Hour).Format(time.RFC3339Nano), updated.Format(time.RFC3339Nano)))
}

type tarEntry struct {
	name     string
	typeflag byte
	body     []byte
	link     string
}

func gzTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: tf, Mode: 0o644, Linkname: e.link}
		if tf == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("tar body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// dbTarball is a well-formed db.tar.gz as `oras pull` produces it.
func dbTarball(t *testing.T, version int, updated time.Time, fill byte) []byte {
	return gzTar(t, []tarEntry{
		{name: trivyDBFile, body: fakeBoltDB(fill)},
		{name: trivyMetaFile, body: metaJSON(version, updated)},
	})
}

// installDB writes a DB straight into <cache>/db, as a trivy download would.
func installDB(t *testing.T, cache string, updated time.Time, fill byte) {
	t.Helper()
	dir := filepath.Join(cache, "db")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, trivyDBFile), fakeBoltDB(fill), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, trivyMetaFile), metaJSON(2, updated), 0o644); err != nil {
		t.Fatal(err)
	}
}

// snapshotDB returns the installed DB files' contents.
func snapshotDB(t *testing.T, cache string) string {
	t.Helper()
	var out strings.Builder
	for _, f := range []string{trivyDBFile, trivyMetaFile} {
		b, err := os.ReadFile(filepath.Join(cache, "db", f))
		if err != nil {
			t.Fatalf("read installed %s: %v", f, err)
		}
		sum := sha256.Sum256(b)
		out.WriteString(f + "=" + hex.EncodeToString(sum[:]) + ";")
	}
	return out.String()
}

func assertNoStaging(t *testing.T, cache string) {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(cache, importTempGlob+"*"))
	if len(m) != 0 {
		t.Errorf("staging dirs left behind: %v", m)
	}
}

// newImportServer builds a standalone Server whose version probe passed but
// which has no DB yet (so it is not ready), with the DB routes enabled.
func newImportServer(t *testing.T, cache string, tweak func(*Config)) (*Server, *httptest.Server) {
	t.Helper()
	cfg := LoadConfig()
	cfg.CacheDir = cache
	cfg.TrivyServer = ""
	cfg.AdapterToken = testToken
	cfg.ScannerVersion = "0.76.0"
	if tweak != nil {
		tweak(cfg)
	}
	srv := NewServer(cfg)
	srv.versionProbed.Store(true)
	srv.markReadyIfDBPresent(func() bool { return DBReady(cfg) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func putDB(t *testing.T, ts *httptest.Server, query string, body []byte, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/vulndb"+query, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func getDB(t *testing.T, ts *httptest.Server, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/vulndb", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func probeReady(t *testing.T, ts *httptest.Server) int {
	t.Helper()
	resp, err := http.Get(ts.URL + "/probe/ready")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestLoadConfigOffline(t *testing.T) {
	for _, k := range []string{"SCANNER_OFFLINE", "SCANNER_TRIVY_SKIP_DB_UPDATE", "SCANNER_TRIVY_DB_SCHEMA_VERSION",
		"SCANNER_ADAPTER_TOKEN", "SCANNER_VULNDB_MAX_UPLOAD_BYTES", "SCANNER_VULNDB_MAX_EXTRACTED_BYTES"} {
		t.Setenv(k, "")
	}
	cfg := LoadConfig()
	if cfg.Offline || cfg.SkipDBUpdate || cfg.AdapterToken != "" || cfg.DBSchemaVersion != 2 {
		t.Errorf("connected defaults changed: %+v", cfg)
	}
	if cfg.VulnDBMaxUploadBytes != 2<<30 || cfg.VulnDBMaxExtractedBytes != 8<<30 {
		t.Errorf("cap defaults: %d %d", cfg.VulnDBMaxUploadBytes, cfg.VulnDBMaxExtractedBytes)
	}
	if got := strings.Join(cfg.dbUpdateArgs(), " "); got != "" {
		t.Errorf("connected install got DB flags %q", got)
	}

	// Offline wins over an explicit SKIP_DB_UPDATE=false.
	t.Setenv("SCANNER_OFFLINE", "true")
	t.Setenv("SCANNER_TRIVY_SKIP_DB_UPDATE", "false")
	t.Setenv("SCANNER_TRIVY_DB_SCHEMA_VERSION", "3")
	t.Setenv("SCANNER_ADAPTER_TOKEN", "  tok  ")
	cfg = LoadConfig()
	if !cfg.Offline || !cfg.SkipDBUpdate || cfg.DBSchemaVersion != 3 || cfg.AdapterToken != "tok" {
		t.Errorf("offline config: %+v", cfg)
	}

	for _, bad := range []string{"0", "abc", "-1"} {
		t.Setenv("SCANNER_TRIVY_DB_SCHEMA_VERSION", bad)
		if v := LoadConfig().DBSchemaVersion; v != 2 {
			t.Errorf("schema %q -> %d, want default 2", bad, v)
		}
	}
}

func TestOfflineScanArgs(t *testing.T) {
	cfg := LoadConfig()
	cfg.Offline = true
	cfg.SkipDBUpdate = true
	cfg.TrivyServer = ""
	s := NewScanner(cfg)
	for name, args := range map[string][]string{
		"image":      s.buildArgs("backend:8080/repo:tag"),
		"filesystem": s.buildFsArgs("/work"),
	} {
		joined := strings.Join(args, " ")
		for _, want := range []string{"--skip-db-update", "--skip-java-db-update", "--offline-scan"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%s args missing %s: %s", name, want, joined)
			}
		}
	}
	// SkipDBUpdate alone now also reaches filesystem scans, without the
	// offline-only flags.
	cfg.Offline = false
	joined := strings.Join(s.buildFsArgs("/work"), " ")
	if !strings.Contains(joined, "--skip-db-update") || strings.Contains(joined, "--offline-scan") {
		t.Errorf("SkipDBUpdate fs args: %s", joined)
	}
}

func TestVulnDBImportHappyPathFlipsReadiness(t *testing.T) {
	cache := t.TempDir()
	_, ts := newImportServer(t, cache, nil)
	if code := probeReady(t, ts); code != http.StatusServiceUnavailable {
		t.Fatalf("ready before import = %d, want 503", code)
	}
	if code, _ := getDB(t, ts, testToken); code != http.StatusNotFound {
		t.Fatalf("GET with no DB = %d, want 404", code)
	}

	updated := time.Now().Add(-6 * time.Hour).UTC()
	body := dbTarball(t, 2, updated, 'a')
	code, resp := putDB(t, ts, "", body, testToken)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", code, resp)
	}
	var res ImportResult
	if err := json.Unmarshal([]byte(resp), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sum := sha256.Sum256(body)
	if res.SHA256 != hex.EncodeToString(sum[:]) || res.Previous != nil || res.Forced {
		t.Errorf("import result: %+v", res)
	}
	if res.Imported.Version != 2 || res.Imported.DownloadedAt == nil || res.Imported.AgeSeconds == nil {
		t.Errorf("imported status: %+v", res.Imported)
	}

	// Ready with no restart.
	if code := probeReady(t, ts); code != http.StatusOK {
		t.Fatalf("ready after import = %d, want 200", code)
	}
	got, _ := os.ReadFile(filepath.Join(cache, "db", trivyDBFile))
	if !bytes.Equal(got, fakeBoltDB('a')) {
		t.Error("installed trivy.db differs from the upload")
	}
	info, err := ReadVulnDBInfo(cache)
	if err != nil || info.DownloadedAt == nil || !info.UpdatedAt.Equal(updated) {
		t.Errorf("installed metadata: %+v %v", info, err)
	}
	assertNoStaging(t, cache)

	// GET reports it with its age.
	code, resp = getDB(t, ts, testToken)
	if code != http.StatusOK {
		t.Fatalf("GET = %d: %s", code, resp)
	}
	var st VulnDBStatus
	if err := json.Unmarshal([]byte(resp), &st); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if st.AgeSeconds == nil || *st.AgeSeconds < 6*3600-60 || *st.AgeSeconds > 6*3600+60 || st.Stale || st.Version != 2 {
		t.Errorf("GET status: %s", resp)
	}
}

func TestVulnDBGetReportsStale(t *testing.T) {
	cache := t.TempDir()
	installDB(t, cache, time.Now().Add(-72*time.Hour), 'a')
	_, ts := newImportServer(t, cache, func(c *Config) { c.Offline = true })
	code, resp := getDB(t, ts, testToken)
	if code != http.StatusOK || !strings.Contains(resp, `"stale":true`) || !strings.Contains(resp, `"offline":true`) {
		t.Errorf("GET = %d %s", code, resp)
	}
}

func TestVulnDBImportRejectsBadTarballsAndKeepsCurrentDB(t *testing.T) {
	updated := time.Now().Add(-time.Hour).UTC()
	good := dbTarball(t, 2, updated, 'n')
	meta := metaJSON(2, updated)
	bolt := fakeBoltDB('n')
	cases := map[string][]byte{
		"not gzip":       []byte("this is not a gzip stream at all"),
		"truncated gzip": good[:len(good)-10],
		"corrupt gzip":   append(append([]byte{}, good[:20]...), bytes.Repeat([]byte{0xff}, len(good)-20)...),
		"path traversal": gzTar(t, []tarEntry{{name: "../trivy.db", body: bolt}, {name: trivyMetaFile, body: meta}}),
		"nested path":    gzTar(t, []tarEntry{{name: "db/trivy.db", body: bolt}, {name: trivyMetaFile, body: meta}}),
		"absolute path":  gzTar(t, []tarEntry{{name: "/trivy.db", body: bolt}, {name: trivyMetaFile, body: meta}}),
		"symlink":        gzTar(t, []tarEntry{{name: trivyDBFile, typeflag: tar.TypeSymlink, link: "/etc/passwd"}, {name: trivyMetaFile, body: meta}}),
		"hardlink":       gzTar(t, []tarEntry{{name: trivyMetaFile, body: meta}, {name: trivyDBFile, typeflag: tar.TypeLink, link: trivyMetaFile}}),
		"directory":      gzTar(t, []tarEntry{{name: "./", typeflag: tar.TypeDir}, {name: trivyDBFile, body: bolt}, {name: trivyMetaFile, body: meta}}),
		"extra file":     gzTar(t, []tarEntry{{name: trivyDBFile, body: bolt}, {name: trivyMetaFile, body: meta}, {name: "evil.sh", body: []byte("x")}}),
		"duplicate":      gzTar(t, []tarEntry{{name: trivyDBFile, body: bolt}, {name: "./trivy.db", body: bolt}, {name: trivyMetaFile, body: meta}}),
		"missing meta":   gzTar(t, []tarEntry{{name: trivyDBFile, body: bolt}}),
		"missing db":     gzTar(t, []tarEntry{{name: trivyMetaFile, body: meta}}),
		"not bolt":       gzTar(t, []tarEntry{{name: trivyDBFile, body: []byte("SQLite format 3\x00 not bolt at all")}, {name: trivyMetaFile, body: meta}}),
		"bad metadata":   gzTar(t, []tarEntry{{name: trivyDBFile, body: bolt}, {name: trivyMetaFile, body: []byte("{nope")}}),
		"wrong schema":   dbTarball(t, 1, updated, 'n'),
		"no updated_at":  gzTar(t, []tarEntry{{name: trivyDBFile, body: bolt}, {name: trivyMetaFile, body: []byte(`{"Version":2}`)}}),
		"empty body":     {},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			cache := t.TempDir()
			installDB(t, cache, updated.Add(-24*time.Hour), 'o')
			before := snapshotDB(t, cache)
			_, ts := newImportServer(t, cache, nil)
			code, resp := putDB(t, ts, "", body, testToken)
			if code != http.StatusBadRequest {
				t.Errorf("PUT = %d, want 400: %s", code, resp)
			}
			if after := snapshotDB(t, cache); after != before {
				t.Error("current DB changed after a refused import")
			}
			assertNoStaging(t, cache)
		})
	}
}

func TestVulnDBImportWrongSchemaMessage(t *testing.T) {
	_, ts := newImportServer(t, t.TempDir(), nil)
	code, resp := putDB(t, ts, "", dbTarball(t, 3, time.Now(), 'a'), testToken)
	if code != http.StatusBadRequest || !strings.Contains(resp, "schema version 3") || !strings.Contains(resp, "trivy-db:2") {
		t.Errorf("PUT = %d %s", code, resp)
	}
}

func TestVulnDBImportOlderRefusedUnlessForced(t *testing.T) {
	cache := t.TempDir()
	current := time.Now().Add(-time.Hour).UTC()
	installDB(t, cache, current, 'o')
	before := snapshotDB(t, cache)
	_, ts := newImportServer(t, cache, nil)
	older := dbTarball(t, 2, current.Add(-48*time.Hour), 'n')

	code, resp := putDB(t, ts, "", older, testToken)
	if code != http.StatusConflict || !strings.Contains(resp, "force=true") {
		t.Fatalf("older PUT = %d, want 409: %s", code, resp)
	}
	if snapshotDB(t, cache) != before {
		t.Fatal("current DB changed after a 409")
	}
	assertNoStaging(t, cache)

	if code, _ := putDB(t, ts, "?force=maybe", older, testToken); code != http.StatusBadRequest {
		t.Errorf("force=maybe = %d, want 400", code)
	}
	code, resp = putDB(t, ts, "?force=true", older, testToken)
	if code != http.StatusOK || !strings.Contains(resp, `"forced":true`) || !strings.Contains(resp, `"previous"`) {
		t.Fatalf("forced PUT = %d: %s", code, resp)
	}
	got, _ := os.ReadFile(filepath.Join(cache, "db", trivyDBFile))
	if !bytes.Equal(got, fakeBoltDB('n')) {
		t.Error("forced import did not install the older DB")
	}
	assertNoStaging(t, cache)

	// A newer DB replaces without force.
	if code, resp := putDB(t, ts, "", dbTarball(t, 2, current.Add(time.Hour), 'z'), testToken); code != http.StatusOK {
		t.Errorf("newer PUT = %d: %s", code, resp)
	}
}

func TestVulnDBRoutesRequireToken(t *testing.T) {
	body := dbTarball(t, 2, time.Now(), 'a')

	// Routes off while no token is configured.
	_, off := newImportServer(t, t.TempDir(), func(c *Config) { c.AdapterToken = "" })
	if code, _ := putDB(t, off, "", body, testToken); code != http.StatusForbidden {
		t.Errorf("PUT with routes off = %d, want 403", code)
	}
	if code, _ := getDB(t, off, testToken); code != http.StatusForbidden {
		t.Errorf("GET with routes off = %d, want 403", code)
	}

	cache := t.TempDir()
	_, ts := newImportServer(t, cache, nil)
	for _, tok := range []string{"", "wrong", testToken + "x"} {
		if code, _ := putDB(t, ts, "", body, tok); code != http.StatusUnauthorized {
			t.Errorf("PUT with token %q = %d, want 401", tok, code)
		}
		if code, _ := getDB(t, ts, tok); code != http.StatusUnauthorized {
			t.Errorf("GET with token %q = %d, want 401", tok, code)
		}
	}
	if _, err := os.Stat(filepath.Join(cache, "db")); !os.IsNotExist(err) {
		t.Error("an unauthorized PUT installed a DB")
	}
	if code := probeReady(t, ts); code != http.StatusServiceUnavailable {
		t.Errorf("ready after unauthorized PUT = %d", code)
	}
}

func TestVulnDBImportNoReadyWithoutVersionProbe(t *testing.T) {
	srv, ts := newImportServer(t, t.TempDir(), nil)
	srv.versionProbed.Store(false)
	if code, resp := putDB(t, ts, "", dbTarball(t, 2, time.Now(), 'a'), testToken); code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", code, resp)
	}
	if code := probeReady(t, ts); code != http.StatusServiceUnavailable {
		t.Errorf("ready = %d, want 503 (trivy version probe never passed)", code)
	}
}

func TestVulnDBClientModeRefused(t *testing.T) {
	_, ts := newImportServer(t, t.TempDir(), func(c *Config) { c.TrivyServer = "http://trivy:4954" })
	if code, _ := putDB(t, ts, "", dbTarball(t, 2, time.Now(), 'a'), testToken); code != http.StatusConflict {
		t.Errorf("client-mode PUT = %d, want 409", code)
	}
	if code, _ := getDB(t, ts, testToken); code != http.StatusNotFound {
		t.Errorf("client-mode GET = %d, want 404", code)
	}
}

func TestVulnDBImportCaps(t *testing.T) {
	body := dbTarball(t, 2, time.Now(), 'a')

	cache := t.TempDir()
	_, ts := newImportServer(t, cache, func(c *Config) { c.VulnDBMaxUploadBytes = int64(len(body) / 2) })
	if code, resp := putDB(t, ts, "", body, testToken); code != http.StatusRequestEntityTooLarge {
		t.Errorf("over upload cap = %d, want 413: %s", code, resp)
	}
	assertNoStaging(t, cache)

	cache = t.TempDir()
	_, ts = newImportServer(t, cache, func(c *Config) { c.VulnDBMaxExtractedBytes = 1024 })
	if code, resp := putDB(t, ts, "", body, testToken); code != http.StatusBadRequest || !strings.Contains(resp, "MAX_EXTRACTED") {
		t.Errorf("over extracted cap = %d, want 400: %s", code, resp)
	}
	assertNoStaging(t, cache)
}

// The swap waits for an in-flight scan (which holds the DB read lock).
func TestVulnDBImportWaitsForInFlightScan(t *testing.T) {
	cache := t.TempDir()
	srv, ts := newImportServer(t, cache, nil)
	srv.scanner.dbMu.RLock()
	done := make(chan int, 1)
	body := dbTarball(t, 2, time.Now(), 'a')
	go func() {
		code, _ := putDB(t, ts, "", body, testToken)
		done <- code
	}()
	select {
	case code := <-done:
		srv.scanner.dbMu.RUnlock()
		t.Fatalf("import finished (%d) while a scan held the DB", code)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Join(cache, "db")); !os.IsNotExist(err) {
		t.Error("DB swapped in while a scan held the read lock")
	}
	srv.scanner.dbMu.RUnlock()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Errorf("import after scan = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("import never completed")
	}
}

func TestSwapDirRestoresOnFailure(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, "db")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The new dir does not exist, so installing it fails.
	if err := swapDir(dst, filepath.Join(root, "missing"), filepath.Join(root, "aside")); err == nil {
		t.Fatal("swapDir succeeded with no new dir")
	}
	if _, err := os.Stat(filepath.Join(dst, "keep")); err != nil {
		t.Errorf("previous DB not restored: %v", err)
	}
}

func TestCleanStaleImports(t *testing.T) {
	cache := t.TempDir()
	stale := filepath.Join(cache, importTempGlob+"123")
	if err := os.MkdirAll(filepath.Join(stale, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	installDB(t, cache, time.Now(), 'a')
	cleanStaleImports(cache)
	assertNoStaging(t, cache)
	if !dbPresent(cache) {
		t.Error("cleanStaleImports removed the installed DB")
	}
}
