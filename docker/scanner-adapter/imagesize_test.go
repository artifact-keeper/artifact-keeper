package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRegistry serves manifests by "<repository>/<reference>" and counts the
// requests. With token set, a request without "Bearer <token>" answers 401.
type fakeRegistry struct {
	manifests map[string]string // key -> body
	types     map[string]string // key -> Content-Type
	token     string
	hits      atomic.Int32
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	if f.token != "" && r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), ociIndexMimeType) {
		http.Error(w, "missing Accept", http.StatusBadRequest)
		return
	}
	key := strings.Replace(strings.TrimPrefix(r.URL.Path, "/v2/"), "/manifests/", "/", 1)
	body, ok := f.manifests[key]
	if !ok {
		http.Error(w, "manifest unknown", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", f.types[key])
	_, _ = w.Write([]byte(body))
}

func imageManifest(config int64, layers ...int64) string {
	ls := make([]string, len(layers))
	for i, n := range layers {
		ls[i] = fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l%d","size":%d}`, i, n)
	}
	return fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:c","size":%d},"layers":[%s]}`,
		ociManifestMimeType, config, strings.Join(ls, ","))
}

// newSizeTestServer builds an adapter with SCANNER_MAX_IMAGE_BYTES = limit
// and a fake registry. The trivy stub fails every scan, so a 500 report
// proves trivy ran and a 422 proves it did not.
func newSizeTestServer(t *testing.T, trivy string, limit int64, reg *fakeRegistry) (*httptest.Server, *httptest.Server) {
	t.Helper()
	registry := httptest.NewServer(reg)
	t.Cleanup(registry.Close)
	ts := newTestServerWithConfig(t, trivy, t.TempDir(), func(c *Config) { c.MaxImageBytes = limit })
	t.Cleanup(ts.Close)
	return ts, registry
}

func sizeReq(registryURL, tag string) ScanRequest {
	return ScanRequest{
		Registry: RegistryRef{URL: registryURL, Authorization: "Bearer tok"},
		Artifact: ArtifactRef{Repository: "repo/big", Tag: tag, MimeType: ociManifestMimeType},
	}
}

// pollReportFull is pollReport that also returns the response headers.
func pollReportFull(t *testing.T, base, id string) (int, http.Header, []byte) {
	t.Helper()
	client := noRedirectClient()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(base + "/api/v1/scan/" + id + "/report")
		if err != nil {
			t.Fatalf("get report: %v", err)
		}
		if resp.StatusCode == http.StatusFound {
			resp.Body.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return resp.StatusCode, resp.Header, readAll(t, resp)
	}
	t.Fatal("report never left pending state")
	return 0, nil, nil
}

// TestImageOverLimitIsRefusedWithoutRunningTrivy: an image whose layers add
// up to more than SCANNER_MAX_IMAGE_BYTES ends TooLarge (422 +
// X-Scan-Status: TooLarge), and trivy never runs (#5909).
func TestImageOverLimitIsRefusedWithoutRunningTrivy(t *testing.T) {
	reg := &fakeRegistry{
		token:     "tok",
		manifests: map[string]string{"repo/big/v1": imageManifest(100, 600, 500)},
		types:     map[string]string{"repo/big/v1": ociManifestMimeType},
	}
	ts, registry := newSizeTestServer(t, failStub(t), 1000, reg)

	id := submitScan(t, ts.URL, sizeReq(registry.URL, "v1"))
	status, header, body := pollReportFull(t, ts.URL, id)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", status, body)
	}
	if got := header.Get(scanStatusHeader); got != "TooLarge" {
		t.Errorf("%s = %q, want TooLarge", scanStatusHeader, got)
	}
	for _, want := range []string{"not scanned: image too large", "1200 bytes", "SCANNER_MAX_IMAGE_BYTES=1000", "repo/big:v1"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("body %q lacks %q", body, want)
		}
	}
	if bytes.Contains(body, []byte("tok")) {
		t.Errorf("body leaks the registry token: %q", body)
	}
	// The image is named by host, not by the registry URL with its scheme
	// (buildRef takes an already-trimmed host since #5943).
	if want := strings.TrimPrefix(registry.URL, "http://") + "/repo/big:v1"; !bytes.Contains(body, []byte(want)) || bytes.Contains(body, []byte("http://")) {
		t.Errorf("body %q should name the image as %q", body, want)
	}
}

// TestImageUnderLimitIsScanned: at or under the limit the scan runs as before.
func TestImageUnderLimitIsScanned(t *testing.T) {
	reg := &fakeRegistry{
		token:     "tok",
		manifests: map[string]string{"repo/big/v1": imageManifest(100, 900)},
		types:     map[string]string{"repo/big/v1": ociManifestMimeType},
	}
	ts, registry := newSizeTestServer(t, succeedStub(t), 1000, reg)

	id := submitScan(t, ts.URL, sizeReq(registry.URL, "v1"))
	if status, body := pollReport(t, ts.URL, id); status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	if reg.hits.Load() == 0 {
		t.Error("the size check never read the manifest")
	}
}

// TestImageIndexIsMeasuredOnThePlatformManifest: for an index the check
// measures the image trivy scans, linux/amd64 (trivy gets no --platform),
// whatever the adapter's own architecture, not the index or another entry.
func TestImageIndexIsMeasuredOnThePlatformManifest(t *testing.T) {
	index := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[
	  {"mediaType":%q,"digest":"sha256:small","size":10,"platform":{"os":"linux","architecture":"arm64"}},
	  {"mediaType":%q,"digest":"sha256:large","size":10,"platform":{"os":"linux","architecture":"amd64"}}]}`,
		ociIndexMimeType, ociManifestMimeType, ociManifestMimeType)
	reg := &fakeRegistry{
		token: "tok",
		manifests: map[string]string{
			"repo/big/multi":        index,
			"repo/big/sha256:small": imageManifest(1, 1),
			"repo/big/sha256:large": imageManifest(1, 5000),
		},
		types: map[string]string{
			"repo/big/multi":        ociIndexMimeType,
			"repo/big/sha256:small": ociManifestMimeType,
			"repo/big/sha256:large": ociManifestMimeType,
		},
	}
	ts, registry := newSizeTestServer(t, failStub(t), 1000, reg)

	id := submitScan(t, ts.URL, sizeReq(registry.URL, "multi"))
	status, _, body := pollReportFull(t, ts.URL, id)
	if status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("5001 bytes")) {
		t.Fatalf("status = %d body=%s, want 422 measuring the linux/amd64 image (5001 bytes)", status, body)
	}
}

// TestImageSizeHungOrClosedRegistryFailsOpen: a registry that never answers,
// or a closed port, makes the check give up within its timeout and the scan
// proceeds (trivy runs and the report is 200).
func TestImageSizeHungOrClosedRegistryFailsOpen(t *testing.T) {
	old := imageSizeCheckTimeout
	imageSizeCheckTimeout = 300 * time.Millisecond
	defer func() { imageSizeCheckTimeout = old }()

	unblock := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-unblock:
		}
	}))
	defer hung.Close()
	defer close(unblock)

	closedLn := httptest.NewServer(http.NotFoundHandler())
	closedURL := closedLn.URL
	closedLn.Close() // nothing listens on this port any more

	for name, url := range map[string]string{"hung": hung.URL, "closed port": closedURL} {
		ts := newTestServerWithConfig(t, succeedStub(t), t.TempDir(), func(c *Config) { c.MaxImageBytes = 1000 })
		start := time.Now()
		id := submitScan(t, ts.URL, sizeReq(url, "v1"))
		status, body := pollReport(t, ts.URL, id)
		ts.Close()
		if status != http.StatusOK {
			t.Fatalf("%s registry: status %d, want 200 (the check must fail open); body=%s", name, status, body)
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Errorf("%s registry: scan took %s, the size check must give up at its timeout", name, el)
		}
	}
}

func TestImageSizeCheckTimeoutIsShort(t *testing.T) {
	if imageSizeCheckTimeout > 10*time.Second {
		t.Fatalf("size check timeout %s, want at most 10s so it does not eat the backend's poll budget", imageSizeCheckTimeout)
	}
}

// TestImageSizeUnreadableDoesNotBlockTheScan: a manifest the check cannot
// read (here: rejected credential) never fails the scan; trivy runs.
func TestImageSizeUnreadableDoesNotBlockTheScan(t *testing.T) {
	reg := &fakeRegistry{token: "other", manifests: map[string]string{}}
	ts, registry := newSizeTestServer(t, succeedStub(t), 1000, reg)

	id := submitScan(t, ts.URL, sizeReq(registry.URL, "v1"))
	if status, body := pollReport(t, ts.URL, id); status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (check must fail open); body=%s", status, body)
	}
}

// TestImageSizeCheckOffByDefault: with the default (0) no manifest is read.
func TestImageSizeCheckOffByDefault(t *testing.T) {
	reg := &fakeRegistry{manifests: map[string]string{"repo/big/v1": imageManifest(1, 1<<40)}}
	ts, registry := newSizeTestServer(t, succeedStub(t), 0, reg)

	id := submitScan(t, ts.URL, sizeReq(registry.URL, "v1"))
	if status, body := pollReport(t, ts.URL, id); status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	if n := reg.hits.Load(); n != 0 {
		t.Errorf("registry hit %d times with the check disabled", n)
	}
}

func TestPickPlatform(t *testing.T) {
	d := func(digest, os, arch string) registryDescriptor {
		return registryDescriptor{Digest: digest, Platform: &registryPlatform{OS: os, Architecture: arch}}
	}
	ms := []registryDescriptor{
		d("sha256:att", "unknown", "unknown"), // buildx attestation
		d("sha256:win", "windows", "amd64"),
		d("sha256:arm", "linux", "arm64"),
		d("sha256:amd", "linux", "amd64"),
	}
	// trivy (no --platform) scans linux/amd64, whatever the adapter's arch.
	if got := pickPlatform(ms); got != "sha256:amd" {
		t.Errorf("picked %q, want linux/amd64", got)
	}
	if got := pickPlatform(ms[:3]); got != "" {
		t.Errorf("no linux/amd64 entry should pick nothing, got %q", got)
	}
	// go-containerregistry treats an entry without a platform as linux/amd64
	// and takes the first match.
	noPlat := []registryDescriptor{{Digest: "sha256:bare"}, d("sha256:amd", "linux", "amd64")}
	if got := pickPlatform(noPlat); got != "sha256:bare" {
		t.Errorf("an entry without a platform counts as linux/amd64, got %q", got)
	}
}

func TestImageBytes(t *testing.T) {
	m := &registryManifest{Config: &registryDescriptor{Size: 5}, Layers: []registryDescriptor{{Size: 10}, {Size: 20}}}
	if n, err := m.imageBytes(); err != nil || n != 35 {
		t.Errorf("imageBytes = %d, %v; want 35", n, err)
	}
	if _, err := (&registryManifest{Layers: []registryDescriptor{{Size: -1}}}).imageBytes(); err == nil {
		t.Error("negative size must be an error")
	}
	if _, err := (&registryManifest{Layers: []registryDescriptor{{Size: 1 << 62}, {Size: 1 << 62}}}).imageBytes(); err == nil {
		t.Error("overflow must be an error")
	}
}

func TestManifestBaseURLs(t *testing.T) {
	cases := []struct {
		url      string
		insecure bool
		want     []string
	}{
		{"http://reg:8080/", true, []string{"http://reg:8080"}},
		{"https://reg", true, []string{"https://reg"}},
		{"reg:5000", true, []string{"https://reg:5000", "http://reg:5000"}},
		{"reg:5000", false, []string{"https://reg:5000"}},
		// The scheme is matched after trimming and ignoring case, so these
		// never fall through to https (#5909 review).
		{" http://reg:8080 ", true, []string{"http://reg:8080"}},
		{"HTTP://reg:8080/", false, []string{"http://reg:8080"}},
		{"HttpS://reg", true, []string{"https://reg"}},
	}
	for _, c := range cases {
		if got := manifestBaseURLs(c.url, c.insecure); !reflect.DeepEqual(got, c.want) {
			t.Errorf("manifestBaseURLs(%q, %v) = %v, want %v", c.url, c.insecure, got, c.want)
		}
	}
}

func TestLoadConfigMaxImageBytes(t *testing.T) {
	t.Setenv("SCANNER_MAX_IMAGE_BYTES", "")
	if got := LoadConfig().MaxImageBytes; got != 0 {
		t.Errorf("default = %d, want 0 (no bound)", got)
	}
	t.Setenv("SCANNER_MAX_IMAGE_BYTES", "4294967296")
	if got := LoadConfig().MaxImageBytes; got != 4<<30 {
		t.Errorf("override = %d, want 4 GiB", got)
	}
	t.Setenv("SCANNER_MAX_IMAGE_BYTES", "-5")
	if got := LoadConfig().MaxImageBytes; got != 0 {
		t.Errorf("negative = %d, want the default 0", got)
	}
	for v, want := range map[string]int64{"4Gi": 4 << 30, "512Mi": 512 << 20, "64Ki": 64 << 10, "2G": 2e9, "500M": 500e6, "8K": 8000, " 3 Gi ": 3 << 30, "0": 0} {
		t.Setenv("SCANNER_MAX_IMAGE_BYTES", v)
		if got := LoadConfig().MaxImageBytes; got != want {
			t.Errorf("%q = %d, want %d", v, got, want)
		}
	}
}

// TestBadMaxImageBytesIsLogged: a value that does not parse is ignored with a
// warning naming the variable, never silently.
func TestBadMaxImageBytesIsLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	for _, v := range []string{"4GB", "lots", "4.5Gi", "-1Gi", "9999999999Ti"} {
		buf.Reset()
		t.Setenv("SCANNER_MAX_IMAGE_BYTES", v)
		if got := LoadConfig().MaxImageBytes; got != 0 {
			t.Errorf("%q = %d, want the default 0", v, got)
		}
		if !strings.Contains(buf.String(), "SCANNER_MAX_IMAGE_BYTES") || !strings.Contains(buf.String(), "WARNING") {
			t.Errorf("%q: no warning logged: %q", v, buf.String())
		}
	}
}

func TestJobStoreSweepEvictsTooLarge(t *testing.T) {
	s := NewJobStore(time.Minute)
	job, _ := s.Create()
	s.TooLarge(job.ID, "not scanned: image too large")
	if got, _ := s.Get(job.ID); got.Status != StatusTooLarge || got.Err == "" {
		t.Fatalf("job = %+v, want TooLarge with a message", got)
	}
	if n := s.sweep(time.Now().Add(2 * time.Minute)); n != 1 {
		t.Errorf("sweep evicted %d, want the TooLarge job", n)
	}
}

// TestFsScanOverCapIs413: a workspace over SCANNER_FS_MAX_UPLOAD_BYTES is a
// 413 naming the bound, not a 400 "invalid workspace tar" (#5909).
func TestFsScanOverCapIs413(t *testing.T) {
	ts := newTestServerWithConfig(t, fsSucceedStub(t), t.TempDir(), func(c *Config) { c.FsMaxUploadBytes = 2048 })
	defer ts.Close()

	body := tarOf(t, map[string]string{"go.sum": strings.Repeat("x", 8192)})
	resp, err := http.Post(ts.URL+"/api/v1/filesystem/scan", "application/x-tar", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	got := readAll(t, resp)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", resp.StatusCode, got)
	}
	if !bytes.Contains(got, []byte("SCANNER_FS_MAX_UPLOAD_BYTES=2048")) {
		t.Errorf("body %q does not name the bound", got)
	}
}
