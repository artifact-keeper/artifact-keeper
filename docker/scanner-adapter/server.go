package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// Server holds the adapter's HTTP state.
type Server struct {
	cfg     *Config
	jobs    *JobStore
	scanner *Scanner
	// ready is false until the startup trivy-version probe succeeds; /probe/ready
	// returns 503 until then so the backend fails scans closed rather than
	// dispatching to a half-initialized adapter.
	ready atomic.Bool
	// versionProbed is set once the startup trivy-version check passed. A DB
	// import (PUT /api/v1/vulndb) flips ready on only when it is set, so an
	// import never makes an adapter with a broken trivy binary ready.
	versionProbed atomic.Bool
	// remote is the trivy-server readiness gate in client mode
	// (cfg.TrivyServer set); nil in standalone mode.
	remote *remoteGate
	// scanSlots holds one token per running scan, image and filesystem alike
	// (#5657); nil when cfg.MaxConcurrentScans is 0 (unbounded).
	scanSlots chan struct{}
}

// NewServer constructs a Server. It is NOT ready until MarkReady is called.
func NewServer(cfg *Config) *Server {
	s := &Server{
		cfg:     cfg,
		jobs:    NewJobStore(cfg.JobTTL),
		scanner: NewScanner(cfg),
	}
	if cfg.MaxConcurrentScans > 0 {
		s.scanSlots = make(chan struct{}, cfg.MaxConcurrentScans)
	}
	if cfg.TrivyServer != "" {
		client := newServerHTTPClient(cfg)
		s.remote = newRemoteGate(10*time.Second, func(ctx context.Context) error {
			// ClientVersion (the probed binary), never the reported pin.
			return checkTrivyServer(ctx, client, cfg.TrivyServer, cfg.ClientVersion)
		})
	}
	return s
}

// MarkReady flips the readiness gate on (called after a successful version probe).
func (s *Server) MarkReady() { s.ready.Store(true) }

// markReadyIfDBPresent flips readiness on only when dbReady reports a loaded
// vuln DB, and reports whether it did. Extracted as a seam so the DB-presence
// readiness gate is unit-testable without a real trivy cache. A missing DB
// keeps the adapter not-ready so the backend fails every scan closed rather than
// dispatching to a scanner that would exit 0 with empty (false-clean) results.
func (s *Server) markReadyIfDBPresent(dbReady func() bool) bool {
	if dbReady() {
		s.MarkReady()
		return true
	}
	return false
}

// Handler returns the adapter's HTTP router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /probe/ready", s.handleReady)
	mux.HandleFunc("GET /probe/healthy", s.handleHealthy)
	mux.HandleFunc("GET /api/v1/metadata", s.handleMetadata)
	// Scan and report routes: bearer token when SCANNER_SCAN_TOKEN(S_FILE)
	// is set (#5948); the probes and metadata above stay open.
	auth := newScanAuth(s.cfg)
	mux.HandleFunc("POST /api/v1/scan", auth.wrap(s.handleScan))
	mux.HandleFunc("GET /api/v1/scan/{id}/report", auth.wrap(s.handleReport))
	// Filesystem scans (#2363): the backend uploads a tarred, pre-hardened
	// workspace; the adapter untars it and runs `trivy filesystem` over it.
	mux.HandleFunc("POST /api/v1/filesystem/scan", auth.wrap(s.handleFsScan))
	mux.HandleFunc("GET /api/v1/filesystem/scan/{id}/report", auth.wrap(s.handleFsReport))
	// Vulnerability-DB status and offline import (#5287); bearer-token only.
	mux.HandleFunc("GET /api/v1/vulndb", s.handleVulnDBGet)
	mux.HandleFunc("PUT /api/v1/vulndb", s.handleVulnDBPut)
	return mux
}

func (s *Server) debugf(format string, args ...any) {
	if s.cfg.LogLevel == "debug" {
		log.Printf(format, args...)
	}
}

// handleReady is the readiness probe called before every scan.
// In client mode it also requires the trivy server check to pass (cached for a
// few seconds), so a missing, DB-less or mismatched server fails scans closed.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "scanner starting", http.StatusServiceUnavailable)
		return
	}
	if s.remote != nil {
		if fresh, err := s.remote.Ready(); err != nil {
			if fresh { // once per check, not once per probe
				log.Printf("not ready: %v", err)
			}
			http.Error(w, "trivy server not ready", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// handleHealthy is the liveness probe (always OK once the process is serving).
func (s *Server) handleHealthy(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// handleMetadata serves the Harbor scanner metadata document.
func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	meta := ScannerMetadata{
		Scanner: HarborScannerInfo{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: s.cfg.ScannerVersion,
		},
		Capabilities: []ScannerCapability{{
			ConsumesMimeTypes: []string{ociManifestMimeType, dockerManifestMimeType},
			ProducesMimeTypes: []string{reportMimeType},
		}},
	}
	// Only registry mode adds the property, so with no new config the
	// document is exactly what it was.
	if s.cfg.CachePartitionMode == partitionModeRegistry {
		meta.Properties = map[string]string{cachePartitionModeProperty: s.cfg.CachePartitionMode}
	}
	writeJSON(w, http.StatusOK, meta)
}

// handleScan accepts a scan request, starts it asynchronously, and returns the
// job id.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Artifact.Repository == "" {
		http.Error(w, "artifact.repository is required", http.StatusBadRequest)
		return
	}
	// Registry partition mode derives the partition from the registry host,
	// so a request without one is refused rather than given the shared
	// prefix partition (#5943).
	if s.cfg.CachePartitionMode == partitionModeRegistry && trimRegistryHost(req.Registry.URL) == "" {
		http.Error(w, "registry.url with a host is required in registry partition mode", http.StatusBadRequest)
		return
	}
	hasTag := req.Artifact.Tag != ""
	hasDigest := req.Artifact.Digest != ""
	if hasTag == hasDigest {
		http.Error(w, "artifact must carry exactly one of tag or digest", http.StatusBadRequest)
		return
	}

	job, err := s.jobs.Create()
	if err != nil {
		http.Error(w, "failed to create scan job", http.StatusInternalServerError)
		return
	}

	go s.runJob(job.ID, req)

	writeJSON(w, http.StatusAccepted, ScanResponse{ID: job.ID})
}

// acquireScanSlot blocks until one of the MaxConcurrentScans slots is free,
// marking the job Queued while it waits, then marks it Running (#5657). The
// returned func frees the slot. The scan's own timeout starts after this, so
// time spent queued never eats into it.
func (s *Server) acquireScanSlot(id string) (release func()) {
	if s.scanSlots == nil {
		s.jobs.Running(id)
		return func() {}
	}
	select {
	case s.scanSlots <- struct{}{}:
	default:
		s.jobs.Queued(id)
		log.Printf("scan %s queued: %d scans already running (SCANNER_MAX_CONCURRENT_SCANS)", id, cap(s.scanSlots))
		s.scanSlots <- struct{}{}
	}
	s.jobs.Running(id)
	return func() { <-s.scanSlots }
}

// runJob executes the scan and records the outcome. Detached from the request
// context so a client disconnect does not cancel the scan.
//
// The image size check (#5909) runs first, outside the scan slots: it is two
// manifest GETs at most, and an image it refuses never waits for a slot.
func (s *Server) runJob(id string, req ScanRequest) {
	if tooLarge := s.scanner.checkImageSize(context.Background(), &req); tooLarge != nil {
		log.Printf("scan %s refused: %v", id, tooLarge)
		s.jobs.TooLarge(id, tooLarge.Error())
		return
	}
	defer s.acquireScanSlot(id)()
	report, err := s.scanner.Scan(context.Background(), &req)
	if err != nil {
		// Do not include the request authorization; Scan's error messages only
		// carry the image ref + trivy stderr.
		log.Printf("scan %s failed: %v", id, err)
		s.jobs.Fail(id, err.Error())
		return
	}
	s.debugf("scan %s succeeded: %d vulnerabilities", id, len(report.Vulnerabilities))
	s.jobs.Succeed(id, report)
}

// handleReport serves the image-scan report per the Harbor polling contract.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	s.serveJobReport(w, r.PathValue("id"), reportMimeType, func(job *Job) any { return job.Report })
}

// handleFsScan accepts a tarred scan workspace, untars it into a private temp
// dir, and starts the filesystem scan asynchronously (#2363). The body is
// capped at cfg.FsMaxUploadBytes; since the tar is uncompressed, the cap also
// bounds the extracted tree.
func (s *Server) handleFsScan(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, s.cfg.FsMaxUploadBytes)

	dir, err := os.MkdirTemp("", "fs-scan-")
	if err != nil {
		http.Error(w, "failed to create scan workspace", http.StatusInternalServerError)
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		http.Error(w, "failed to secure scan workspace", http.StatusInternalServerError)
		return
	}
	if err := untarWorkspaceOpts(body, dir, s.cfg.CachePartitionMode == partitionModeRegistry); err != nil {
		_ = os.RemoveAll(dir)
		// An over-cap body surfaces here as a read error from MaxBytesReader:
		// answer it as such (413), not as a malformed tar (#5909).
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, fmt.Sprintf("not scanned: workspace too large: over SCANNER_FS_MAX_UPLOAD_BYTES=%d", s.cfg.FsMaxUploadBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid workspace tar: "+err.Error(), http.StatusBadRequest)
		return
	}

	job, err := s.jobs.Create()
	if err != nil {
		_ = os.RemoveAll(dir)
		http.Error(w, "failed to create scan job", http.StatusInternalServerError)
		return
	}

	go s.runFsJob(job.ID, dir)

	writeJSON(w, http.StatusAccepted, ScanResponse{ID: job.ID})
}

// runFsJob executes the filesystem scan and records the outcome, then removes
// the untarred workspace. Detached from the request context so a client
// disconnect does not cancel the scan.
func (s *Server) runFsJob(id, dir string) {
	defer func() { _ = os.RemoveAll(dir) }()
	defer s.acquireScanSlot(id)()
	report, db, stderr, err := s.scanner.ScanFilesystem(context.Background(), dir)
	if err != nil {
		log.Printf("filesystem scan %s failed: %v", id, err)
		s.jobs.Fail(id, err.Error())
		return
	}
	s.debugf("filesystem scan %s succeeded (%d report bytes)", id, len(report))
	s.jobs.SucceedFs(id, &FsScanResult{
		Report:          report,
		Stderr:          stderr,
		ScannerVersion:  s.cfg.ScannerVersion,
		VulnerabilityDB: db,
	})
}

// handleFsReport serves the filesystem-scan result with the same polling
// contract as the image report (200 / 302+Refresh-After / 500).
func (s *Server) handleFsReport(w http.ResponseWriter, r *http.Request) {
	s.serveJobReport(w, r.PathValue("id"), "", func(job *Job) any { return job.Fs })
}

// serveJobReport implements the shared report-polling contract for both scan
// families: 200 + body when Succeeded, 500 when Failed (fail-closed — a trivy
// error is NEVER a 200 with empty findings), 302 + integer Refresh-After while
// Pending/Queued/Running (the state in X-Scan-Status, #5657), 422 with
// X-Scan-Status: TooLarge for an image refused by SCANNER_MAX_IMAGE_BYTES
// (#5909), 404 for an unknown/expired id.
func (s *Server) serveJobReport(w http.ResponseWriter, id, contentType string, body func(*Job) any) {
	job, ok := s.jobs.Get(id)
	if !ok {
		http.Error(w, "unknown scan id", http.StatusNotFound)
		return
	}

	switch job.Status {
	case StatusSucceeded:
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		writeJSON(w, http.StatusOK, body(job))
	case StatusFailed:
		http.Error(w, "scan failed: "+job.Err, http.StatusInternalServerError)
	case StatusTooLarge:
		// Not a scan failure: the image was refused before trivy ran
		// (#5909). Clients that do not know the header still read a
		// terminal non-2xx answer, i.e. no report.
		w.Header().Set(scanStatusHeader, string(job.Status))
		http.Error(w, job.Err, http.StatusUnprocessableEntity)
	default:
		w.Header().Set("Refresh-After", "5")
		w.Header().Set(scanStatusHeader, string(job.Status))
		w.WriteHeader(http.StatusFound)
	}
}

// scanStatusHeader carries a pending job's state (Pending, Queued or Running)
// on the 302 report response, so the backend can tell a scan waiting for a
// slot from one that is running (#5657), and the TooLarge state on the 422
// of an image refused by SCANNER_MAX_IMAGE_BYTES (#5909). Not part of the
// Harbor contract; clients that ignore it see the same 302 + Refresh-After
// as before, and a terminal non-2xx for TooLarge.
const scanStatusHeader = "X-Scan-Status"

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
