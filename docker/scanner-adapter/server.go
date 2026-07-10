package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync/atomic"
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
}

// NewServer constructs a Server. It is NOT ready until MarkReady is called.
func NewServer(cfg *Config) *Server {
	return &Server{
		cfg:     cfg,
		jobs:    NewJobStore(cfg.JobTTL),
		scanner: NewScanner(cfg),
	}
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
	mux.HandleFunc("POST /api/v1/scan", s.handleScan)
	mux.HandleFunc("GET /api/v1/scan/{id}/report", s.handleReport)
	// Filesystem scans (#2363): the backend uploads a tarred, pre-hardened
	// workspace; the adapter untars it and runs `trivy filesystem` over it.
	mux.HandleFunc("POST /api/v1/filesystem/scan", s.handleFsScan)
	mux.HandleFunc("GET /api/v1/filesystem/scan/{id}/report", s.handleFsReport)
	return mux
}

func (s *Server) debugf(format string, args ...any) {
	if s.cfg.LogLevel == "debug" {
		log.Printf(format, args...)
	}
}

// handleReady is the readiness probe called before every scan.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "scanner starting", http.StatusServiceUnavailable)
		return
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

// runJob executes the scan and records the outcome. Detached from the request
// context so a client disconnect does not cancel the scan.
func (s *Server) runJob(id string, req ScanRequest) {
	s.jobs.Running(id)
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
	if err := untarWorkspace(body, dir); err != nil {
		_ = os.RemoveAll(dir)
		// An over-cap body surfaces here as a read error from MaxBytesReader.
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
	s.jobs.Running(id)
	report, stderr, err := s.scanner.ScanFilesystem(context.Background(), dir)
	if err != nil {
		log.Printf("filesystem scan %s failed: %v", id, err)
		s.jobs.Fail(id, err.Error())
		return
	}
	s.debugf("filesystem scan %s succeeded (%d report bytes)", id, len(report))
	s.jobs.SucceedFs(id, &FsScanResult{
		Report:         report,
		Stderr:         stderr,
		ScannerVersion: s.cfg.ScannerVersion,
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
// Pending/Running, 404 for an unknown/expired id.
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
	default:
		w.Header().Set("Refresh-After", "5")
		w.WriteHeader(http.StatusFound)
	}
}

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
