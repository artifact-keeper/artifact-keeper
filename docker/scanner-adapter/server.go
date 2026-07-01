package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
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

// Handler returns the adapter's HTTP router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /probe/ready", s.handleReady)
	mux.HandleFunc("GET /probe/healthy", s.handleHealthy)
	mux.HandleFunc("GET /api/v1/metadata", s.handleMetadata)
	mux.HandleFunc("POST /api/v1/scan", s.handleScan)
	mux.HandleFunc("GET /api/v1/scan/{id}/report", s.handleReport)
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

// handleReport serves the scan report per the Harbor polling contract.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.jobs.Get(id)
	if !ok {
		// Unknown id: treated as pending by the backend (times out -> fail
		// closed). Never 404 a known-failed job.
		http.Error(w, "unknown scan id", http.StatusNotFound)
		return
	}

	switch job.Status {
	case StatusSucceeded:
		w.Header().Set("Content-Type", reportMimeType)
		writeJSON(w, http.StatusOK, job.Report)
	case StatusFailed:
		// Fail-closed: a trivy error is a 500, NEVER a 200 with empty findings.
		http.Error(w, "scan failed: "+job.Err, http.StatusInternalServerError)
	default:
		// Pending / Running: signal "not ready" with an integer Refresh-After.
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
