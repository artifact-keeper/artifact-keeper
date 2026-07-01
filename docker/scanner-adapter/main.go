// Command scanner-adapter is an Artifact-Keeper-owned Harbor Pluggable Scanner
// API v1 adapter. It accepts scan requests from the AK backend, runs the trivy
// CLI against the requested image in the AK registry, and serves the resulting
// vulnerability report in the Harbor format the backend consumes.
//
// It is deliberately fail-closed: any trivy error surfaces as a 500 on the
// report endpoint so the backend marks the scan failed rather than silently
// completing with zero findings.
package main

import (
	"context"
	"log"
	"net/http"
	"time"
)

func main() {
	cfg := LoadConfig()
	srv := NewServer(cfg)

	// Probe the trivy version at startup (unless pinned via env). Readiness is
	// gated on a successful probe so the backend does not dispatch scans to an
	// adapter whose trivy binary is missing/broken.
	if cfg.ScannerVersion == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		version, err := ProbeVersion(ctx, cfg)
		cancel()
		if err != nil {
			log.Printf("trivy version probe failed (staying not-ready): %v", err)
		} else {
			cfg.ScannerVersion = version
			log.Printf("trivy version probed: %s", version)
			srv.MarkReady()
		}
	} else {
		log.Printf("trivy version pinned via env: %s", cfg.ScannerVersion)
		srv.MarkReady()
	}

	stop := make(chan struct{})
	defer close(stop)
	go srv.jobs.RunSweeper(stop)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("scanner-adapter listening on %s (trivy=%s)", cfg.Addr, cfg.TrivyPath)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
