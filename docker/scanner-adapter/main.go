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

	if cfg.TrivyServer != "" {
		// Client mode: the vulnerability DB and the matching live on the trivy
		// server, so no local DB is downloaded. startClientMode validates the
		// settings and probes the bundled CLI (always, even with a pinned
		// SCANNER_SCANNER_VERSION); readiness is then re-checked against the
		// server on /probe/ready (cached briefly; see remote.go).
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := srv.startClientMode(ctx)
		cancel()
		if err != nil {
			log.Printf("trivy client mode not started (staying not-ready): %v", err)
		} else {
			log.Printf("trivy client mode: server %s holds the vuln DB; readiness follows it (trivy=%s)", redactURL(cfg.TrivyServer), cfg.ClientVersion)
			if cfg.CachePartition != "" {
				log.Printf("trivy analysis cache partitioned (%s)", cachePartitionDir(cfg.CachePartition))
			}
		}
	} else {
		startStandalone(srv, cfg)
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

// startStandalone is the standalone-mode startup: probe the trivy version
// (unless pinned), download the vuln DB, and mark ready only once it is present.
func startStandalone(srv *Server, cfg *Config) {
	// Probe the trivy version at startup (unless pinned via env). A failed probe
	// leaves the adapter not-ready so the backend does not dispatch scans to an
	// adapter whose trivy binary is missing/broken.
	versionOK := true
	if cfg.ScannerVersion == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		version, err := ProbeVersion(ctx, cfg)
		cancel()
		if err != nil {
			log.Printf("trivy version probe failed (staying not-ready): %v", err)
			versionOK = false
		} else {
			cfg.ScannerVersion = version
			log.Printf("trivy version probed: %s", version)
		}
	} else {
		log.Printf("trivy version pinned via env: %s", cfg.ScannerVersion)
	}

	// DB-presence readiness gate (#2167): do NOT advertise ready until the trivy
	// vuln DB is actually loaded. Without a DB, trivy exits 0 with empty Results
	// (a FALSE CLEAN); staying not-ready makes the backend fail every scan closed
	// instead. When DB updates are enabled, download it now so it is present
	// before the readiness flag flips (rather than racing the first scan).
	if versionOK {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ScanTimeout)
		if !cfg.SkipDBUpdate {
			if err := DownloadDB(ctx, cfg); err != nil {
				log.Printf("trivy DB download failed (staying not-ready): %v", err)
			}
		}
		cancel()
		if srv.markReadyIfDBPresent(func() bool { return DBReady(cfg) }) {
			log.Printf("trivy vuln DB present; adapter ready (trivy=%s)", cfg.ScannerVersion)
		} else {
			log.Printf("trivy vuln DB not present in %s (staying not-ready)", cfg.CacheDir)
		}
	}
}
