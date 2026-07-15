package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the adapter's runtime configuration, populated from the
// environment. All values have sane defaults so the adapter runs with an empty
// environment (the container sets only what it needs to override).
type Config struct {
	// Addr is the listen address, e.g. ":8080" or ":8090".
	Addr string
	// TrivyPath is the trivy binary to exec (absolute path or $PATH name).
	TrivyPath string
	// CacheDir is trivy's --cache-dir (vuln DB + fanal cache).
	CacheDir string
	// Insecure passes --insecure to trivy so it pulls manifests/blobs from the
	// AK registry over plain HTTP on the rig/cluster network.
	Insecure bool
	// SkipDBUpdate passes --skip-db-update so an air-gapped / pre-seeded cache
	// is used verbatim instead of contacting the trivy DB registry.
	SkipDBUpdate bool
	// DBRepository overrides the OCI repository trivy pulls its vulnerability DB
	// from (--db-repository). Empty means trivy's built-in default
	// (mirror.gcr.io/aquasecurity/trivy-db), which is an anonymous, shared,
	// rate-limited endpoint that made the release-gate scanner-efficacy check
	// flaky (#2167). Point this at an AK-controlled mirror (e.g.
	// ghcr.io/artifact-keeper/trivy-db) to avoid the public mirror entirely.
	// trivy accepts a comma-separated fallback list.
	DBRepository string
	// DBUpdateRetries is how many EXTRA attempts DownloadDB makes after the first
	// on a transient failure (rate-limit / network blip), with exponential
	// backoff. 0 preserves the single-shot behaviour.
	DBUpdateRetries int
	// DBUpdateRetryDelay is the base backoff between DB-download attempts; the nth
	// retry waits DBUpdateRetryDelay * 2^(n-1), capped by the download context.
	DBUpdateRetryDelay time.Duration
	// Severity is the trivy --severity filter (comma-separated UPPERCASE).
	Severity string
	// ScanTimeout bounds a single trivy image invocation.
	ScanTimeout time.Duration
	// FsScanTimeout bounds a single trivy filesystem invocation (#2363). Kept
	// separate from ScanTimeout: an extracted incus rootfs is a much larger
	// walk than a registry image pull.
	FsScanTimeout time.Duration
	// FsMaxUploadBytes caps the tar workspace body accepted by
	// POST /api/v1/filesystem/scan. The body is an UNCOMPRESSED tar, so this
	// also bounds the extracted tree (no decompression amplification).
	FsMaxUploadBytes int64
	// JobTTL is how long a finished job (report or error) is retained before the
	// sweeper evicts it.
	JobTTL time.Duration
	// LogLevel is "debug" | "info" (anything != debug is treated as info).
	LogLevel string
	// ScannerVersion is the trivy version reported in the Harbor report's
	// `scanner.version`. Empty at construction; filled by ProbeVersion at
	// startup (or overridden via SCANNER_SCANNER_VERSION).
	ScannerVersion string
}

// LoadConfig reads the SCANNER_* environment variables, applying defaults.
func LoadConfig() *Config {
	return &Config{
		Addr:         getenv("SCANNER_ADAPTER_ADDR", ":8080"),
		TrivyPath:    getenv("SCANNER_TRIVY_PATH", "trivy"),
		CacheDir:     getenv("SCANNER_TRIVY_CACHE_DIR", "/home/scanner/.cache/trivy"),
		Insecure:     getenvBool("SCANNER_TRIVY_INSECURE", true),
		SkipDBUpdate: getenvBool("SCANNER_TRIVY_SKIP_DB_UPDATE", false),
		DBRepository: getenv("SCANNER_TRIVY_DB_REPOSITORY", ""),
		// Default to 3 extra attempts (2s, 4s, 8s backoff) so a transient
		// public-mirror rate-limit no longer hard-fails the release-gate (#2167).
		DBUpdateRetries:    getenvIntNonNeg("SCANNER_TRIVY_DB_UPDATE_RETRIES", 3),
		DBUpdateRetryDelay: getenvDuration("SCANNER_TRIVY_DB_UPDATE_RETRY_DELAY", 2*time.Second),
		Severity:           getenv("SCANNER_TRIVY_SEVERITY", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"),
		ScanTimeout:        getenvDuration("SCANNER_TRIVY_TIMEOUT", 5*time.Minute),
		// Defaults mirror the backend's legacy CLI path: incus rootfs scans ran
		// with --timeout 10m; the 64 GiB body cap matches the backend's
		// MAX_INCUS_SCAN_EXTRACTED_BYTES default (the backend enforces its own
		// budget before uploading).
		FsScanTimeout:    getenvDuration("SCANNER_FS_SCAN_TIMEOUT", 10*time.Minute),
		FsMaxUploadBytes: getenvInt64("SCANNER_FS_MAX_UPLOAD_BYTES", 64*1024*1024*1024),
		JobTTL:           getenvDuration("SCANNER_JOB_TTL", 30*time.Minute),
		LogLevel:         getenv("SCANNER_LOG_LEVEL", "info"),
		ScannerVersion:   os.Getenv("SCANNER_SCANNER_VERSION"),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}

func getenvInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// getenvIntNonNeg parses a non-negative int, allowing 0 (unlike getenvInt64,
// which treats 0 as invalid). Used for retry counts where 0 = "no retries".
func getenvIntNonNeg(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return def
	}
	return n
}

func getenvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return d
}
