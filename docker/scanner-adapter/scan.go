package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Scanner runs trivy against an image reference and maps the result into the
// Harbor report shape.
type Scanner struct {
	cfg *Config
}

// NewScanner constructs a Scanner bound to cfg.
func NewScanner(cfg *Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// trimRegistryHost strips any scheme and trailing slash from a registry URL so
// it can be used as the host prefix of a trivy image reference. Single source
// of truth for host normalization (referenced by buildRef + tests).
func trimRegistryHost(registryURL string) string {
	host := registryURL
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimRight(host, "/")
	return host
}

// buildRef assembles a fully-qualified trivy image reference from the Harbor
// request fields. It enforces the #1483 rule: a digest reference is joined with
// `@`, a tag with `:`, and exactly one of the two must be present.
func buildRef(registryURL, repository, tag, digest string) (string, error) {
	host := trimRegistryHost(registryURL)
	if repository == "" {
		return "", fmt.Errorf("repository is required")
	}
	ref := repository
	if host != "" {
		ref = host + "/" + repository
	}
	switch {
	case digest != "":
		return ref + "@" + digest, nil
	case tag != "":
		return ref + ":" + tag, nil
	default:
		return "", fmt.Errorf("artifact must carry a tag or a digest")
	}
}

// buildArgs returns the trivy CLI arguments for scanning imageRef.
func (s *Scanner) buildArgs(imageRef string) []string {
	args := []string{
		"image",
		"--format", "json",
		"--scanners", "vuln",
		"--severity", s.cfg.Severity,
		"--timeout", s.cfg.ScanTimeout.String(),
		"--cache-dir", s.cfg.CacheDir,
		"--quiet",
	}
	if s.cfg.Insecure {
		args = append(args, "--insecure")
	}
	if s.cfg.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	args = append(args, imageRef)
	return args
}

// registryToken extracts the bare token from a "Bearer <token>" authorization
// value, or "" for anonymous. Never log the return value.
func registryToken(authorization string) string {
	const prefix = "Bearer "
	if strings.HasPrefix(authorization, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
	}
	return ""
}

// dockerAuthEntry is a single registry credential in a Docker config.json. Only
// registrytoken (a bearer token) is populated; trivy/go-containerregistry sends
// it as `Authorization: Bearer <registrytoken>` for pulls from the keyed host.
type dockerAuthEntry struct {
	RegistryToken string `json:"registrytoken"`
}

// dockerConfig is the minimal Docker config.json shape trivy reads via
// DOCKER_CONFIG: a per-host auth map. Credentials are resolved PER registry
// host, so an entry keyed to the target host is never applied to trivy's
// vuln-DB OCI pull from its mirrors.
type dockerConfig struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

// dockerConfigJSON builds a Docker config.json that scopes token to a single
// registry host. Because credentials are resolved per host, the token is sent
// ONLY for pulls from host; the vuln-DB pull (mirror.gcr.io /
// ghcr.io/aquasec/trivy-db / public.ecr.aws) has no matching entry and pulls
// anonymously. Never log the return value (it embeds the token).
func dockerConfigJSON(host, token string) ([]byte, error) {
	return json.Marshal(dockerConfig{
		Auths: map[string]dockerAuthEntry{
			host: {RegistryToken: token},
		},
	})
}

// scanCredential carries the per-scan registry credential material: extra env
// for trivy (DOCKER_CONFIG when a host-scoped config was written) and a cleanup
// that removes the temp config dir. It never exposes the token as a field.
type scanCredential struct {
	env     []string
	cleanup func()
}

// buildCredential prepares the target-image pull credential. When the request
// carries a Bearer token it writes a host-scoped Docker config.json into a
// private 0700 temp dir and returns DOCKER_CONFIG pointing at it, so the bearer
// applies ONLY to the target registry host (trimRegistryHost(URL), incl. port)
// and NOT to trivy's anonymous vuln-DB pull. An anonymous request yields an
// empty credential (no config, no DOCKER_CONFIG). Callers MUST defer cleanup.
// This replaces the flat, host-unscoped TRIVY_REGISTRY_TOKEN, which trivy
// applied to EVERY registry request (including the DB mirrors, which reject the
// target-scoped bearer -> no DB -> empty results -> false clean).
func buildCredential(req *ScanRequest) (*scanCredential, error) {
	token := registryToken(req.Registry.Authorization)
	if token == "" {
		return &scanCredential{cleanup: func() {}}, nil
	}
	host := trimRegistryHost(req.Registry.URL)
	data, err := dockerConfigJSON(host, token)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "scanner-dockercfg-")
	if err != nil {
		return nil, fmt.Errorf("create docker config dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		return nil, fmt.Errorf("chmod docker config dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("write docker config: %w", err)
	}
	return &scanCredential{env: []string{"DOCKER_CONFIG=" + dir}, cleanup: cleanup}, nil
}

// trivyDBErrorMarkers are stderr substrings (matched case-insensitively) that
// indicate trivy failed to load its vulnerability DB. trivy can exit 0 with
// empty Results in this case, which would surface as a FALSE CLEAN. The set is
// kept tight to DB-fatal signals so a legitimately clean image (0 findings, no
// DB error, e.g. distroless/FROM scratch) is never flagged.
var trivyDBErrorMarkers = []string{
	"unauthorized",
	"failed to download vulnerability db",
	"vulnerability db does not exist",
	"db error",
}

// trivyOutputIndicatesDBFailure reports whether trivy stderr contains a
// DB-fatal marker. Pure fn (unit-tested) so the exit-0 fail-closed path has no
// false fire on benign output.
func trivyOutputIndicatesDBFailure(stderr string) bool {
	low := strings.ToLower(stderr)
	for _, m := range trivyDBErrorMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// dbPresent reports whether a trivy vulnerability DB is loaded in cacheDir.
// trivy stores it at <cacheDir>/db/metadata.json (+ trivy.db); a present,
// non-empty metadata file is the readiness signal.
func dbPresent(cacheDir string) bool {
	info, err := os.Stat(filepath.Join(cacheDir, "db", "metadata.json"))
	return err == nil && !info.IsDir() && info.Size() > 0
}

// DBReady reports whether the trivy vuln DB is present in cfg.CacheDir.
// Readiness is gated on this in addition to the version probe so the adapter
// never advertises ready with no DB (which trivy treats as 0 vulnerabilities).
func DBReady(cfg *Config) bool { return dbPresent(cfg.CacheDir) }

// DownloadDB triggers a trivy DB download into cfg.CacheDir. It is run at
// startup when DB updates are enabled so the DB is present before the adapter
// marks itself ready (rather than lazily on the first scan, which would race the
// readiness gate). Output is captured for the log; it never carries a token.
func DownloadDB(ctx context.Context, cfg *Config) error {
	cmd := exec.CommandContext(ctx, cfg.TrivyPath, "image", "--download-db-only", "--cache-dir", cfg.CacheDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("trivy --download-db-only failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Scan runs trivy for the given request and returns the Harbor report. Any
// non-zero exit or parse failure is an error (the caller marks the job Failed
// and the report endpoint 500s — fail-closed, never a silent empty report).
func (s *Scanner) Scan(ctx context.Context, req *ScanRequest) (*HarborScanReport, error) {
	imageRef, err := buildRef(req.Registry.URL, req.Artifact.Repository, req.Artifact.Tag, req.Artifact.Digest)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.cfg.TrivyPath, s.buildArgs(imageRef)...)
	// Inherit the adapter's environment; add a HOST-SCOPED registry credential
	// for private pulls via a per-scan Docker config (DOCKER_CONFIG). The bearer
	// is applied ONLY to the target registry host, so trivy's vuln-DB OCI pull
	// goes anonymously to its mirror (a flat TRIVY_REGISTRY_TOKEN would be sent
	// to the DB mirror too and be rejected -> no DB -> false clean). Never logged.
	cred, err := buildCredential(req)
	if err != nil {
		return nil, fmt.Errorf("prepare registry credential for %s: %w", imageRef, err)
	}
	defer cred.cleanup()
	cmd.Env = append(cmd.Environ(), cred.env...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy scan failed for %s: %v: %s", imageRef, err, strings.TrimSpace(stderr.String()))
	}

	// Exit-0 DB-failure detection: trivy can exit 0 with empty Results when its
	// vuln DB failed to load (auth-rejected mirror pull, missing/corrupt DB).
	// That is a FALSE CLEAN; treat a DB-fatal stderr marker on a zero-exit run as
	// an error so the job fails closed (report 500) instead of reporting no
	// findings. Gated on markers, not on empty Results (a distroless image can
	// legitimately catalog 0 packages).
	if trivyOutputIndicatesDBFailure(stderr.String()) {
		return nil, fmt.Errorf("trivy scan for %s reported a vulnerability-DB failure: %s", imageRef, strings.TrimSpace(stderr.String()))
	}

	var trivyReport TrivyReport
	if err := json.Unmarshal([]byte(stdout.String()), &trivyReport); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output for %s: %w", imageRef, err)
	}

	scanner := HarborScanner{Name: "Trivy", Version: s.cfg.ScannerVersion}
	return mapTrivyToHarbor(&trivyReport, scanner), nil
}

// fsSeverity is the severity filter for filesystem scans. It mirrors the
// backend's legacy `trivy filesystem` CLI invocation (trivy_fs_scanner.rs /
// incus_scanner.rs) so routing through the adapter (#2363) does not change
// which findings are reported.
const fsSeverity = "CRITICAL,HIGH,MEDIUM,LOW"

// buildFsArgs returns the trivy CLI arguments for a filesystem scan over dir.
// `--list-all-pkgs` is load-bearing: the backend's SBOM package inventory
// (#903) reads the Packages blocks it adds to the native JSON report.
func (s *Scanner) buildFsArgs(dir string) []string {
	return []string{
		"filesystem",
		"--format", "json",
		"--list-all-pkgs",
		"--severity", fsSeverity,
		"--timeout", s.cfg.FsScanTimeout.String(),
		"--cache-dir", s.cfg.CacheDir,
		"--quiet",
		dir,
	}
}

// ScanFilesystem runs `trivy filesystem` over an untarred workspace dir and
// returns trivy's NATIVE JSON report plus its stderr text. The stderr is
// returned even on success so the backend can classify partial scans (#1153).
// Fail-closed like Scan: a non-zero exit, an exit-0 DB failure, or unparseable
// output is an error (the job fails and the report endpoint 500s).
func (s *Scanner) ScanFilesystem(ctx context.Context, dir string) (json.RawMessage, string, error) {
	// Leave headroom over trivy's own --timeout so trivy's descriptive timeout
	// error wins over a blunt context kill.
	ctx, cancel := context.WithTimeout(ctx, s.cfg.FsScanTimeout+30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.cfg.TrivyPath, s.buildFsArgs(dir)...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, stderr.String(), fmt.Errorf("trivy filesystem scan failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}

	// Exit-0 DB-failure detection: same fail-closed marker check the image
	// path uses, so a missing/rejected vuln DB never yields a false clean.
	if trivyOutputIndicatesDBFailure(stderr.String()) {
		return nil, stderr.String(), fmt.Errorf("trivy filesystem scan reported a vulnerability-DB failure: %s", strings.TrimSpace(stderr.String()))
	}

	raw := []byte(stdout.String())
	if !json.Valid(raw) {
		return nil, stderr.String(), fmt.Errorf("trivy filesystem output is not valid JSON")
	}
	return json.RawMessage(raw), stderr.String(), nil
}

// ProbeVersion runs `trivy --version` and extracts the semantic version string
// (e.g. "0.71.2"). Used at startup to populate scanner.version and gate
// readiness.
func ProbeVersion(ctx context.Context, cfg *Config) (string, error) {
	cmd := exec.CommandContext(ctx, cfg.TrivyPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("trivy --version failed: %w", err)
	}
	v := parseTrivyVersion(string(out))
	if v == "" {
		return "", fmt.Errorf("could not parse trivy version from output")
	}
	return v, nil
}

// parseTrivyVersion extracts the version token from `trivy --version` output.
// The first line is `Version: 0.71.2`.
func parseTrivyVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	return ""
}
