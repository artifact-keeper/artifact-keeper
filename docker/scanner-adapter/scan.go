package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
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
	// Inherit the adapter's environment; add a per-scan registry token for
	// private pulls. TRIVY_REGISTRY_TOKEN is consumed by trivy's registry
	// client. The token is NEVER logged.
	cmd.Env = cmd.Environ()
	if token := registryToken(req.Registry.Authorization); token != "" {
		cmd.Env = append(cmd.Env, "TRIVY_REGISTRY_TOKEN="+token)
	}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy scan failed for %s: %v: %s", imageRef, err, strings.TrimSpace(stderr.String()))
	}

	var trivyReport TrivyReport
	if err := json.Unmarshal([]byte(stdout.String()), &trivyReport); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output for %s: %w", imageRef, err)
	}

	scanner := HarborScanner{Name: "Trivy", Version: s.cfg.ScannerVersion}
	return mapTrivyToHarbor(&trivyReport, scanner), nil
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
