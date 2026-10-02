package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client mode (SCANNER_TRIVY_SERVER): the vulnerability DB lives on the trivy
// server, not in this adapter's cache, so the local DB-presence readiness gate
// (#2167) cannot apply. The equivalent fail-closed guarantee is that the server
// is reachable, has a DB loaded, and runs the same trivy release as the bundled
// CLI. Without a DB the server would answer with empty results (a false clean);
// with a different release, analyzer output and the RPC schema can disagree in
// ways that drop findings silently, because trivy itself does not refuse a
// mismatched client.

// trivyServerVersion is the subset of trivy server's `GET /version` body the
// readiness check reads. VulnerabilityDB is null when the server has no DB.
type trivyServerVersion struct {
	Version         string           `json:"Version"`
	VulnerabilityDB *json.RawMessage `json:"VulnerabilityDB"`
}

// checkTrivyServer asks the trivy server at base for its version and DB state.
// It returns nil only when the server answers 200, reports a loaded
// vulnerability DB and, when want is non-empty, reports the same trivy version.
// The /version endpoint needs no token.
func checkTrivyServer(ctx context.Context, client *http.Client, base, want string) error {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("trivy server URL %q must be an absolute http(s) URL", base)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/version", http.NoBody)
	if err != nil {
		return fmt.Errorf("build trivy server version request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("trivy server %s unreachable: %w", base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trivy server %s /version returned %d", base, resp.StatusCode)
	}
	var info trivyServerVersion
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return fmt.Errorf("trivy server %s /version: %w", base, err)
	}
	if info.VulnerabilityDB == nil || string(*info.VulnerabilityDB) == "null" {
		return fmt.Errorf("trivy server %s has no vulnerability DB loaded", base)
	}
	if want != "" && normalizeVersion(info.Version) != normalizeVersion(want) {
		return fmt.Errorf("trivy server %s runs trivy %q but the bundled client is %q; client/server mode needs matching releases", base, info.Version, want)
	}
	return nil
}

func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// remoteGate caches the outcome of the trivy-server check for ttl, so the
// backend's per-scan /probe/ready call does not turn into one server request
// per scan, while a server that goes away (or comes back) is noticed within ttl.
type remoteGate struct {
	check func(ctx context.Context) error
	ttl   time.Duration

	mu      sync.Mutex
	checked time.Time
	lastErr error
}

func newRemoteGate(ttl time.Duration, check func(ctx context.Context) error) *remoteGate {
	return &remoteGate{check: check, ttl: ttl}
}

// Ready returns nil when the server check passed within the last ttl.
func (g *remoteGate) Ready(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.checked.IsZero() && time.Since(g.checked) < g.ttl {
		return g.lastErr
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	g.lastErr = g.check(ctx)
	g.checked = time.Now()
	return g.lastErr
}
