package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
// mismatched client. The readiness gate checks this every 10s; each scan
// re-checks it against the server info trivy embeds in its report.

// readinessCheckTimeout bounds one GET <server>/version for the readiness gate.
// It stays under the backend's 5s /probe/ready timeout (HEALTH_CHECK_TIMEOUT)
// so a slow server is reported as not-ready rather than as a cancelled probe.
const readinessCheckTimeout = 3 * time.Second

// trivyServerVersion is the subset of trivy server's `GET /version` body (and
// of the report's `Trivy.Server` block, which is the same document) that the
// adapter reads. VulnerabilityDB is absent when the server has no DB; it has
// the same fields as <cache>/db/metadata.json.
type trivyServerVersion struct {
	Version string `json:"Version"`
	// encoding/json leaves a pointer nil for both an absent key and a literal
	// `null`, so nil is the single "no DB" state.
	VulnerabilityDB *json.RawMessage `json:"VulnerabilityDB"`
}

// redactURL renders a URL for logs with any userinfo password masked.
// Userinfo is rejected by validateClientMode; this is belt and braces.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable URL>"
	}
	return u.Redacted()
}

// validateClientMode checks the client-mode settings once at startup. A bad
// setting keeps the adapter not-ready (fail closed) with one clear log line,
// instead of failing every /probe/ready.
//
//   - SCANNER_TRIVY_SERVER must be an absolute http(s) URL with no userinfo,
//     path, query or fragment. trivy resolves `version` against the base and
//     the server serves it at the root, so a path would make the adapter and
//     trivy probe different URLs.
//   - trivy's --insecure is global: it also disables TLS verification on the
//     RPC scan client and the remote cache client. With an https server and
//     SCANNER_TRIVY_INSECURE (default true, meant for plain-HTTP registry
//     pulls), every scan would send TRIVY_TOKEN and receive findings over
//     unverified TLS. That combination needs SCANNER_TRIVY_SERVER_INSECURE=true.
func (c *Config) validateClientMode() error {
	u, err := url.Parse(c.TrivyServer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("SCANNER_TRIVY_SERVER %q must be an absolute http(s) URL", redactURL(c.TrivyServer))
	}
	if u.User != nil {
		return fmt.Errorf("SCANNER_TRIVY_SERVER %s must not carry credentials; use TRIVY_TOKEN", u.Redacted())
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("SCANNER_TRIVY_SERVER %s must be scheme://host[:port] with no path, query or fragment", u.Redacted())
	}
	if u.Scheme == "https" && c.Insecure && !c.TrivyServerInsecure {
		return fmt.Errorf("SCANNER_TRIVY_SERVER %s is https but SCANNER_TRIVY_INSECURE=true would make trivy skip TLS verification of the server too (it is a global flag); set SCANNER_TRIVY_INSECURE=false, or SCANNER_TRIVY_SERVER_INSECURE=true to accept an unverified server", u.Redacted())
	}
	return nil
}

// serverTLSUnverified reports whether scans reach an https trivy server
// without TLS verification (the explicit SCANNER_TRIVY_SERVER_INSECURE opt-in).
func (c *Config) serverTLSUnverified() bool {
	return strings.HasPrefix(c.TrivyServer, "https://") && c.Insecure && c.TrivyServerInsecure
}

// startClientMode validates the client-mode config, probes the bundled trivy
// CLI and marks the adapter ready. On error the adapter stays not-ready.
//
// The probe always runs, even when SCANNER_SCANNER_VERSION pins the reported
// version: the server must match the binary that actually runs, not the pin.
func (s *Server) startClientMode(ctx context.Context) error {
	if err := s.cfg.validateClientMode(); err != nil {
		return err
	}
	version, err := ProbeVersion(ctx, s.cfg)
	if err != nil {
		return fmt.Errorf("trivy version probe failed: %w", err)
	}
	s.cfg.ClientVersion = version
	if s.cfg.ScannerVersion == "" {
		s.cfg.ScannerVersion = version
	}
	if s.cfg.serverTLSUnverified() {
		log.Printf("WARNING: SCANNER_TRIVY_SERVER_INSECURE=true: TLS to trivy server %s is NOT verified; TRIVY_TOKEN and scan results can be intercepted or forged by anyone on the path", redactURL(s.cfg.TrivyServer))
	}
	s.MarkReady()
	return nil
}

// newServerHTTPClient is the readiness gate's client. It verifies TLS unless
// the operator opted out with SCANNER_TRIVY_SERVER_INSECURE, matching what the
// trivy subprocess does, so readiness never looks safer than the scans are.
func newServerHTTPClient(cfg *Config) *http.Client {
	client := &http.Client{Timeout: readinessCheckTimeout}
	if cfg.serverTLSUnverified() {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit operator opt-in, warned at startup
		client.Transport = tr
	}
	return client
}

// fetchTrivyServerVersion GETs <base>/version from a trivy server and decodes
// it. It fails on a non-absolute URL, a transport error or a non-200 answer.
// The /version endpoint needs no token.
func fetchTrivyServerVersion(ctx context.Context, client *http.Client, base string) (*trivyServerVersion, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("trivy server URL %q must be an absolute http(s) URL", redactURL(base))
	}
	shown := u.Redacted()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/version", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build trivy server version request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trivy server %s unreachable: %w", shown, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trivy server %s /version returned %d", shown, resp.StatusCode)
	}
	var info trivyServerVersion
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return nil, fmt.Errorf("trivy server %s /version: %w", shown, err)
	}
	return &info, nil
}

// verify checks a server's version info against the bundled client version:
// the server must report a loaded DB and the same trivy release. An empty want
// (client version unknown) fails closed.
func (v *trivyServerVersion) verify(want string) error {
	if v.VulnerabilityDB == nil {
		return errors.New("trivy server has no vulnerability DB loaded")
	}
	if want == "" {
		return errors.New("bundled trivy version unknown; cannot verify the trivy server release")
	}
	if normalizeVersion(v.Version) != normalizeVersion(want) {
		return fmt.Errorf("trivy server runs trivy %q but the bundled client is %q; client/server mode needs matching releases", v.Version, want)
	}
	return nil
}

// checkTrivyServer asks the trivy server at base for its version and DB state.
// It returns nil only when the server answers 200, reports a loaded
// vulnerability DB and reports the same trivy version as want.
func checkTrivyServer(ctx context.Context, client *http.Client, base, want string) error {
	info, err := fetchTrivyServerVersion(ctx, client, base)
	if err != nil {
		return err
	}
	if err := info.verify(want); err != nil {
		return fmt.Errorf("%s: %w", redactURL(base), err)
	}
	return nil
}

// trivyReportInfo is the report's top-level `Trivy` block. In client mode
// trivy (>= 0.74) fetches the server's /version alongside the Scan RPC and
// embeds it as `Server`; it is absent in standalone mode, and also when that
// fetch failed (trivy only logs a warning then).
type trivyReportInfo struct {
	Version string              `json:"Version"`
	Server  *trivyServerVersion `json:"Server"`
}

// clientModeProvenance verifies the server a client-mode scan actually ran
// against and returns its DB provenance (#3014). It is taken from the report
// itself, so it names the DB that served this scan even if the server's DB
// changed since. An error fails the scan closed: a report with no server info
// cannot be verified, a server without a DB yields a false clean, and a
// different release can drop findings silently. A DB block that is present but
// malformed only omits provenance.
func clientModeProvenance(info trivyReportInfo, want string) (*VulnDBInfo, error) {
	if info.Server == nil || info.Server.Version == "" {
		return nil, errors.New("trivy report carries no server version (Trivy.Server); cannot verify the trivy server this scan ran against")
	}
	if err := info.Server.verify(want); err != nil {
		return nil, err
	}
	db, err := parseDBMetadata(*info.Server.VulnerabilityDB)
	if err != nil {
		log.Printf("trivy DB provenance unavailable: %v", err)
		return nil, nil
	}
	return db, nil
}

func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// remoteGate caches the outcome of the trivy-server check for ttl, so the
// backend's per-scan /probe/ready call does not turn into one server request
// per scan, while a server that goes away (or comes back) is noticed within ttl.
//
// The check runs on its own context (readinessCheckTimeout), never on the
// probe request's: a backend that gives up on a slow probe must not leave a
// "context canceled" verdict cached for the next ttl.
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

// Ready returns nil when the server check passed within the last ttl. fresh is
// true when this call ran the check (rather than reusing the cached verdict),
// so callers can log a failure once per check instead of once per probe.
func (g *remoteGate) Ready() (fresh bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.checked.IsZero() && time.Since(g.checked) < g.ttl {
		return false, g.lastErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), readinessCheckTimeout)
	defer cancel()
	g.lastErr = g.check(ctx)
	g.checked = time.Now()
	return true, g.lastErr
}
