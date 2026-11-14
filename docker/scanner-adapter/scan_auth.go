package main

// Bearer-token gate on the scan and report routes (#5948).
//
// SCANNER_SCAN_TOKEN and/or SCANNER_SCAN_TOKENS_FILE turn it on: every
// POST /api/v1/scan, POST /api/v1/filesystem/scan and their report routes then
// require `Authorization: Bearer <token>` and answer 401 otherwise. The probes
// and GET /api/v1/metadata stay open, and with neither variable set the routes
// behave as before. The scan credential is separate from SCANNER_ADAPTER_TOKEN
// (the DB-import credential) so the two rotate independently.
//
// The tokens file holds one token per line (blank lines and lines starting
// with '#' are ignored), so one adapter can serve several Artifact Keeper
// instances, each with its own credential, and drop one without touching the
// others. It is re-read whenever its modification time or size changes
// (checked on each request), which picks up a Kubernetes Secret update.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type scanAuth struct {
	// static is the digest of SCANNER_SCAN_TOKEN; nil when unset.
	static *[sha256.Size]byte
	// file is SCANNER_SCAN_TOKENS_FILE; empty when unset.
	file string

	mu       sync.Mutex
	modTime  time.Time
	size     int64
	loaded   bool
	lastErr  string
	fromFile [][sha256.Size]byte
}

// newScanAuth builds the gate from the config; nil means the routes are open.
func newScanAuth(cfg *Config) *scanAuth {
	if cfg.ScanToken == "" && cfg.ScanTokensFile == "" {
		return nil
	}
	a := &scanAuth{file: cfg.ScanTokensFile}
	if cfg.ScanToken != "" {
		d := sha256.Sum256([]byte(cfg.ScanToken))
		a.static = &d
	}
	if a.file != "" {
		a.refresh()
	}
	return a
}

// refresh re-reads the tokens file when it changed since the last read. A
// file that cannot be read keeps the last set that could (so a Secret being
// swapped does not reject a request mid-swap); one that was never read
// accepts no token from the file, failing closed.
func (a *scanAuth) refresh() {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, err := os.Stat(a.file)
	if err == nil && a.loaded && st.ModTime().Equal(a.modTime) && st.Size() == a.size {
		return
	}
	var raw []byte
	if err == nil {
		raw, err = os.ReadFile(a.file)
	}
	if err != nil {
		if msg := err.Error(); msg != a.lastErr { // once per distinct failure
			a.lastErr = msg
			log.Printf("SCANNER_SCAN_TOKENS_FILE: %v (keeping %d token(s) from the last read)", err, len(a.fromFile))
		}
		return
	}
	var tokens [][sha256.Size]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens = append(tokens, sha256.Sum256([]byte(line)))
	}
	a.fromFile = tokens
	a.modTime = st.ModTime()
	a.size = st.Size()
	a.loaded = true
	a.lastErr = ""
	log.Printf("SCANNER_SCAN_TOKENS_FILE: loaded %d scan token(s)", len(tokens))
}

// allowed reports whether presented matches a configured token. Every
// candidate is compared, by digest, so the time taken depends on neither the
// presented value nor which token (if any) it matches.
func (a *scanAuth) allowed(presented string) bool {
	if a.file != "" {
		a.refresh()
	}
	got := sha256.Sum256([]byte(presented))
	match := 0
	if a.static != nil {
		match |= subtle.ConstantTimeCompare(got[:], a.static[:])
	}
	a.mu.Lock()
	for i := range a.fromFile {
		match |= subtle.ConstantTimeCompare(got[:], a.fromFile[i][:])
	}
	a.mu.Unlock()
	return match == 1
}

// wrap guards h. A nil gate returns h unchanged.
func (a *scanAuth) wrap(h http.HandlerFunc) http.HandlerFunc {
	if a == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		if len(got) < len(prefix) || !strings.EqualFold(got[:len(prefix)], prefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scanner-adapter"`)
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if !a.allowed(strings.TrimSpace(got[len(prefix):])) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scanner-adapter", error="invalid_token"`)
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}
