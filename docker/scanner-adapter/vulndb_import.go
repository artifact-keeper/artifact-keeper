package main

// Vulnerability-DB import and status routes (#5287).
//
// A disconnected install cannot download the trivy DB, so it carries the DB
// across the gap and imports it:
//
//	PUT /api/v1/vulndb[?force=true]   body: db.tar.gz
//	GET /api/v1/vulndb                metadata.json + age
//
// The body is the layer `oras pull ghcr.io/aquasecurity/trivy-db:2` writes,
// db.tar.gz, a gzip tar holding exactly trivy.db and metadata.json. Both
// routes require `Authorization: Bearer $SCANNER_ADAPTER_TOKEN` and are off
// (403) while that variable is unset.
//
// Import order, each step failing without touching <CacheDir>/db:
//  1. stream the body (capped) into a fresh temp dir inside CacheDir, so the
//     final rename stays on one filesystem, hashing it on the way;
//  2. accept only the two regular files, by exact name (no paths, links,
//     directories or duplicates), with a cap on the extracted bytes, and
//     read the gzip stream to its end so a truncated or corrupt tail is
//     caught by the gzip checksum;
//  3. check trivy.db carries the bbolt magic, and that metadata.json parses,
//     carries the expected schema Version and an UpdatedAt;
//  4. under the DB write lock: refuse a DB older than the installed one
//     unless force=true (409), then rename the installed db dir aside,
//     rename the new one into place (renaming the old one back if that
//     fails), and remove the old one.
//
// Concurrency: every trivy scan holds the DB read lock for its whole run
// (Scanner.runLocked). trivy opens trivy.db once per run, early; a rename
// between the two swap renames would make a scan that is starting see no DB,
// and with DB updates on trivy may rewrite the db dir mid-run. Holding the
// read lock for the run makes the swap wait for in-flight scans, and new
// scans wait for the swap (Go's RWMutex blocks new readers behind a waiting
// writer). The upload and verification run before the lock is taken, so only
// the two renames are serialized against scans. A scan that already has the
// old trivy.db open would in any case keep reading the old inode safely.

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	trivyDBFile    = "trivy.db"
	trivyMetaFile  = "metadata.json"
	importTempGlob = ".vulndb-import-"
	// bboltMagic is the magic number in a bbolt meta page (offset 16, after
	// the 16-byte page header), little-endian as bbolt writes it on every
	// platform trivy ships for.
	bboltMagic = 0xED0CDAED
	// maxMetadataBytes bounds metadata.json (a ~150 byte document).
	maxMetadataBytes = 64 * 1024
)

// importError is a refusal with the HTTP status it maps to.
type importError struct {
	status int
	msg    string
	cause  error
}

func (e *importError) Error() string { return e.msg }
func (e *importError) Unwrap() error { return e.cause }

// badImport is a 400 refusal. A %w operand stays reachable through
// errors.As, so an over-cap body (http.MaxBytesError) surfacing inside the
// gzip or tar reader is still reported as 413.
func badImport(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	return &importError{status: http.StatusBadRequest, msg: err.Error(), cause: errors.Unwrap(err)}
}

// VulnDBStatus is the body of GET /api/v1/vulndb and of a successful import.
type VulnDBStatus struct {
	VulnDBInfo
	// AgeSeconds is now - UpdatedAt (the upstream build time), or absent
	// when the DB carries no UpdatedAt.
	AgeSeconds *int64 `json:"age_seconds,omitempty"`
	// Stale is true once NextUpdate has passed.
	Stale bool `json:"stale"`
	// Offline reports SCANNER_OFFLINE.
	Offline bool `json:"offline"`
}

// ImportResult is the body of a successful PUT /api/v1/vulndb.
type ImportResult struct {
	Imported VulnDBStatus `json:"imported"`
	// Previous is the DB that was replaced, absent when there was none.
	Previous *VulnDBInfo `json:"previous,omitempty"`
	// SHA256 is the digest of the uploaded db.tar.gz.
	SHA256 string `json:"sha256"`
	// Forced reports that force=true was given.
	Forced bool `json:"forced"`
}

func dbStatus(info *VulnDBInfo, offline bool, now time.Time) VulnDBStatus {
	st := VulnDBStatus{VulnDBInfo: *info, Offline: offline}
	if info.UpdatedAt != nil {
		age := int64(now.Sub(*info.UpdatedAt) / time.Second)
		st.AgeSeconds = &age
	}
	if info.NextUpdate != nil && now.After(*info.NextUpdate) {
		st.Stale = true
	}
	return st
}

// authorizeVulnDB enforces the shared bearer token on the DB routes and
// writes the refusal itself. An unset token disables the routes.
func (s *Server) authorizeVulnDB(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdapterToken == "" {
		http.Error(w, "vulnerability-DB routes are disabled: set SCANNER_ADAPTER_TOKEN", http.StatusForbidden)
		return false
	}
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if !strings.HasPrefix(got, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scanner-adapter"`)
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return false
	}
	// Compare digests so the comparison is constant-time whatever the lengths.
	a := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(got, prefix))))
	b := sha256.Sum256([]byte(s.cfg.AdapterToken))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scanner-adapter", error="invalid_token"`)
		http.Error(w, "invalid bearer token", http.StatusUnauthorized)
		return false
	}
	return true
}

// handleVulnDBGet serves the installed DB's metadata and age.
func (s *Server) handleVulnDBGet(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeVulnDB(w, r) {
		return
	}
	if s.cfg.TrivyServer != "" {
		http.Error(w, "client mode: the trivy server holds the vulnerability DB", http.StatusNotFound)
		return
	}
	s.scanner.dbMu.RLock()
	info, err := ReadVulnDBInfo(s.cfg.CacheDir)
	s.scanner.dbMu.RUnlock()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "no vulnerability DB installed", http.StatusNotFound)
			return
		}
		http.Error(w, "vulnerability DB metadata unreadable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, dbStatus(info, s.cfg.Offline, time.Now()))
}

// handleVulnDBPut imports a trivy DB tarball (see the file comment).
func (s *Server) handleVulnDBPut(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeVulnDB(w, r) {
		return
	}
	if s.cfg.TrivyServer != "" {
		http.Error(w, "client mode: import the DB into the trivy server, not the adapter", http.StatusConflict)
		return
	}
	force := false
	if v := r.URL.Query().Get("force"); v != "" {
		f, err := parseBool(v)
		if err != nil {
			http.Error(w, "force must be true or false", http.StatusBadRequest)
			return
		}
		force = f
	}
	body := http.MaxBytesReader(w, r.Body, s.cfg.VulnDBMaxUploadBytes)
	res, err := s.importVulnDB(body, force, time.Now())
	if err != nil {
		var ie *importError
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			http.Error(w, fmt.Sprintf("DB tarball exceeds %d bytes (SCANNER_VULNDB_MAX_UPLOAD_BYTES)", mbe.Limit), http.StatusRequestEntityTooLarge)
		case errors.As(err, &ie):
			http.Error(w, ie.msg, ie.status)
		default:
			log.Printf("vulnerability DB import failed: %v", err)
			http.Error(w, "vulnerability DB import failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	log.Printf("vulnerability DB imported: schema=%d updated_at=%s sha256=%s forced=%t",
		res.Imported.Version, fmtTime(res.Imported.UpdatedAt), res.SHA256, res.Forced)
	if s.versionProbed.Load() && s.markReadyIfDBPresent(func() bool { return DBReady(s.cfg) }) {
		log.Printf("trivy vuln DB present; adapter ready (trivy=%s)", s.cfg.ScannerVersion)
	}
	writeJSON(w, http.StatusOK, res)
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "yes":
		return true, nil
	case "0", "f", "false", "no":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean: %q", v)
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// importVulnDB stages, verifies and installs the DB tarball read from body.
// On any error <CacheDir>/db is left exactly as it was.
func (s *Server) importVulnDB(body io.Reader, force bool, now time.Time) (*ImportResult, error) {
	cfg := s.cfg
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	stage, err := os.MkdirTemp(cfg.CacheDir, importTempGlob)
	if err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := os.Chmod(stage, 0o700); err != nil {
		return nil, fmt.Errorf("secure staging dir: %w", err)
	}
	newDB := filepath.Join(stage, "db")
	if err := os.Mkdir(newDB, 0o755); err != nil {
		return nil, fmt.Errorf("create staging db dir: %w", err)
	}

	hash := sha256.New()
	if err := extractDBTarball(io.TeeReader(body, hash), newDB, cfg.VulnDBMaxExtractedBytes); err != nil {
		return nil, err
	}
	// Hash the whole upload, including anything after the gzip stream.
	if _, err := io.Copy(hash, body); err != nil {
		return nil, err
	}
	digest := hex.EncodeToString(hash.Sum(nil))

	info, err := verifyStagedDB(newDB, cfg.DBSchemaVersion)
	if err != nil {
		return nil, err
	}
	// Record the import time where trivy records its download time, so
	// GET shows when this DB arrived (UpdatedAt stays the upstream build).
	if err := stampDownloadedAt(filepath.Join(newDB, trivyMetaFile), now); err != nil {
		return nil, fmt.Errorf("stamp metadata.json: %w", err)
	}
	t := now.UTC()
	info.DownloadedAt = &t

	s.scanner.dbMu.Lock()
	defer s.scanner.dbMu.Unlock()

	dbDir := filepath.Join(cfg.CacheDir, "db")
	var prev *VulnDBInfo
	if cur, err := ReadVulnDBInfo(cfg.CacheDir); err == nil {
		prev = cur
	}
	if prev != nil && prev.UpdatedAt != nil && info.UpdatedAt.Before(*prev.UpdatedAt) && !force {
		return nil, &importError{status: http.StatusConflict, msg: fmt.Sprintf(
			"refusing to replace the installed DB (UpdatedAt %s) with an older one (UpdatedAt %s); retry with ?force=true to downgrade",
			fmtTime(prev.UpdatedAt), fmtTime(info.UpdatedAt))}
	}
	if err := swapDir(dbDir, newDB, filepath.Join(stage, "old")); err != nil {
		return nil, err
	}
	return &ImportResult{
		Imported: dbStatus(info, cfg.Offline, now),
		Previous: prev,
		SHA256:   digest,
		Forced:   force,
	}, nil
}

// swapDir installs newDir at dst. An existing dst is first renamed to
// aside; if installing fails it is renamed back. aside is left for the
// caller to remove.
func swapDir(dst, newDir, aside string) error {
	hadOld := true
	if err := os.Rename(dst, aside); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("move installed DB aside: %w", err)
		}
		hadOld = false
	}
	if err := os.Rename(newDir, dst); err != nil {
		if hadOld {
			if rerr := os.Rename(aside, dst); rerr != nil {
				return fmt.Errorf("install DB: %w (restoring the previous DB also failed: %v)", err, rerr)
			}
		}
		return fmt.Errorf("install DB: %w", err)
	}
	return nil
}

// extractDBTarball reads a gzip tar holding exactly trivy.db and
// metadata.json (each a regular file, optionally prefixed "./") into dir.
func extractDBTarball(r io.Reader, dir string, maxExtracted int64) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return badImport("not a gzip stream: %w", err)
	}
	// One member only: a second gzip member would be read as a continuation.
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	remaining := maxExtracted
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return badImport("corrupt DB tarball: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name != trivyDBFile && name != trivyMetaFile {
			return badImport("unexpected entry %q in DB tarball: only %s and %s are allowed", hdr.Name, trivyDBFile, trivyMetaFile)
		}
		if hdr.Typeflag != tar.TypeReg {
			return badImport("entry %q in DB tarball is not a regular file", hdr.Name)
		}
		if seen[name] {
			return badImport("duplicate entry %q in DB tarball", hdr.Name)
		}
		seen[name] = true
		if hdr.Size < 0 || hdr.Size > remaining {
			return badImport("DB tarball expands beyond %d bytes (SCANNER_VULNDB_MAX_EXTRACTED_BYTES)", maxExtracted)
		}
		if name == trivyMetaFile && hdr.Size > maxMetadataBytes {
			return badImport("%s is %d bytes; not a trivy DB metadata document", trivyMetaFile, hdr.Size)
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return fmt.Errorf("stage %s: %w", name, err)
		}
		n, err := io.Copy(f, tr)
		cerr := f.Close()
		if err != nil {
			return badImport("corrupt DB tarball reading %s: %w", name, err)
		}
		if cerr != nil {
			return fmt.Errorf("stage %s: %w", name, cerr)
		}
		remaining -= n
	}
	// Read to the end of the gzip member so its CRC and length are checked.
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return badImport("corrupt DB tarball: %w", err)
	}
	for _, want := range []string{trivyDBFile, trivyMetaFile} {
		if !seen[want] {
			return badImport("DB tarball has no %s", want)
		}
	}
	return nil
}

// verifyStagedDB checks the staged trivy.db and metadata.json.
func verifyStagedDB(dir string, wantSchema int) (*VulnDBInfo, error) {
	f, err := os.Open(filepath.Join(dir, trivyDBFile))
	if err != nil {
		return nil, fmt.Errorf("open staged %s: %w", trivyDBFile, err)
	}
	head := make([]byte, 24)
	_, err = io.ReadFull(f, head)
	_ = f.Close()
	if err != nil || binary.LittleEndian.Uint32(head[16:20]) != bboltMagic {
		return nil, badImport("%s is not a bolt database", trivyDBFile)
	}
	raw, err := os.ReadFile(filepath.Join(dir, trivyMetaFile))
	if err != nil {
		return nil, fmt.Errorf("read staged %s: %w", trivyMetaFile, err)
	}
	info, err := parseDBMetadata(raw)
	if err != nil {
		return nil, badImport("invalid %s: %v", trivyMetaFile, err)
	}
	if info.Version != wantSchema {
		return nil, badImport("DB schema version %d does not match the version this adapter's trivy expects (%d, SCANNER_TRIVY_DB_SCHEMA_VERSION); pull ghcr.io/aquasecurity/trivy-db:%d",
			info.Version, wantSchema, wantSchema)
	}
	if info.UpdatedAt == nil {
		return nil, badImport("%s carries no UpdatedAt", trivyMetaFile)
	}
	return info, nil
}

// stampDownloadedAt sets DownloadedAt in a metadata.json, keeping every other
// field as it was.
func stampDownloadedAt(path string, now time.Time) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	ts, err := json.Marshal(now.UTC())
	if err != nil {
		return err
	}
	doc["DownloadedAt"] = ts
	out, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// cleanStaleImports removes staging dirs an interrupted import left behind.
func cleanStaleImports(cacheDir string) {
	matches, _ := filepath.Glob(filepath.Join(cacheDir, importTempGlob+"*"))
	for _, m := range matches {
		_ = os.RemoveAll(m)
	}
}
