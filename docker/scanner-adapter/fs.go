package main

// Filesystem-scan request/report types and the workspace untar step (#2363).
//
// The backend prepares (extracts + hardens) the scan workspace locally, tars
// it, and uploads the tar to POST /api/v1/filesystem/scan. The adapter untars
// it into a private temp dir and runs `trivy filesystem` over it. Unlike the
// Harbor image-scan report (which drops the Packages block), the filesystem
// report returns trivy's NATIVE JSON verbatim so the backend keeps its full
// SBOM package inventory (#903) and completeness classification (#1153).

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FsScanResult is the successful GET /api/v1/filesystem/scan/{id}/report body.
type FsScanResult struct {
	// Report is trivy's native `--format json` document, passed through
	// verbatim (including the `Packages` blocks from --list-all-pkgs).
	Report json.RawMessage `json:"report"`
	// Stderr is trivy's stderr text. The backend needs it even on success to
	// classify partial scans (#1153): a malformed lockfile only surfaces as a
	// stderr warning, never as a non-zero exit.
	Stderr string `json:"stderr"`
	// ScannerVersion is the probed trivy version (e.g. "0.71.2") for
	// scan-result provenance.
	ScannerVersion string `json:"scanner_version,omitempty"`
}

// untarWorkspace extracts an UNCOMPRESSED tar stream into dst.
//
// The backend already hardens the workspace before tarring, but the adapter
// stays defensive about the archive it executes trivy over:
//   - entries whose cleaned path escapes dst (absolute or `..`) are rejected;
//   - symlinks, hardlinks, and device nodes are skipped (trivy only needs the
//     regular files carrying package DBs / lockfiles);
//   - the stream is size-bounded upstream by http.MaxBytesReader, and since
//     the tar is uncompressed the extracted tree cannot exceed the body cap.
func untarWorkspace(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		name := filepath.Clean(hdr.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry %q escapes the workspace", hdr.Name)
		}
		target := filepath.Join(dst, name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("create dir %q: %w", name, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("create parent of %q: %w", name, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("create file %q: %w", name, err)
			}
			// The body reader is already capped by MaxBytesReader; no per-file
			// LimitReader is needed on top of an uncompressed stream.
			if _, err := io.Copy(f, tr); err != nil { //nolint:gosec
				f.Close()
				return fmt.Errorf("write file %q: %w", name, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("close file %q: %w", name, err)
			}
		default:
			// Symlinks / hardlinks / devices: skipped, never materialized.
			continue
		}
	}
}
