package main

// Image size bound (#5909). trivy pulls every layer of an image into its cache
// directory and holds the analysed layers in memory, so an image larger than
// the adapter's memory or ephemeral-storage limit gets the adapter OOM-killed
// or evicted part-way through the scan, taking every other running scan with
// it. With SCANNER_MAX_IMAGE_BYTES set, the adapter reads the image manifest
// first and refuses an image whose layers add up to more than the limit,
// without running trivy. The job then ends TooLarge, which the report route
// answers distinctly from a failed scan.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Manifest media types read by the size check. Indexes are resolved to one
// platform manifest.
const (
	ociIndexMimeType           = "application/vnd.oci.image.index.v1+json"
	dockerManifestListMimeType = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// manifestAccept is the Accept header of a manifest GET: every image
// manifest and index type trivy can scan.
var manifestAccept = strings.Join([]string{
	ociManifestMimeType, dockerManifestMimeType, ociIndexMimeType, dockerManifestListMimeType,
}, ", ")

// maxManifestBytes bounds a manifest body the size check reads. Registries
// commonly cap manifests at 4 MiB.
const maxManifestBytes = 4 << 20

// imageSizeCheckTimeout bounds the whole size check (index plus one platform
// manifest). Kept short: a hung registry must not eat into the backend's
// report-poll budget before trivy even starts, and the check fails open.
// A var so tests can shorten it.
var imageSizeCheckTimeout = 10 * time.Second

// imageTooLargeError is the outcome of an image over SCANNER_MAX_IMAGE_BYTES.
// Its message is what the report route returns, so it names the image, both
// numbers and the knob.
type imageTooLargeError struct {
	Ref   string
	Size  int64
	Limit int64
}

func (e *imageTooLargeError) Error() string {
	return fmt.Sprintf("not scanned: image too large: %s is %d bytes (compressed layers), over SCANNER_MAX_IMAGE_BYTES=%d",
		e.Ref, e.Size, e.Limit)
}

// registryManifest is the subset of an image manifest or index the size check
// reads. An image manifest has Config and Layers; an index has Manifests.
type registryManifest struct {
	MediaType string               `json:"mediaType"`
	Config    *registryDescriptor  `json:"config"`
	Layers    []registryDescriptor `json:"layers"`
	Manifests []registryDescriptor `json:"manifests"`
}

type registryDescriptor struct {
	MediaType string            `json:"mediaType"`
	Digest    string            `json:"digest"`
	Size      int64             `json:"size"`
	Platform  *registryPlatform `json:"platform"`
}

type registryPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// isIndex reports whether a manifest body (with its response Content-Type)
// is an image index / manifest list rather than an image manifest.
func (m *registryManifest) isIndex(contentType string) bool {
	for _, mt := range []string{m.MediaType, contentType} {
		mt = strings.TrimSpace(strings.SplitN(mt, ";", 2)[0])
		if mt == ociIndexMimeType || mt == dockerManifestListMimeType {
			return true
		}
	}
	return m.Config == nil && len(m.Manifests) > 0
}

// imageBytes sums the config and layer sizes of an image manifest: the
// compressed bytes trivy downloads. A negative size is an error.
func (m *registryManifest) imageBytes() (int64, error) {
	var total int64
	descs := m.Layers
	if m.Config != nil {
		descs = append([]registryDescriptor{*m.Config}, descs...)
	}
	for _, d := range descs {
		if d.Size < 0 {
			return 0, fmt.Errorf("descriptor %s has a negative size", d.Digest)
		}
		total += d.Size
		if total < 0 {
			return 0, fmt.Errorf("image size overflows int64")
		}
	}
	return total, nil
}

// pickPlatform returns the digest of the index entry the size check
// measures: the one trivy scans. The adapter passes trivy no --platform, and
// then trivy (pkg/remote/remote.go tryGet, v0.76.0) adds no
// remote.WithPlatform, so go-containerregistry (v0.22.1,
// pkg/v1/remote/index.go childByPlatform) resolves the index to its default
// platform, linux/amd64 (pkg/v1/remote/options.go defaultPlatform), whatever
// the adapter's own architecture: the first entry whose OS and architecture
// are linux and amd64, an entry without a platform counting as linux/amd64.
// "" when none matches; the check then does not block the scan.
func pickPlatform(manifests []registryDescriptor) string {
	for _, d := range manifests {
		os, arch := "linux", "amd64"
		if d.Platform != nil {
			os, arch = d.Platform.OS, d.Platform.Architecture
		}
		if os == "linux" && arch == "amd64" && d.Digest != "" {
			return d.Digest
		}
	}
	return ""
}

// manifestBaseURLs returns the registry base URLs to try, in order. A URL with
// a scheme (matched after trimming and ignoring case) is used as is. Without
// one, https is tried first and, when SCANNER_TRIVY_INSECURE is set, plain
// http after it, as trivy's --insecure does.
func manifestBaseURLs(registryURL string, insecure bool) []string {
	u := strings.TrimSpace(registryURL)
	lower := strings.ToLower(u)
	switch {
	case strings.HasPrefix(lower, "http://"):
		return []string{"http://" + strings.TrimRight(u[len("http://"):], "/")}
	case strings.HasPrefix(lower, "https://"):
		return []string{"https://" + strings.TrimRight(u[len("https://"):], "/")}
	}
	host := strings.TrimRight(u, "/")
	if insecure {
		return []string{"https://" + host, "http://" + host}
	}
	return []string{"https://" + host}
}

// newRegistryHTTPClient is the client of the size check. With
// SCANNER_TRIVY_INSECURE it skips TLS verification, as the trivy invocation
// it runs before does (--insecure).
func newRegistryHTTPClient(cfg *Config) *http.Client {
	client := &http.Client{Timeout: imageSizeCheckTimeout}
	if cfg.Insecure {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // same opt-in as trivy --insecure on the scan itself
		client.Transport = tr
	}
	return client
}

// fetchManifest GETs <base>/v2/<repository>/manifests/<reference> with the
// scan request's bearer credential. The token is never logged or returned.
func fetchManifest(ctx context.Context, client *http.Client, base, repository, reference, authorization string) (*registryManifest, string, error) {
	u := base + "/v2/" + repository + "/manifests/" + reference
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, "", fmt.Errorf("build manifest request: %w", err)
	}
	req.Header.Set("Accept", manifestAccept)
	if token := registryToken(authorization); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET %s answered %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read manifest %s: %w", u, err)
	}
	if len(body) > maxManifestBytes {
		return nil, "", fmt.Errorf("manifest %s is larger than %d bytes", u, maxManifestBytes)
	}
	var m registryManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, "", fmt.Errorf("parse manifest %s: %w", u, err)
	}
	return &m, resp.Header.Get("Content-Type"), nil
}

// measureImage returns the compressed size of the image req names, resolving
// an index to the platform manifest trivy scans (see pickPlatform).
func (s *Scanner) measureImage(ctx context.Context, req *ScanRequest) (int64, error) {
	reference := req.Artifact.Digest
	if reference == "" {
		reference = req.Artifact.Tag
	}
	if req.Artifact.Repository == "" || reference == "" {
		return 0, errors.New("request names no repository and reference")
	}
	var lastErr error
	for _, base := range manifestBaseURLs(req.Registry.URL, s.cfg.Insecure) {
		size, err := s.measureAt(ctx, base, req.Artifact.Repository, reference, req.Registry.Authorization)
		if err == nil {
			return size, nil
		}
		lastErr = err
	}
	return 0, lastErr
}

func (s *Scanner) measureAt(ctx context.Context, base, repository, reference, authorization string) (int64, error) {
	m, contentType, err := fetchManifest(ctx, s.registryClient, base, repository, reference, authorization)
	if err != nil {
		return 0, err
	}
	if m.isIndex(contentType) {
		digest := pickPlatform(m.Manifests)
		if digest == "" {
			return 0, fmt.Errorf("index lists no linux/amd64 image (the platform trivy scans)")
		}
		m, contentType, err = fetchManifest(ctx, s.registryClient, base, repository, digest, authorization)
		if err != nil {
			return 0, err
		}
		if m.isIndex(contentType) {
			return 0, fmt.Errorf("platform entry %s is itself an index", digest)
		}
	}
	return m.imageBytes()
}

// checkImageSize enforces SCANNER_MAX_IMAGE_BYTES. It returns a non-nil
// *imageTooLargeError only when the image's measured size is over the limit.
// A disabled check returns nil, and so does a manifest that cannot be read
// or measured: that is logged and the scan runs as it would without the
// check, so the bound never fails a scan that would otherwise succeed.
func (s *Scanner) checkImageSize(ctx context.Context, req *ScanRequest) *imageTooLargeError {
	if s.cfg.MaxImageBytes <= 0 {
		return nil
	}
	// buildRef takes the host as given (#5943): trim it once, like Scan does.
	ref, err := buildRef(trimRegistryHost(req.Registry.URL), req.Artifact.Repository, req.Artifact.Tag, req.Artifact.Digest)
	if err != nil {
		return nil // Scan reports the bad reference itself.
	}
	ctx, cancel := context.WithTimeout(ctx, imageSizeCheckTimeout)
	defer cancel()
	size, err := s.measureImage(ctx, req)
	if err != nil {
		log.Printf("image size check skipped for %s, scanning without it: %v", ref, err)
		return nil
	}
	if size > s.cfg.MaxImageBytes {
		return &imageTooLargeError{Ref: ref, Size: size, Limit: s.cfg.MaxImageBytes}
	}
	return nil
}
