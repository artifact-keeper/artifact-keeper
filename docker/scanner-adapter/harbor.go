package main

// Harbor Pluggable Scanner API v1 request/response types and the trivy->Harbor
// mapping. See https://github.com/goharbor/pluggable-scanner-spec. The JSON
// shapes here are the FROZEN contract PR #2090's `image_scanner.rs` deserializes
// (HarborScanResponse / HarborScanReport), so field names and casing must not
// drift.

// The media type the report endpoint produces / the backend requests via
// `Accept`.
const reportMimeType = "application/vnd.security.vulnerability.report; version=1.1"

// Manifest media types the adapter advertises as consumable in /api/v1/metadata.
const (
	ociManifestMimeType    = "application/vnd.oci.image.manifest.v1+json"
	dockerManifestMimeType = "application/vnd.docker.distribution.manifest.v2+json"
)

// ScanRequest is the body of POST /api/v1/scan sent by the backend.
type ScanRequest struct {
	Registry RegistryRef `json:"registry"`
	Artifact ArtifactRef `json:"artifact"`
}

// RegistryRef identifies the registry the adapter should pull from.
type RegistryRef struct {
	URL string `json:"url"`
	// Authorization is "Bearer <jwt>" for private pulls, omitted for anonymous.
	Authorization string `json:"authorization,omitempty"`
}

// ArtifactRef identifies the image to scan: repository plus exactly one of
// tag / digest.
type ArtifactRef struct {
	Repository string `json:"repository"`
	MimeType   string `json:"mime_type"`
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

// ScanResponse is the body of a successful POST /api/v1/scan: the opaque id used
// to fetch the report.
type ScanResponse struct {
	ID string `json:"id"`
}

// HarborScanReport is the successful GET /api/v1/scan/{id}/report body.
type HarborScanReport struct {
	Scanner         HarborScanner         `json:"scanner"`
	Vulnerabilities []HarborVulnerability `json:"vulnerabilities"`
}

// HarborScanner identifies the scanner that produced the report.
type HarborScanner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HarborVulnerability is one Harbor-shaped CVE row.
type HarborVulnerability struct {
	ID          string   `json:"id"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	FixVersion  string   `json:"fix_version,omitempty"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Links       []string `json:"links,omitempty"`
}

// ScannerMetadata is the GET /api/v1/metadata body (Harbor conformance / #237).
type ScannerMetadata struct {
	Scanner      HarborScannerInfo   `json:"scanner"`
	Capabilities []ScannerCapability `json:"capabilities"`
}

// HarborScannerInfo describes the scanner in metadata.
type HarborScannerInfo struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// ScannerCapability advertises the consumed/produced media types.
type ScannerCapability struct {
	ConsumesMimeTypes []string `json:"consumes_mime_types"`
	ProducesMimeTypes []string `json:"produces_mime_types"`
}

// mapSeverity translates a trivy UPPERCASE severity token into the Harbor
// Title-case vocabulary the backend expects. Single source of truth for the
// severity mapping (referenced by scan + tests).
func mapSeverity(trivySeverity string) string {
	switch trivySeverity {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	case "UNKNOWN":
		return "Unknown"
	default:
		// Empty or unrecognized -> Unknown (backend maps Unknown -> Info).
		return "Unknown"
	}
}

// firstLink returns the best single reference URL for a trivy vuln: PrimaryURL
// when present, otherwise the first entry in References. Single source of truth
// for the link/reference selection (referenced by the mapping + tests).
func firstLink(v TrivyVulnerability) []string {
	if v.PrimaryURL != "" {
		return []string{v.PrimaryURL}
	}
	if len(v.References) > 0 {
		return []string{v.References[0]}
	}
	return nil
}

// mapTrivyToHarbor flattens every result's vulnerabilities into the Harbor
// report shape. The vulnerabilities slice is always non-nil (empty array, never
// null) so the JSON body serializes as `[]` for a clean image.
func mapTrivyToHarbor(report *TrivyReport, scanner HarborScanner) *HarborScanReport {
	vulns := make([]HarborVulnerability, 0)
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			vulns = append(vulns, HarborVulnerability{
				ID:          v.VulnerabilityID,
				Package:     v.PkgName,
				Version:     v.InstalledVersion,
				FixVersion:  v.FixedVersion,
				Severity:    mapSeverity(v.Severity),
				Description: v.Description,
				Links:       firstLink(v),
			})
		}
	}
	return &HarborScanReport{
		Scanner:         scanner,
		Vulnerabilities: vulns,
	}
}
