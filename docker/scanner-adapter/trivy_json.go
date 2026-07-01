package main

// Minimal subset of the trivy `--format json` report we consume. Only the
// fields mapped into the Harbor report are declared; everything else in trivy's
// output is ignored by encoding/json.

// TrivyReport is the top-level trivy JSON document.
type TrivyReport struct {
	Results []TrivyResult `json:"Results"`
}

// TrivyResult is one scanned target (an OS package set or a language lockfile).
type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

// TrivyVulnerability is a single CVE row inside a result.
type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
}
