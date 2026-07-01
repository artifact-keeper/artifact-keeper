package main

import "testing"

func TestMapSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "Critical",
		"HIGH":     "High",
		"MEDIUM":   "Medium",
		"LOW":      "Low",
		"UNKNOWN":  "Unknown",
		"":         "Unknown",
		"garbage":  "Unknown",
	}
	for in, want := range cases {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstLink(t *testing.T) {
	if got := firstLink(TrivyVulnerability{PrimaryURL: "https://p"}); len(got) != 1 || got[0] != "https://p" {
		t.Errorf("PrimaryURL should win: %v", got)
	}
	got := firstLink(TrivyVulnerability{References: []string{"https://r1", "https://r2"}})
	if len(got) != 1 || got[0] != "https://r1" {
		t.Errorf("first reference should be used: %v", got)
	}
	if got := firstLink(TrivyVulnerability{}); got != nil {
		t.Errorf("no links should be nil, got %v", got)
	}
}

func TestMapTrivyToHarborEmptyIsArrayNotNull(t *testing.T) {
	report := mapTrivyToHarbor(&TrivyReport{}, HarborScanner{Name: "Trivy", Version: "0.71.2"})
	if report.Vulnerabilities == nil {
		t.Fatal("Vulnerabilities must be an empty slice, not nil")
	}
	if len(report.Vulnerabilities) != 0 {
		t.Fatalf("expected 0 vulns, got %d", len(report.Vulnerabilities))
	}
	if report.Scanner.Name != "Trivy" || report.Scanner.Version != "0.71.2" {
		t.Errorf("scanner metadata not carried through: %+v", report.Scanner)
	}
}

func TestMapTrivyToHarborMapsFields(t *testing.T) {
	trivy := &TrivyReport{
		Results: []TrivyResult{
			{
				Target: "alpine:3.14",
				Class:  "os-pkgs",
				Vulnerabilities: []TrivyVulnerability{
					{
						VulnerabilityID:  "CVE-2021-1234",
						PkgName:          "openssl",
						InstalledVersion: "3.1.0",
						FixedVersion:     "3.1.1",
						Severity:         "HIGH",
						Description:      "buffer overflow",
						PrimaryURL:       "https://avd.aquasec.com/CVE-2021-1234",
					},
					{
						VulnerabilityID:  "CVE-2022-9999",
						PkgName:          "musl",
						InstalledVersion: "1.2.2",
						Severity:         "CRITICAL",
						References:       []string{"https://ref/one", "https://ref/two"},
					},
				},
			},
		},
	}
	report := mapTrivyToHarbor(trivy, HarborScanner{Name: "Trivy", Version: "0.71.2"})
	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(report.Vulnerabilities))
	}

	v0 := report.Vulnerabilities[0]
	if v0.ID != "CVE-2021-1234" || v0.Package != "openssl" || v0.Version != "3.1.0" ||
		v0.FixVersion != "3.1.1" || v0.Severity != "High" || v0.Description != "buffer overflow" {
		t.Errorf("v0 mapped incorrectly: %+v", v0)
	}
	if len(v0.Links) != 1 || v0.Links[0] != "https://avd.aquasec.com/CVE-2021-1234" {
		t.Errorf("v0 links: %v", v0.Links)
	}

	v1 := report.Vulnerabilities[1]
	if v1.Severity != "Critical" {
		t.Errorf("v1 severity = %q, want Critical", v1.Severity)
	}
	if len(v1.Links) != 1 || v1.Links[0] != "https://ref/one" {
		t.Errorf("v1 should fall back to first reference: %v", v1.Links)
	}
	if v1.FixVersion != "" {
		t.Errorf("v1 fix_version should be empty, got %q", v1.FixVersion)
	}
}
