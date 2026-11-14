package main

import (
	"strings"
	"testing"
)

func TestParseClientLimitsFormats(t *testing.T) {
	yamlBlock := `
---
# limits for the clients sharing this adapter
default:
  max_concurrent: 2   # per client
  weight: 1
"http://AK-One.example:8080/":
  max_concurrent: 4
  weight: 3
ak-two.example:8443:
  weight: 2
'ak-three.example': {max_concurrent: 1, weight: 5}
`
	jsonDoc := `{
  "default": {"max_concurrent": 2, "weight": 1},
  "http://AK-One.example:8080/": {"max_concurrent": 4, "weight": 3},
  "ak-two.example:8443": {"weight": 2},
  "ak-three.example": {"max_concurrent": 1, "weight": 5}
}`
	for name, doc := range map[string]string{"yaml": yamlBlock, "json": jsonDoc} {
		l, err := parseClientLimits([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checks := map[string]ClientLimit{
			"ak-one.example:8080": {MaxConcurrent: 4, Weight: 3}, // key normalized like registry.url
			"ak-two.example:8443": {MaxConcurrent: 2, Weight: 2}, // max_concurrent from default
			"ak-three.example":    {MaxConcurrent: 1, Weight: 5},
			"unlisted.example":    {MaxConcurrent: 2, Weight: 1},
		}
		for client, want := range checks {
			if got := l.For(client); got != want {
				t.Errorf("%s: %s = %+v, want %+v", name, client, got, want)
			}
		}
	}
}

func TestParseClientLimitsEmptyAndDefaults(t *testing.T) {
	for _, doc := range []string{"", "# nothing\n", "{}"} {
		l, err := parseClientLimits([]byte(doc))
		if err != nil {
			t.Fatalf("%q: %v", doc, err)
		}
		if got := l.For("x"); got != (ClientLimit{MaxConcurrent: 0, Weight: 1}) {
			t.Errorf("%q: default = %+v, want no cap and weight 1", doc, got)
		}
	}
}

func TestParseClientLimitsRejectsInvalid(t *testing.T) {
	for name, doc := range map[string]string{
		"zero weight":                 "a.example:\n  weight: 0\n",
		"negative max":                "a.example: {max_concurrent: -1}\n",
		"unknown field yaml":          "a.example:\n  burst: 3\n",
		"unknown field json":          `{"a.example": {"burst": 3}}`,
		"not an integer":              "a.example:\n  weight: lots\n",
		"scalar entry":                "a.example: 3\n",
		"duplicate key":               "a.example: {weight: 1}\na.example: {weight: 2}\n",
		"duplicate after normalizing": "a.example: {weight: 1}\n\"http://A.example/\": {weight: 2}\n",
		"bad indentation":             "a.example:\n  weight: 1\n    max_concurrent: 1\n",
		"orphan indented":             "  weight: 1\n",
		"tab indentation":             "a.example:\n\tweight: 1\n",
		"bad json":                    `{"a.example": `,
		"unterminated quote":          "\"a.example: {weight: 1}\n",
	} {
		if _, err := parseClientLimits([]byte(doc)); err == nil {
			t.Errorf("%s: want an error for %q", name, doc)
		}
	}
}

func TestParseClientLimitsErrorNamesLine(t *testing.T) {
	_, err := parseClientLimits([]byte("a.example:\n  weight: 1\nb.example:\n  weight: x\n"))
	if err == nil || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("error should name line 4, got %v", err)
	}
}
