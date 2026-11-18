package main

// Per-client limits file (SCANNER_CLIENT_LIMITS_FILE, #5944).
//
// The file maps a client (a registry host, see clientKey) to its
// max_concurrent and weight, with a `default` entry for every client not
// listed. It is JSON, or YAML in the block or flow style shown in the README
// (the adapter is stdlib-only, so it reads that subset of YAML rather than
// all of it; JSON is valid YAML as well):
//
//	default:
//	  max_concurrent: 2
//	  weight: 1
//	"ak-one.example:8080":
//	  max_concurrent: 4
//	  weight: 3
//
// max_concurrent 0 (or absent) means no per-client cap; weight must be at
// least 1. A listed client's absent field takes the default entry's value.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// ClientLimit is one client's scheduling limits.
type ClientLimit struct {
	// MaxConcurrent is how many of the client's scans may run at once; 0 is
	// no per-client cap (the global SCANNER_MAX_CONCURRENT_SCANS still holds).
	MaxConcurrent int
	// Weight is the client's share in the weighted round robin: jobs started
	// per round while it has jobs queued. At least 1.
	Weight int
}

// ClientLimits is a parsed limits file. Immutable once built.
type ClientLimits struct {
	def     ClientLimit
	clients map[string]ClientLimit
}

// limitsDefaultKey is the limits file entry for clients not listed.
const limitsDefaultKey = "default"

func defaultClientLimits() *ClientLimits {
	return &ClientLimits{def: ClientLimit{Weight: 1}, clients: map[string]ClientLimit{}}
}

// For returns the limits of client.
func (l *ClientLimits) For(client string) ClientLimit {
	if c, ok := l.clients[client]; ok {
		return c
	}
	return l.def
}

// rawLimit is one entry as written in the file.
type rawLimit struct {
	MaxConcurrent *int `json:"max_concurrent"`
	Weight        *int `json:"weight"`
}

// parseClientLimits parses a limits file (JSON or the YAML subset).
func parseClientLimits(data []byte) (*ClientLimits, error) {
	var raw map[string]rawLimit
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("parse JSON: %w", err)
		}
	} else {
		var err error
		if raw, err = parseLimitsYAML(string(data)); err != nil {
			return nil, err
		}
	}
	return buildClientLimits(raw)
}

func buildClientLimits(raw map[string]rawLimit) (*ClientLimits, error) {
	out := defaultClientLimits()
	apply := func(base ClientLimit, r rawLimit, name string) (ClientLimit, error) {
		if r.MaxConcurrent != nil {
			if *r.MaxConcurrent < 0 {
				return base, fmt.Errorf("%s: max_concurrent must be >= 0", name)
			}
			base.MaxConcurrent = *r.MaxConcurrent
		}
		if r.Weight != nil {
			if *r.Weight < 1 {
				return base, fmt.Errorf("%s: weight must be >= 1", name)
			}
			base.Weight = *r.Weight
		}
		return base, nil
	}
	if d, ok := raw[limitsDefaultKey]; ok {
		def, err := apply(out.def, d, limitsDefaultKey)
		if err != nil {
			return nil, err
		}
		out.def = def
	}
	for name, r := range raw {
		if name == limitsDefaultKey {
			continue
		}
		key := clientKey(name)
		if key == "" {
			return nil, fmt.Errorf("empty client name")
		}
		if _, dup := out.clients[key]; dup {
			return nil, fmt.Errorf("client %q is listed twice", key)
		}
		lim, err := apply(out.def, r, name)
		if err != nil {
			return nil, err
		}
		out.clients[key] = lim
	}
	return out, nil
}

// parseLimitsYAML reads the YAML subset of a limits file: top-level keys
// (optionally quoted), each with either an indented block of `field: <int>`
// lines or a flow mapping `{field: <int>, ...}`. Comments and a leading
// `---` are allowed. Anything else is an error, never a guess.
func parseLimitsYAML(text string) (map[string]rawLimit, error) {
	out := map[string]rawLimit{}
	var cur string
	var curSet bool
	childIndent := -1
	set := func(entry, field, value string, line int) error {
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("line %d: %s: value %q is not an integer", line, field, value)
		}
		r := out[entry]
		switch field {
		case "max_concurrent":
			r.MaxConcurrent = &n
		case "weight":
			r.Weight = &n
		default:
			return fmt.Errorf("line %d: unknown field %q", line, field)
		}
		out[entry] = r
		return nil
	}
	for i, rawLine := range strings.Split(text, "\n") {
		ln := i + 1
		line := stripYAMLComment(strings.TrimRight(rawLine, " \t\r"))
		if strings.TrimSpace(line) == "" || (i == 0 || !curSet) && strings.TrimSpace(line) == "---" {
			continue
		}
		if strings.Contains(line, "\t") {
			return nil, fmt.Errorf("line %d: tabs are not allowed in YAML indentation", ln)
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, value, err := splitYAMLKey(strings.TrimSpace(line))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln, err)
		}
		if indent == 0 {
			if _, dup := out[key]; dup {
				return nil, fmt.Errorf("line %d: %q is listed twice", ln, key)
			}
			cur, curSet, childIndent = key, true, -1
			out[key] = rawLimit{}
			switch {
			case value == "":
				// Block mapping follows.
			case strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}"):
				inner := strings.TrimSpace(value[1 : len(value)-1])
				if inner == "" {
					continue
				}
				for _, part := range strings.Split(inner, ",") {
					f, v, err := splitYAMLKey(strings.TrimSpace(part))
					if err != nil || v == "" {
						return nil, fmt.Errorf("line %d: bad flow mapping entry %q", ln, part)
					}
					if err := set(key, f, v, ln); err != nil {
						return nil, err
					}
				}
			default:
				return nil, fmt.Errorf("line %d: %q must map to max_concurrent/weight", ln, key)
			}
			continue
		}
		if !curSet {
			return nil, fmt.Errorf("line %d: indented line outside an entry", ln)
		}
		if childIndent == -1 {
			childIndent = indent
		} else if indent != childIndent {
			return nil, fmt.Errorf("line %d: inconsistent indentation", ln)
		}
		if value == "" {
			return nil, fmt.Errorf("line %d: %s needs a value", ln, key)
		}
		if err := set(cur, key, value, ln); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// stripYAMLComment drops a `#` comment that starts the line or follows a
// space, outside quotes.
func stripYAMLComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '#' && (i == 0 || line[i-1] == ' '):
			return line[:i]
		}
	}
	return line
}

// splitYAMLKey splits `key: value` (value may be empty). The key may be
// quoted; an unquoted key ends at the first ": " or a trailing ":", so a
// host:port key needs no quotes.
func splitYAMLKey(s string) (string, string, error) {
	if s == "" {
		return "", "", fmt.Errorf("empty line")
	}
	if q := s[0]; q == '"' || q == '\'' {
		end := strings.IndexByte(s[1:], q)
		if end < 0 {
			return "", "", fmt.Errorf("unterminated quote in %q", s)
		}
		key := s[1 : 1+end]
		rest := strings.TrimSpace(s[2+end:])
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("expected ':' after %q", key)
		}
		return key, strings.TrimSpace(rest[1:]), nil
	}
	if i := strings.Index(s, ": "); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:]), nil
	}
	if strings.HasSuffix(s, ":") {
		return strings.TrimSpace(s[:len(s)-1]), "", nil
	}
	return "", "", fmt.Errorf("expected 'key: value' in %q", s)
}

// loadClientLimitsFile reads and parses path.
func loadClientLimitsFile(path string) (*ClientLimits, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l, err := parseClientLimits(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

// limitsReloadInterval is how often the limits file is checked for changes.
const limitsReloadInterval = 5 * time.Second

// limitsStamp is what watchClientLimits compares to notice a change.
type limitsStamp struct {
	mod  time.Time
	size int64
	ok   bool
}

// statClientLimits returns path's current stamp.
func statClientLimits(path string) limitsStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return limitsStamp{}
	}
	return limitsStamp{mod: fi.ModTime(), size: fi.Size(), ok: true}
}

// watchClientLimits re-reads path whenever its modification time or size
// differs from last and hands a valid result to apply. The caller takes
// last before its own initial load, so an edit made between that load and
// the first check is still picked up. A file that fails to read or parse is
// logged and the previous limits stay in force. Runs until stop closes.
func watchClientLimits(path string, last limitsStamp, interval time.Duration, apply func(*ClientLimits), stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		cur := statClientLimits(path)
		if !cur.ok || (cur.mod.Equal(last.mod) && cur.size == last.size) {
			continue
		}
		last = cur
		l, err := loadClientLimitsFile(path)
		if err != nil {
			log.Printf("client limits not reloaded, keeping the previous ones: %v", err)
			continue
		}
		apply(l)
		log.Printf("client limits reloaded from %s (%d client entries)", path, len(l.clients))
	}
}
