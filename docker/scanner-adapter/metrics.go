package main

// Queue metrics (#5944), served in the Prometheus text exposition format on a
// separate listener (SCANNER_METRICS_ADDR, off by default). Hand-written
// rather than via client_golang: the adapter is stdlib-only (see
// docker/Dockerfile.scanner-adapter).

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// queueWaitBuckets are the upper bounds (seconds) of the queue-wait
// histogram: from an immediate start to the backend's 30-minute queue budget.
var queueWaitBuckets = []float64{0.1, 0.5, 1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800, 3600}

// Job outcomes counted by scanner_adapter_jobs_total.
const (
	outcomeSucceeded = "succeeded"
	outcomeFailed    = "failed"
)

// Metrics holds the counters and histogram; gauges are read from the
// scheduler at scrape time.
type Metrics struct {
	mu        sync.Mutex
	waitCount []uint64 // per bucket, non-cumulative; last is +Inf
	waitSum   float64
	waitTotal uint64
	outcomes  map[string]uint64
	// perClient adds the opt-in per-client series
	// (SCANNER_METRICS_CLIENT_LABEL); the client set is unbounded.
	perClient bool
}

// NewMetrics returns empty metrics.
func NewMetrics(perClient bool) *Metrics {
	return &Metrics{
		waitCount: make([]uint64, len(queueWaitBuckets)+1),
		outcomes:  map[string]uint64{outcomeSucceeded: 0, outcomeFailed: 0},
		perClient: perClient,
	}
}

// ObserveWait records one job's time from enqueue to slot grant.
func (m *Metrics) ObserveWait(d time.Duration) {
	sec := d.Seconds()
	i := sort.SearchFloat64s(queueWaitBuckets, sec)
	m.mu.Lock()
	m.waitCount[i]++
	m.waitSum += sec
	m.waitTotal++
	m.mu.Unlock()
}

// JobDone counts a finished job.
func (m *Metrics) JobDone(outcome string) {
	m.mu.Lock()
	m.outcomes[outcome]++
	m.mu.Unlock()
}

// Handler serves GET /metrics.
func (m *Metrics) Handler(s *Scheduler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m.Write(w, s.Snapshot(m.perClient))
	})
	return mux
}

// Write renders every metric for snap.
func (m *Metrics) Write(w io.Writer, snap schedSnapshot) {
	gauge := func(name, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	gauge("scanner_adapter_jobs_queued", "Scan jobs waiting for a scan slot, by priority band.")
	for b := Priority(0); b < numBands; b++ {
		fmt.Fprintf(w, "scanner_adapter_jobs_queued{priority=%q} %d\n", b.String(), snap.queued[b])
	}
	gauge("scanner_adapter_jobs_running", "Scan jobs holding a scan slot.")
	fmt.Fprintf(w, "scanner_adapter_jobs_running %d\n", snap.running)
	gauge("scanner_adapter_slots_capacity", "Scan slots (SCANNER_MAX_CONCURRENT_SCANS); 0 means unbounded.")
	fmt.Fprintf(w, "scanner_adapter_slots_capacity %d\n", snap.capacity)

	m.mu.Lock()
	counts := append([]uint64(nil), m.waitCount...)
	sum, total := m.waitSum, m.waitTotal
	outcomes := make([]string, 0, len(m.outcomes))
	for k := range m.outcomes {
		outcomes = append(outcomes, k)
	}
	sort.Strings(outcomes)
	outcomeVals := make([]uint64, len(outcomes))
	for i, k := range outcomes {
		outcomeVals[i] = m.outcomes[k]
	}
	m.mu.Unlock()

	fmt.Fprintf(w, "# HELP scanner_adapter_queue_wait_seconds Time a scan job waited for a scan slot.\n# TYPE scanner_adapter_queue_wait_seconds histogram\n")
	var cum uint64
	for i, le := range queueWaitBuckets {
		cum += counts[i]
		fmt.Fprintf(w, "scanner_adapter_queue_wait_seconds_bucket{le=%q} %d\n", strconv.FormatFloat(le, 'g', -1, 64), cum)
	}
	cum += counts[len(queueWaitBuckets)]
	fmt.Fprintf(w, "scanner_adapter_queue_wait_seconds_bucket{le=\"+Inf\"} %d\n", cum)
	fmt.Fprintf(w, "scanner_adapter_queue_wait_seconds_sum %s\n", strconv.FormatFloat(sum, 'g', -1, 64))
	fmt.Fprintf(w, "scanner_adapter_queue_wait_seconds_count %d\n", total)

	fmt.Fprintf(w, "# HELP scanner_adapter_jobs_total Finished scan jobs, by outcome.\n# TYPE scanner_adapter_jobs_total counter\n")
	for i, k := range outcomes {
		fmt.Fprintf(w, "scanner_adapter_jobs_total{outcome=%s} %d\n", promLabel(k), outcomeVals[i])
	}

	if !m.perClient {
		return
	}
	clients := snap.clients
	sort.Slice(clients, func(i, j int) bool { return clients[i].name < clients[j].name })
	gauge("scanner_adapter_client_jobs_queued", "Scan jobs waiting for a scan slot, by client and priority band (opt-in: SCANNER_METRICS_CLIENT_LABEL).")
	for _, c := range clients {
		for b := Priority(0); b < numBands; b++ {
			fmt.Fprintf(w, "scanner_adapter_client_jobs_queued{client=%s,priority=%q} %d\n", promLabel(c.name), b.String(), c.queued[b])
		}
	}
	gauge("scanner_adapter_client_jobs_running", "Scan jobs holding a scan slot, by client (opt-in: SCANNER_METRICS_CLIENT_LABEL).")
	for _, c := range clients {
		fmt.Fprintf(w, "scanner_adapter_client_jobs_running{client=%s} %d\n", promLabel(c.name), c.running)
	}
}

// promLabel quotes a label value per the text exposition format (backslash,
// double quote and newline escaped).
func promLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(v) + `"`
}
