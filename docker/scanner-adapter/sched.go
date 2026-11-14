package main

// Scan scheduling (#5944): which queued scan gets the next free trivy slot.
//
// The adapter bounds concurrent trivy runs with SCANNER_MAX_CONCURRENT_SCANS
// (#5657). Several clients (Artifact Keeper instances or registries) can share
// one adapter, so the order in which waiting scans get a slot is no longer
// global arrival order:
//
//   - Per-client limits: a client (see clientKey) at its max_concurrent waits
//     even when global slots are free.
//   - Weighted fair queueing: when a slot frees, the next job is chosen by
//     deficit round robin across the clients with queued jobs, each client
//     getting `weight` jobs per round. Within a client, jobs stay FIFO.
//   - Priority bands: a background job starts only when no interactive job
//     can take the slot (none is waiting, or every waiting one is held by
//     its own client's cap), or once it has waited BackgroundMaxWait (the
//     starvation bound), after which starved jobs alternate with
//     interactive work, one starved job at a time.
//
// All of this is opt-in: without SCANNER_CLIENT_LIMITS_FILE every job is
// queued under one client (arrival order, as before), and the background band
// applies only to requests that ask for it.
//
// Everything is decided under one mutex; a waiting job blocks on its own
// channel, which the scheduler closes when it grants the slot.

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Priority is a scan's band.
type Priority int

const (
	// PriorityInteractive is the default band: scans someone is waiting on.
	PriorityInteractive Priority = iota
	// PriorityBackground is for work that can yield, such as periodic or
	// post-DB-update rescans.
	PriorityBackground
	numBands
)

// String returns the wire name of the band, as used in requests and metrics.
func (p Priority) String() string {
	if p == PriorityBackground {
		return "background"
	}
	return "interactive"
}

// parsePriority reads the optional `priority` of a scan request: empty or
// "interactive" is interactive, "background" is background, anything else is
// an error (the request is refused rather than silently run at another band).
func parsePriority(s string) (Priority, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "interactive":
		return PriorityInteractive, nil
	case "background":
		return PriorityBackground, nil
	default:
		return 0, fmt.Errorf("priority must be %q or %q", "interactive", "background")
	}
}

// clientKey identifies the client of an image scan by its registry host:
// trimRegistryHost (scheme and trailing slash dropped, port kept), lowercased.
// It is also how the limits file's keys are normalized.
//
// Any userinfo (user:password@) is dropped, so a credential in the URL never
// reaches a log line or a metrics label.
//
// It is the registry-partition host key (trimRegistryHost, then
// partitionHostKey, #5943), so a client and its cache partition are named by
// the same normalized host.
func clientKey(registryURL string) string {
	host := trimRegistryHost(registryURL)
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	return partitionHostKey(host)
}

// fsClientKey identifies the client of a filesystem scan, whose upload names
// no registry: the X-Scan-Client header when present (normalized like a
// registry URL, so a backend can send the same registry URL it uses for image
// scans), otherwise the remote IP address.
func fsClientKey(header, remoteAddr string) string {
	if k := clientKey(header); k != "" {
		return k
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(remoteAddr)
}

// scanTicket is one job's claim on a scan slot.
type scanTicket struct {
	sched    *Scheduler
	client   string
	band     Priority
	enqueued time.Time
	// granted is closed when the job may run.
	granted chan struct{}
	once    sync.Once
	// starved is set when the job was started past the starvation bound.
	starved bool
}

// Granted is closed once the job holds a slot.
func (t *scanTicket) Granted() <-chan struct{} { return t.granted }

// Release frees the slot. Safe to call more than once.
func (t *scanTicket) Release() { t.once.Do(func() { t.sched.release(t) }) }

// clientState is the scheduler's view of one client. It exists while the
// client has a job queued or running and is dropped when it has neither, so
// the map stays bounded by the active clients.
type clientState struct {
	name    string
	running int
	queues  [numBands][]*scanTicket
	// deficit and inTurn are the deficit-round-robin state per band.
	deficit [numBands]int
	inTurn  [numBands]bool
	inRing  [numBands]bool
}

// Scheduler grants scan slots. The zero value is not usable; see NewScheduler.
type Scheduler struct {
	mu sync.Mutex
	// capacity is the global slot count; 0 means unbounded.
	capacity int
	running  int
	queued   [numBands]int
	limits   *ClientLimits
	clients  map[string]*clientState
	// ring holds, per band, the clients with jobs queued in that band, in
	// round-robin order; cursor is the client whose turn it is.
	ring   [numBands][]*clientState
	cursor [numBands]int
	// bgMaxWait is the starvation bound; 0 disables it.
	bgMaxWait time.Duration

	now func() time.Time
	// starvedRunning counts running jobs that were started as starved
	// background work; lastStarved is set when the latest grant was one.
	// Together they keep starved background work to one slot at a time,
	// alternating with interactive work (see pickStarved).
	starvedRunning int
	lastStarved    bool

	// fair turns per-client scheduling on: limits, weighted round robin and
	// per-client state. It is set when a limits file is configured. Off (the
	// default), every job is queued under one client, so slots go out in
	// arrival order within each band, as before #5944.
	fair bool

	// onGrant observes each job's queue wait (metrics); may be nil.
	onGrant func(wait time.Duration)
}

// NewScheduler returns a scheduler with capacity global slots (0: unbounded),
// the given per-client limits (nil: no per-client cap, weight 1), the
// starvation bound for background jobs (0: none), and fair set when
// per-client scheduling is configured (see the fair field).
func NewScheduler(capacity int, limits *ClientLimits, bgMaxWait time.Duration, fair bool) *Scheduler {
	if limits == nil {
		limits = defaultClientLimits()
	}
	return &Scheduler{
		capacity:  capacity,
		limits:    limits,
		clients:   make(map[string]*clientState),
		bgMaxWait: bgMaxWait,
		fair:      fair,
		now:       time.Now,
	}
}

// Enqueue queues a job for client in band and grants it a slot at once when
// the rules allow. The caller waits on Granted and must call Release when the
// scan is done.
func (s *Scheduler) Enqueue(client string, band Priority) *scanTicket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.fair {
		client = ""
	}
	t := &scanTicket{sched: s, client: client, band: band, enqueued: s.now(), granted: make(chan struct{})}
	c := s.clients[client]
	if c == nil {
		c = &clientState{name: client}
		s.clients[client] = c
	}
	c.queues[band] = append(c.queues[band], t)
	if !c.inRing[band] {
		c.inRing[band] = true
		s.ring[band] = append(s.ring[band], c)
	}
	s.queued[band]++
	s.dispatch()
	return t
}

// SetLimits replaces the per-client limits (a reloaded limits file) and
// starts whatever the new limits allow.
func (s *Scheduler) SetLimits(l *ClientLimits) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits = l
	s.dispatch()
}

func (s *Scheduler) release(t *scanTicket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running--
	if t.starved {
		s.starvedRunning--
	}
	if c := s.clients[t.client]; c != nil {
		c.running--
		s.forgetIfIdle(c)
	}
	s.dispatch()
}

// forgetIfIdle drops a client with nothing queued or running.
func (s *Scheduler) forgetIfIdle(c *clientState) {
	if c.running == 0 && len(c.queues[PriorityInteractive]) == 0 && len(c.queues[PriorityBackground]) == 0 {
		delete(s.clients, c.name)
	}
}

func (s *Scheduler) hasFreeSlot() bool { return s.capacity == 0 || s.running < s.capacity }

func (s *Scheduler) underCap(c *clientState) bool {
	max := s.limits.For(c.name).MaxConcurrent
	return max == 0 || c.running < max
}

// dispatch grants slots while one is free and a job may take it. Called with
// s.mu held, on every enqueue, release and limits change.
//
// No timer is needed for the starvation bound: when a slot is free and a
// background job still waits, nothing can take that slot (no interactive job
// is eligible and the background job's own client is at its cap), and the
// passing of time changes neither. A starved job is therefore always picked
// at the next dispatch that has a slot for it, i.e. on the next release.
func (s *Scheduler) dispatch() {
	for s.hasFreeSlot() {
		t := s.pick()
		if t == nil {
			break
		}
		s.grant(t)
	}
}

// pick chooses (and dequeues) the next job, or returns nil when none may
// start. Order: a background job past the starvation bound, then interactive
// jobs by weighted round robin, then background jobs by weighted round robin.
// Background work is held back only while some interactive job could take
// the slot (its client is under its cap): an interactive job held back by
// its own client's cap does not keep other clients' background work off
// free slots.
func (s *Scheduler) pick() *scanTicket {
	if t := s.pickStarved(); t != nil {
		t.starved = true
		s.starvedRunning++
		s.lastStarved = true
		return t
	}
	s.lastStarved = false
	if s.queued[PriorityInteractive] > 0 {
		if t := s.pickDRR(PriorityInteractive); t != nil {
			return t
		}
	}
	return s.pickDRR(PriorityBackground)
}

// pickStarved returns the longest-waiting background job (head of its
// client's FIFO) that has reached the starvation bound and whose client is
// under its cap.
//
// Starved work never takes strict precedence: at most one starved job runs
// at a time, and right after a starved grant the next one goes to regular
// order (interactive first). A backlog of starved background jobs, such as
// a rescan wave, therefore alternates with interactive scans instead of
// running ahead of all of them.
func (s *Scheduler) pickStarved() *scanTicket {
	if s.bgMaxWait <= 0 || s.queued[PriorityBackground] == 0 || s.starvedRunning > 0 || s.lastStarved {
		return nil
	}
	now := s.now()
	var best *clientState
	for _, c := range s.ring[PriorityBackground] {
		head := c.queues[PriorityBackground][0]
		if now.Sub(head.enqueued) < s.bgMaxWait || !s.underCap(c) {
			continue
		}
		if best == nil || head.enqueued.Before(best.queues[PriorityBackground][0].enqueued) {
			best = c
		}
	}
	if best == nil {
		return nil
	}
	return s.dequeue(best, PriorityBackground, s.ringIndex(PriorityBackground, best))
}

// pickDRR is deficit round robin over the clients queued in band: each job
// takes one unit of deficit and a client's quantum is its weight. A client
// whose turn comes while it is at its cap is skipped for that turn.
func (s *Scheduler) pickDRR(band Priority) *scanTicket {
	ring := s.ring[band]
	eligible := false
	for _, c := range ring {
		if s.underCap(c) {
			eligible = true
			break
		}
	}
	if !eligible {
		return nil
	}
	for {
		if s.cursor[band] >= len(s.ring[band]) {
			s.cursor[band] = 0
		}
		i := s.cursor[band]
		c := s.ring[band][i]
		if !s.underCap(c) {
			c.inTurn[band] = false
			s.cursor[band]++
			continue
		}
		if !c.inTurn[band] {
			w := s.limits.For(c.name).Weight
			c.deficit[band] = min(c.deficit[band]+w, w)
			c.inTurn[band] = true
		}
		// Weight >= 1, so a client in its turn always has a job's worth.
		c.deficit[band]--
		t := s.dequeue(c, band, i)
		if c.inRing[band] && c.deficit[band] < 1 {
			// Turn over: the next client goes next.
			c.inTurn[band] = false
			s.cursor[band]++
		}
		return t
	}
}

// dequeue pops the head of c's FIFO in band; c sits at ring index i. A client
// whose queue empties leaves the ring (its place goes to the next client) and
// loses its deficit, as in DRR.
func (s *Scheduler) dequeue(c *clientState, band Priority, i int) *scanTicket {
	t := c.queues[band][0]
	c.queues[band][0] = nil
	c.queues[band] = c.queues[band][1:]
	s.queued[band]--
	if len(c.queues[band]) == 0 {
		c.queues[band] = nil
		c.inRing[band] = false
		c.inTurn[band] = false
		c.deficit[band] = 0
		s.ring[band] = append(s.ring[band][:i], s.ring[band][i+1:]...)
		if s.cursor[band] > i {
			s.cursor[band]--
		}
	}
	return t
}

func (s *Scheduler) ringIndex(band Priority, c *clientState) int {
	for i, r := range s.ring[band] {
		if r == c {
			return i
		}
	}
	panic("scheduler: client not in ring")
}

// grant hands t its slot.
func (s *Scheduler) grant(t *scanTicket) {
	s.running++
	s.clients[t.client].running++
	if s.onGrant != nil {
		s.onGrant(s.now().Sub(t.enqueued))
	}
	close(t.granted)
}

// schedSnapshot is a point-in-time view for the metrics endpoint.
type schedSnapshot struct {
	capacity int
	running  int
	queued   [numBands]int
	clients  []clientSnapshot
}

type clientSnapshot struct {
	name    string
	running int
	queued  [numBands]int
}

// Snapshot returns the current counts; with perClient it also lists every
// active client.
func (s *Scheduler) Snapshot(perClient bool) schedSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := schedSnapshot{capacity: s.capacity, running: s.running, queued: s.queued}
	if perClient {
		for _, c := range s.clients {
			snap.clients = append(snap.clients, clientSnapshot{
				name:    c.name,
				running: c.running,
				queued:  [numBands]int{len(c.queues[PriorityInteractive]), len(c.queues[PriorityBackground])},
			})
		}
	}
	return snap
}
