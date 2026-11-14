package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The scheduler tests are deterministic: a fake clock and grants observed by
// checking each ticket's channel without blocking. No sleeps.

type schedClock struct{ t time.Time }

func (c *schedClock) Now() time.Time          { return c.t }
func (c *schedClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// testSched builds a fair-mode scheduler (as with a limits file) on a fake
// clock.
func testSched(capacity int, limits *ClientLimits, bgMaxWait time.Duration) (*Scheduler, *schedClock) {
	clock := &schedClock{t: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	s := NewScheduler(capacity, limits, bgMaxWait, true)
	s.now = clock.Now
	return s, clock
}

func isGranted(t *scanTicket) bool {
	select {
	case <-t.Granted():
		return true
	default:
		return false
	}
}

func mustLimits(t *testing.T, text string) *ClientLimits {
	t.Helper()
	l, err := parseClientLimits([]byte(text))
	if err != nil {
		t.Fatalf("parse limits: %v", err)
	}
	return l
}

// tracker keeps the tickets of a test and finds which one was granted next.
type tracker struct {
	t       *testing.T
	s       *Scheduler
	tickets []*scanTicket
	labels  []string
	seen    map[*scanTicket]bool
}

func newTracker(t *testing.T, s *Scheduler) *tracker {
	return &tracker{t: t, s: s, seen: map[*scanTicket]bool{}}
}

func (tr *tracker) add(client string, band Priority, label string) *scanTicket {
	tk := tr.s.Enqueue(client, band)
	tr.tickets = append(tr.tickets, tk)
	tr.labels = append(tr.labels, label)
	return tk
}

// newlyGranted returns the labels of tickets granted since the last call, in
// enqueue order.
func (tr *tracker) newlyGranted() []string {
	var out []string
	for i, tk := range tr.tickets {
		if !tr.seen[tk] && isGranted(tk) {
			tr.seen[tk] = true
			out = append(out, tr.labels[i])
		}
	}
	return out
}

// runOrder releases running tickets one at a time (oldest grant first) and
// returns the order in which jobs were granted, for a capacity-1 scheduler.
func (tr *tracker) runOrder() []string {
	var order []string
	var running []*scanTicket
	collect := func() {
		for i, tk := range tr.tickets {
			if !tr.seen[tk] && isGranted(tk) {
				tr.seen[tk] = true
				order = append(order, tr.labels[i])
				running = append(running, tk)
			}
		}
	}
	collect()
	for len(running) > 0 {
		tk := running[0]
		running = running[1:]
		tk.Release()
		collect()
	}
	if len(order) != len(tr.tickets) {
		tr.t.Fatalf("only %d of %d jobs ran: %v", len(order), len(tr.tickets), order)
	}
	return order
}

// TestFairShareSmallClientNotStuckBehindBacklog: client A queues 50 jobs,
// then client B queues 2. B's jobs start within B's fair share (alternating
// with A), not after A's backlog.
func TestFairShareSmallClientNotStuckBehindBacklog(t *testing.T) {
	s, _ := testSched(1, nil, 30*time.Minute)
	tr := newTracker(t, s)
	for i := 0; i < 50; i++ {
		tr.add("a.example", PriorityInteractive, fmt.Sprintf("A%d", i))
	}
	tr.add("b.example", PriorityInteractive, "B0")
	tr.add("b.example", PriorityInteractive, "B1")
	order := tr.runOrder()
	pos := map[string]int{}
	for i, l := range order {
		pos[l] = i
	}
	// Equal weights: A0 was already running, then B and A alternate.
	if pos["B0"] > 2 || pos["B1"] > 4 {
		t.Fatalf("B started at %d and %d, want within its fair share (<= 2, <= 4): %v", pos["B0"], pos["B1"], order[:8])
	}
	// FIFO within a client.
	for i := 1; i < 50; i++ {
		if pos[fmt.Sprintf("A%d", i)] < pos[fmt.Sprintf("A%d", i-1)] {
			t.Fatalf("A jobs out of FIFO order: %v", order)
		}
	}
	if pos["B1"] < pos["B0"] {
		t.Fatalf("B jobs out of FIFO order: %v", order)
	}
}

// TestFairShareFollowsWeights: with weights 3 and 1 and both clients
// backlogged, A gets three slots for every one of B's.
func TestFairShareFollowsWeights(t *testing.T) {
	l := mustLimits(t, "a.example:\n  weight: 3\n")
	s, _ := testSched(1, l, 30*time.Minute)
	tr := newTracker(t, s)
	// One job of C holds the only slot while A and B queue up, so both are
	// backlogged when the round robin starts.
	tr.add("c.example", PriorityInteractive, "C")
	for i := 0; i < 12; i++ {
		tr.add("a.example", PriorityInteractive, "A")
		tr.add("b.example", PriorityInteractive, "B")
	}
	order := tr.runOrder()[1:] // drop C
	a, b := 0, 0
	for _, l := range order[:16] {
		if l == "A" {
			a++
		} else {
			b++
		}
	}
	if a != 12 || b != 4 {
		t.Fatalf("first 16 grants: A=%d B=%d, want 12/4: %v", a, b, order[:16])
	}
}

// TestClientMaxConcurrentHoldsWithFreeGlobalSlots: max_concurrent 1 holds
// even when global slots are free, and other clients use the free slots.
func TestClientMaxConcurrentHoldsWithFreeGlobalSlots(t *testing.T) {
	l := mustLimits(t, `{"a.example": {"max_concurrent": 1}}`)
	s, _ := testSched(4, l, 30*time.Minute)
	tr := newTracker(t, s)
	a0 := tr.add("a.example", PriorityInteractive, "A0")
	tr.add("a.example", PriorityInteractive, "A1")
	tr.add("a.example", PriorityInteractive, "A2")
	if got := tr.newlyGranted(); len(got) != 1 || got[0] != "A0" {
		t.Fatalf("with 4 free slots only A0 may run, granted %v", got)
	}
	tr.add("b.example", PriorityInteractive, "B0")
	tr.add("b.example", PriorityInteractive, "B1")
	if got := tr.newlyGranted(); len(got) != 2 {
		t.Fatalf("B must use the free slots, granted %v", got)
	}
	if snap := s.Snapshot(false); snap.running != 3 || snap.queued[PriorityInteractive] != 2 {
		t.Fatalf("running=%d queued=%d, want 3 and 2", snap.running, snap.queued[PriorityInteractive])
	}
	a0.Release()
	if got := tr.newlyGranted(); len(got) != 1 || got[0] != "A1" {
		t.Fatalf("releasing A0 must start A1 only, granted %v", got)
	}
}

// TestDefaultEntryAppliesToUnlistedClients: the default entry caps a client
// that is not listed; a listed client's absent field inherits it.
func TestDefaultEntryAppliesToUnlistedClients(t *testing.T) {
	l := mustLimits(t, "default:\n  max_concurrent: 1\n  weight: 2\nbig.example: {weight: 5}\n")
	if got := l.For("other.example"); got.MaxConcurrent != 1 || got.Weight != 2 {
		t.Fatalf("default = %+v", got)
	}
	if got := l.For("big.example"); got.MaxConcurrent != 1 || got.Weight != 5 {
		t.Fatalf("listed client = %+v, want inherited max_concurrent 1, weight 5", got)
	}
	s, _ := testSched(4, l, 30*time.Minute)
	tr := newTracker(t, s)
	tr.add("other.example", PriorityInteractive, "O0")
	tr.add("other.example", PriorityInteractive, "O1")
	if got := tr.newlyGranted(); len(got) != 1 {
		t.Fatalf("default max_concurrent 1 must hold, granted %v", got)
	}
}

// TestBackgroundWaitsForInteractive: a background job never starts while an
// interactive one is waiting, in any client.
func TestBackgroundWaitsForInteractive(t *testing.T) {
	s, _ := testSched(1, nil, 30*time.Minute)
	tr := newTracker(t, s)
	tr.add("a.example", PriorityInteractive, "I0")
	tr.add("b.example", PriorityBackground, "BG")
	tr.add("c.example", PriorityInteractive, "I1")
	tr.add("a.example", PriorityInteractive, "I2")
	if got := tr.runOrder(); fmt.Sprint(got) != "[I0 I1 I2 BG]" {
		t.Fatalf("order %v, want every interactive job before the background one", got)
	}
}

// TestBackgroundRunsWhenIdle: with no interactive work queued a background
// job starts at once.
func TestBackgroundRunsWhenIdle(t *testing.T) {
	s, _ := testSched(1, nil, 30*time.Minute)
	if tk := s.Enqueue("a.example", PriorityBackground); !isGranted(tk) {
		t.Fatal("a background job on an idle adapter must start at once")
	}
}

// TestBackgroundRunsWhenOnlyCappedInteractiveWaits: an interactive job held
// back by its own client's cap does not keep another client's background
// job off a free slot. Capacity 4, client a capped at 1 with a second job
// queued, a background job from b: b's job starts at once, with the
// starvation bound off and with the default bound.
func TestBackgroundRunsWhenOnlyCappedInteractiveWaits(t *testing.T) {
	for _, bound := range []time.Duration{0, 30 * time.Minute} {
		l := mustLimits(t, "a.example:\n  max_concurrent: 1\n")
		s, _ := testSched(4, l, bound)
		tr := newTracker(t, s)
		a0 := tr.add("a.example", PriorityInteractive, "A0")
		tr.add("a.example", PriorityInteractive, "A1") // capped
		tr.add("b.example", PriorityBackground, "BG")
		if got := fmt.Sprint(tr.newlyGranted()); got != "[A0 BG]" {
			t.Fatalf("bound %s: granted %s, want [A0 BG]", bound, got)
		}
		a0.Release()
		if got := fmt.Sprint(tr.newlyGranted()); got != "[A1]" {
			t.Fatalf("bound %s: after A0 granted %s, want [A1]", bound, got)
		}
	}
}

// TestEligibleInteractiveStillHoldsBackground: an interactive job that can
// run (its client is under its cap) still goes before background work.
func TestEligibleInteractiveStillHoldsBackground(t *testing.T) {
	s, _ := testSched(2, nil, 30*time.Minute)
	tr := newTracker(t, s)
	tr.add("a.example", PriorityInteractive, "A0")
	a1 := tr.add("a.example", PriorityInteractive, "A1")
	tr.add("b.example", PriorityBackground, "BG")
	tr.add("a.example", PriorityInteractive, "A2")
	if got := fmt.Sprint(tr.newlyGranted()); got != "[A0 A1]" {
		t.Fatalf("granted %s", got)
	}
	a1.Release() // the eligible interactive A2 takes it, not BG
	if got := fmt.Sprint(tr.newlyGranted()); got != "[A2]" {
		t.Fatalf("granted %s, want [A2]", got)
	}
}

// TestStarvedBackgroundGoesAheadOfInteractive: once a background job has
// waited SCANNER_BACKGROUND_MAX_WAIT it takes the next free slot even with
// interactive jobs waiting, but starved jobs then alternate with interactive
// ones rather than all going first.
func TestStarvedBackgroundGoesAheadOfInteractive(t *testing.T) {
	s, clock := testSched(1, nil, 30*time.Minute)
	tr := newTracker(t, s)
	i0 := tr.add("a.example", PriorityInteractive, "I0")
	bg0 := tr.add("b.example", PriorityBackground, "BG0")
	bg1 := tr.add("b.example", PriorityBackground, "BG1")
	i1 := tr.add("a.example", PriorityInteractive, "I1")
	tr.newlyGranted()

	clock.Advance(30 * time.Minute)
	i2 := tr.add("c.example", PriorityInteractive, "I2") // fresh interactive work
	var order []string
	for _, tk := range []*scanTicket{i0, bg0, i1, bg1, i2} {
		tk.Release()
		order = append(order, tr.newlyGranted()...)
	}
	if fmt.Sprint(order) != "[BG0 I1 BG1 I2]" {
		t.Fatalf("grants after I0 = %v, want starved and interactive alternating [BG0 I1 BG1 I2]", order)
	}
}

// TestStarvedBacklogDoesNotRunAheadOfInteractive is the review probe: one
// slot, 20 background jobs past the bound (a rescan wave), then one
// interactive scan. The interactive scan starts after at most one starved
// job, not after all 20 (the backend stops waiting for a queued scan after
// 30 minutes).
func TestStarvedBacklogDoesNotRunAheadOfInteractive(t *testing.T) {
	s, clock := testSched(1, nil, 30*time.Minute)
	tr := newTracker(t, s)
	running := tr.add("a.example", PriorityInteractive, "I0")
	for i := 0; i < 20; i++ {
		tr.add("rescan.example", PriorityBackground, fmt.Sprintf("BG%d", i))
	}
	tr.newlyGranted()
	clock.Advance(31 * time.Minute)
	tr.add("user.example", PriorityInteractive, "USER")
	order := []string{"I0"}
	byLabel := map[string]*scanTicket{"I0": running}
	for i, tk := range tr.tickets {
		byLabel[tr.labels[i]] = tk
	}
	for len(order) < 22 {
		byLabel[order[len(order)-1]].Release()
		got := tr.newlyGranted()
		if len(got) != 1 {
			t.Fatalf("after %v granted %v", order, got)
		}
		order = append(order, got[0])
	}
	pos := -1
	for i, l := range order {
		if l == "USER" {
			pos = i
		}
	}
	if pos < 0 || pos > 2 {
		t.Fatalf("USER started at position %d: %v", pos, order)
	}
}

// TestOneStarvedJobAtATime: with several free slots, starved background work
// takes at most one at a time while interactive work waits.
func TestOneStarvedJobAtATime(t *testing.T) {
	s, clock := testSched(3, nil, 30*time.Minute)
	tr := newTracker(t, s)
	h := []*scanTicket{
		tr.add("h.example", PriorityInteractive, "H0"),
		tr.add("h.example", PriorityInteractive, "H1"),
		tr.add("h.example", PriorityInteractive, "H2"),
	}
	for i := 0; i < 3; i++ {
		tr.add("rescan.example", PriorityBackground, fmt.Sprintf("BG%d", i))
	}
	for i := 0; i < 3; i++ {
		tr.add("a.example", PriorityInteractive, fmt.Sprintf("A%d", i))
	}
	tr.newlyGranted()
	clock.Advance(31 * time.Minute)
	var got []string
	for _, tk := range h {
		tk.Release()
		got = append(got, tr.newlyGranted()...)
	}
	bg := 0
	for _, l := range got {
		if strings.HasPrefix(l, "BG") {
			bg++
		}
	}
	if len(got) != 3 || bg != 1 {
		t.Fatalf("three freed slots went to %v, want exactly one starved background job", got)
	}
}

// TestPickStarvedTakesTheOldest: among starved background jobs the oldest
// goes first, whatever the clients' order in the round robin. Client X is
// first in the ring but, after its first job ran, its head is younger than
// client Y's.
func TestPickStarvedTakesTheOldest(t *testing.T) {
	s, clock := testSched(1, nil, 30*time.Minute)
	tr := newTracker(t, s)
	h := tr.add("h.example", PriorityInteractive, "H")
	x1 := tr.add("x.example", PriorityBackground, "X1") // t0
	clock.Advance(time.Minute)
	tr.add("y.example", PriorityBackground, "Y1") // t0+1m
	clock.Advance(time.Minute)
	tr.add("x.example", PriorityBackground, "X2") // t0+2m
	tr.newlyGranted()
	clock.Advance(31 * time.Minute)

	h.Release()
	if got := fmt.Sprint(tr.newlyGranted()); got != "[X1]" {
		t.Fatalf("granted %s, want the oldest X1", got)
	}
	i := tr.add("i.example", PriorityInteractive, "I")
	x1.Release() // right after a starved grant: interactive goes next
	if got := fmt.Sprint(tr.newlyGranted()); got != "[I]" {
		t.Fatalf("granted %s, want I", got)
	}
	tr.add("i.example", PriorityInteractive, "I2") // keeps the round robin out of it
	i.Release()
	if got := fmt.Sprint(tr.newlyGranted()); got != "[Y1]" {
		t.Fatalf("granted %s, want Y1 (older than X2, though X is first in the ring)", got)
	}
}

// TestDequeueAdjustsCursorWhenAnEarlierClientLeaves: a client leaving the
// ring ahead of the cursor (here through pickStarved) keeps the cursor on the
// same client.
func TestDequeueAdjustsCursorWhenAnEarlierClientLeaves(t *testing.T) {
	s, _ := testSched(1, nil, 30*time.Minute)
	tr := newTracker(t, s)
	tr.add("h.example", PriorityInteractive, "H")
	tr.add("a.example", PriorityBackground, "A")
	tr.add("b.example", PriorityBackground, "B")
	tr.add("c.example", PriorityBackground, "C")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursor[PriorityBackground] = 2 // C's turn
	a := s.ring[PriorityBackground][0]
	s.dequeue(a, PriorityBackground, 0)
	if c := s.ring[PriorityBackground][s.cursor[PriorityBackground]]; c.name != "c.example" {
		t.Fatalf("cursor moved to %s, want it to stay on c.example", c.name)
	}
}

// TestBoundZeroNeverStarvesInteractive: SCANNER_BACKGROUND_MAX_WAIT=0
// disables the bound.
func TestBoundZeroNeverStarvesInteractive(t *testing.T) {
	s, clock := testSched(1, nil, 0)
	tr := newTracker(t, s)
	i0 := tr.add("a.example", PriorityInteractive, "I0")
	tr.add("b.example", PriorityBackground, "BG")
	tr.add("a.example", PriorityInteractive, "I1")
	tr.newlyGranted()
	clock.Advance(24 * time.Hour)
	i0.Release()
	if got := tr.newlyGranted(); fmt.Sprint(got) != "[I1]" {
		t.Fatalf("granted %v, want I1", got)
	}
}

// TestUnboundedCapacityStillAppliesClientCaps: SCANNER_MAX_CONCURRENT_SCANS=0
// removes the global bound only.
func TestUnboundedCapacityStillAppliesClientCaps(t *testing.T) {
	l := mustLimits(t, "a.example:\n  max_concurrent: 2\n")
	s, _ := testSched(0, l, 30*time.Minute)
	tr := newTracker(t, s)
	for i := 0; i < 5; i++ {
		tr.add("a.example", PriorityInteractive, "A")
		tr.add("b.example", PriorityInteractive, "B")
	}
	got := tr.newlyGranted()
	a := 0
	for _, l := range got {
		if l == "A" {
			a++
		}
	}
	if len(got) != 7 || a != 2 {
		t.Fatalf("granted %v, want all 5 B and 2 A", got)
	}
}

// TestSetLimitsRaisingCapStartsWaitingJobs: a reloaded limits file applies at
// once.
func TestSetLimitsRaisingCapStartsWaitingJobs(t *testing.T) {
	s, _ := testSched(4, mustLimits(t, "a.example: {max_concurrent: 1}\n"), 30*time.Minute)
	tr := newTracker(t, s)
	tr.add("a.example", PriorityInteractive, "A0")
	tr.add("a.example", PriorityInteractive, "A1")
	tr.add("a.example", PriorityInteractive, "A2")
	if got := tr.newlyGranted(); len(got) != 1 {
		t.Fatalf("granted %v", got)
	}
	s.SetLimits(mustLimits(t, "a.example: {max_concurrent: 3}\n"))
	if got := tr.newlyGranted(); fmt.Sprint(got) != "[A1 A2]" {
		t.Fatalf("after raising the cap granted %v", got)
	}
}

// TestSchedulerForgetsIdleClientsAndDrainsToZero: after every job is
// released no client state or count is left behind.
func TestSchedulerForgetsIdleClientsAndDrainsToZero(t *testing.T) {
	s, _ := testSched(2, nil, 30*time.Minute)
	tr := newTracker(t, s)
	for i := 0; i < 20; i++ {
		tr.add(fmt.Sprintf("c%d.example", i%5), Priority(i%2), "x")
	}
	tr.runOrder()
	snap := s.Snapshot(true)
	if snap.running != 0 || snap.queued != [numBands]int{} || len(snap.clients) != 0 || len(s.clients) != 0 {
		t.Fatalf("not drained: %+v, clients=%d", snap, len(s.clients))
	}
	for b := Priority(0); b < numBands; b++ {
		if len(s.ring[b]) != 0 {
			t.Fatalf("ring %s not empty", b)
		}
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	s, _ := testSched(1, nil, 0)
	tk := s.Enqueue("a.example", PriorityInteractive)
	tk.Release()
	tk.Release()
	if snap := s.Snapshot(false); snap.running != 0 {
		t.Fatalf("running = %d after a double release", snap.running)
	}
}

func TestParsePriority(t *testing.T) {
	for in, want := range map[string]Priority{"": PriorityInteractive, "interactive": PriorityInteractive, " Background ": PriorityBackground} {
		if got, err := parsePriority(in); err != nil || got != want {
			t.Errorf("parsePriority(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := parsePriority("urgent"); err == nil {
		t.Error("an unknown priority must be refused")
	}
}

func TestClientKeys(t *testing.T) {
	for _, u := range []string{"http://AK.example:8080/", "https://ak.example:8080", "ak.example:8080"} {
		if got := clientKey(u); got != "ak.example:8080" {
			t.Errorf("clientKey(%q) = %q", u, got)
		}
	}
	for _, u := range []string{"http://user:s3cret@ak.example:8080/", "https://tok@AK.example:8080"} {
		if got := clientKey(u); got != "ak.example:8080" {
			t.Errorf("clientKey(%q) = %q, want the userinfo dropped", u, got)
		}
	}
	if got := fsClientKey("http://ak.example:8080/", "10.0.0.9:5555"); got != "ak.example:8080" {
		t.Errorf("fs client from header = %q", got)
	}
	if got := fsClientKey("", "10.0.0.9:5555"); got != "10.0.0.9" {
		t.Errorf("fs client from remote address = %q", got)
	}
	if got := fsClientKey("", "[fd00::1]:5555"); got != "fd00::1" {
		t.Errorf("fs client from IPv6 remote address = %q", got)
	}
}
