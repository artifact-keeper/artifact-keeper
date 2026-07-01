package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// JobStatus is the lifecycle state of a scan job.
type JobStatus string

const (
	// StatusPending: accepted, not yet started.
	StatusPending JobStatus = "Pending"
	// StatusRunning: trivy is executing.
	StatusRunning JobStatus = "Running"
	// StatusSucceeded: a report is available.
	StatusSucceeded JobStatus = "Succeeded"
	// StatusFailed: the scan errored; the report endpoint must 500 (fail-closed).
	StatusFailed JobStatus = "Failed"
)

// Job is a single scan request's state.
type Job struct {
	ID      string
	Status  JobStatus
	Report  *HarborScanReport
	Err     string
	Created time.Time
}

// JobStore is a concurrency-safe in-memory job map with TTL eviction.
type JobStore struct {
	mu   sync.RWMutex
	jobs map[string]*Job
	ttl  time.Duration
}

// NewJobStore creates a store whose finished jobs live for ttl.
func NewJobStore(ttl time.Duration) *JobStore {
	return &JobStore{
		jobs: make(map[string]*Job),
		ttl:  ttl,
	}
}

// newID returns an opaque hex id from crypto/rand.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Create registers a new Pending job and returns it.
func (s *JobStore) Create() (*Job, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	job := &Job{ID: id, Status: StatusPending, Created: time.Now()}
	s.mu.Lock()
	s.jobs[id] = job
	s.mu.Unlock()
	return job, nil
}

// Get returns the job for id and whether it exists.
func (s *JobStore) Get(id string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	return job, ok
}

// setStatus transitions a job's status (no-op if the id is gone).
func (s *JobStore) setStatus(id string, status JobStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.Status = status
	}
}

// Running marks a job as executing.
func (s *JobStore) Running(id string) { s.setStatus(id, StatusRunning) }

// Succeed attaches a report and marks the job Succeeded.
func (s *JobStore) Succeed(id string, report *HarborScanReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.Report = report
		job.Status = StatusSucceeded
	}
}

// Fail records an error and marks the job Failed (fail-closed; never Succeeded
// with an empty report on error).
func (s *JobStore) Fail(id, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.Err = errMsg
		job.Status = StatusFailed
	}
}

// sweep evicts finished jobs older than the TTL. Returns the number evicted.
func (s *JobStore) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, job := range s.jobs {
		terminal := job.Status == StatusSucceeded || job.Status == StatusFailed
		if terminal && now.Sub(job.Created) > s.ttl {
			delete(s.jobs, id)
			n++
		}
	}
	return n
}

// RunSweeper periodically evicts expired jobs until ctx-like stop channel closes.
func (s *JobStore) RunSweeper(stop <-chan struct{}) {
	interval := s.ttl / 2
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			s.sweep(now)
		}
	}
}
