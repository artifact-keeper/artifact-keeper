//go:build !unix

package main

import (
	"context"
	"time"
)

// lockFile is a no-op where flock is unavailable; the adapter ships for Linux
// only, and the in-process single flight still serializes its own downloads.
func lockFile(context.Context, string, time.Duration) (func(), error) { return func() {}, nil }
