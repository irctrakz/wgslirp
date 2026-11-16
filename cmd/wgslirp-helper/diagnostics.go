package main

import (
	"bytes"
	"io"
	"sync"
	"time"
)

const (
	diagnosticQueueSize = 32
	maxDiagnosticBytes  = 4096
	diagnosticDrainTime = 100 * time.Millisecond
)

// diagnostics keeps stderr I/O off packet workers and the control path.
// Diagnostics are best effort. A blocked sink can occupy one worker.
type diagnostics struct {
	mu     sync.Mutex
	closed bool
	queue  chan []byte
	done   chan struct{}
}

func newDiagnostics(stderr io.Writer) *diagnostics {
	d := &diagnostics{
		queue: make(chan []byte, diagnosticQueueSize),
		done:  make(chan struct{}),
	}
	go func() {
		defer close(d.done)
		for record := range d.queue {
			if _, err := stderr.Write(record); err != nil {
				return
			}
		}
	}()
	return d
}

func (d *diagnostics) Write(record []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed && len(record) <= maxDiagnosticBytes && len(d.queue) < cap(d.queue) {
		d.queue <- bytes.Clone(record)
	}
	// A dropped record must not trigger a logger's synchronous fallback.
	return len(record), nil
}

func (d *diagnostics) finish() {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()

	timer := time.NewTimer(diagnosticDrainTime)
	defer timer.Stop()
	select {
	case <-d.done:
	case <-timer.C:
	}
}
