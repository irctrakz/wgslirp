package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/irctrakz/wgslirp/internal/helperwire"
)

const shutdownTimeout = 10 * time.Second

type termination struct {
	code     string
	failed   bool
	deadline time.Time
}

type session struct {
	instance string
	ctx      context.Context
	cancel   context.CancelFunc
	timeout  time.Duration
	output   *helperwire.Output
	outputMu sync.Mutex

	mu       sync.Mutex
	pending  int // includes the executing request until its reply is sent
	stopping bool
	requests chan object
	shutdown chan termination
}

type completion struct {
	reply  *response // reserved terminal reply, sent after cleanup
	failed bool
	at     time.Time
}

func serve(input io.Reader, output *helperwire.Output, controller controller, timeout time.Duration) int {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{
		instance: hex.EncodeToString(nonce[:]), ctx: ctx, cancel: cancel,
		timeout: timeout, output: output,
		requests: make(chan object, 2), shutdown: make(chan termination, 1),
	}
	controller.session = s
	go s.read(input)
	done := make(chan completion, 1)
	go func() {
		result := controller.execute()
		result.at = time.Now()
		done <- result
	}()

	end := <-s.shutdown
	timer := time.NewTimer(time.Until(end.deadline))
	defer timer.Stop()
	var result completion
	select {
	case result = <-done:
	case <-timer.C:
		select {
		case result = <-done:
		default:
		}
	}
	if result.at.IsZero() || result.at.After(end.deadline) {
		end.code, end.failed = "shutdown_timeout", true
		result.reply = nil
	}

	// A stuck worker may still own stdout. Only attempt a terminal frame
	// when we can exclusively acquire a stream at a frame boundary.
	if end.code != "" || result.reply != nil {
		if !s.outputMu.TryLock() {
			return 1
		}
		if !output.Usable() {
			s.outputMu.Unlock()
			return 1
		}
		var frame any = result.reply
		if end.code != "" {
			frame = object{"type": "session_error", "instance_id": s.instance, "code": end.code}
		}
		ctx, cancel := context.WithTimeout(context.Background(), helperwire.WriteTimeout)
		defer cancel()
		written := make(chan error, 1)
		go func() {
			defer s.outputMu.Unlock()
			written <- s.write(ctx, frame)
		}()
		select {
		case err := <-written:
			if err != nil {
				return 1
			}
		case <-ctx.Done():
			return 1
		}
	}
	if end.failed || result.failed {
		return 1
	}
	return 0
}

func (s *session) read(input io.Reader) {
	reader := bufio.NewReader(input)
	for {
		frame, err := helperwire.ReadFrame(reader)
		s.mu.Lock()
		switch {
		case s.stopping:
			s.mu.Unlock()
			return
		case err == io.EOF:
			s.stopLocked("", false)
		case err != nil:
			s.stopLocked(err.Error(), true)
		case s.pending == cap(s.requests):
			s.stopLocked("queue_full", true)
		default:
			s.pending++
			s.requests <- frame
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()
		return
	}
}

// stop claims the shutdown transition. A terminal operation may send its
// reserved reply only if it wins admission closure over a transport failure.
func (s *session) stop(code string, failed bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked(code, failed)
}

func (s *session) stopLocked(code string, failed bool) bool {
	if s.stopping {
		return false
	}
	s.stopping = true
	end := termination{code, failed, time.Now().Add(s.timeout)}
	s.cancel()
	s.shutdown <- end
	return true
}

func (s *session) write(ctx context.Context, frame any) error {
	payload, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return s.output.WriteFrame(ctx, payload)
}

func (s *session) respond(reply response) (err error, usable bool) {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	// Output also has an I/O deadline. The watchdog starts session cleanup
	// even on a platform where closing a blocked write takes longer.
	watchdog := time.AfterFunc(helperwire.WriteTimeout, func() { s.stop("", true) })
	err = s.write(s.ctx, reply)
	watchdog.Stop()
	s.mu.Lock()
	s.pending--
	s.mu.Unlock()
	return err, s.output.Usable()
}
