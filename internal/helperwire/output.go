// Package helperwire contains the helper's bounded protocol I/O primitives.
package helperwire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"
)

const MaxFrameBytes = 65_536
const writeTimeout = 5 * time.Second

var ErrOutputClosed = errors.New("helper protocol output closed")

// Output is owned by the serial control loop. WriteFrame must never be called
// by a packet worker. There is no output queue.
type Output struct {
	writer io.WriteCloser
	failed bool
}

// NewOutput takes ownership of the protocol stream. The writer must support
// closing concurrently with a write, as an os.File or io.PipeWriter does.
func NewOutput(writer io.WriteCloser) *Output { return &Output{writer: writer} }

// WriteFrame writes a single pre-encoded JSON object followed by LF. A failed,
// partial or timed-out write permanently retires the output. The controller
// must shut down the runtime and exit on such a failure. A cancellation
// requests closure concurrently so a platform-specific pipe close cannot
// block the controller. Only the interrupted frame can remain outstanding.
func (o *Output) WriteFrame(ctx context.Context, payload []byte) error {
	if o.failed {
		return ErrOutputClosed
	}
	if len(payload) == 0 || len(payload) > MaxFrameBytes || bytes.ContainsAny(payload, "\r\n") {
		return errors.New("invalid helper output frame")
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		o.retire()
		return err
	}
	frame := make([]byte, len(payload)+1)
	copy(frame, payload)
	frame[len(payload)] = '\n'
	done := make(chan error, 1)
	go func() {
		n, err := o.writer.Write(frame)
		if err == nil && n != len(frame) {
			err = io.ErrShortWrite
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			o.retire()
		}
		return err
	case <-ctx.Done():
		o.retire()
		return ctx.Err()
	}
}

func (o *Output) retire() {
	o.failed = true
	go func() { _ = o.writer.Close() }()
}
