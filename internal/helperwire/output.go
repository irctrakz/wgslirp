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

// NewOutput takes ownership of the protocol stream. Close must interrupt an
// outstanding Write. Use NewStdoutOutput for inherited standard output.
func NewOutput(writer io.WriteCloser) *Output { return &Output{writer: writer} }

type contextWriter interface {
	writeContext(context.Context, []byte) (int, error)
}

// WriteFrame writes a single pre-encoded JSON object followed by LF. A failed,
// partial or timed-out write permanently retires the output. The controller
// must shut down the runtime and exit on such a failure. If cancellation
// interrupts a write, close the stream and wait for the write to stop. A
// complete frame remains successful even when cancellation races its result.
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
		var n int
		var err error
		if writer, ok := o.writer.(contextWriter); ok {
			n, err = writer.writeContext(ctx, frame)
		} else if err = ctx.Err(); err == nil {
			n, err = o.writer.Write(frame)
		}
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
		select {
		case err := <-done:
			if err == nil {
				return nil
			}
			o.retire()
			return err
		default:
		}
		o.retire()
		if err := <-done; err == nil {
			return nil
		}
		return ctx.Err()
	}
}

func (o *Output) retire() {
	o.failed = true
	_ = o.writer.Close()
}
