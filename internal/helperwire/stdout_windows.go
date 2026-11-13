package helperwire

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// NewStdoutOutput takes ownership of the inherited byte pipe. Anonymous
// Windows pipes are synchronous handles. Use nonblocking pipe mode and count
// successful bytes directly so cancellation does not destroy a clean boundary.
func NewStdoutOutput() (*Output, error) {
	handle := windows.Handle(os.Stdout.Fd())
	w := &windowsStdout{File: os.Stdout, handle: handle}
	if err := w.enableNonblocking(); err != nil && !errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return nil, err
	}
	return NewOutput(w), nil
}

type windowsStdout struct {
	*os.File
	handle      windows.Handle
	nonblocking bool
}

func (w *windowsStdout) enableNonblocking() error {
	mode := uint32(windows.PIPE_NOWAIT)
	if err := windows.SetNamedPipeHandleState(w.handle, &mode, nil, nil); err != nil {
		return fmt.Errorf("make helper stdout nonblocking: %w", err)
	}
	w.nonblocking = true
	return nil
}

func (w *windowsStdout) writeContext(ctx context.Context, frame []byte, gate WriteGate) (written int, err error) {
	var retry *time.Timer
	defer func() {
		if retry != nil {
			retry.Stop()
		}
	}()
	const retryDelay = 2 * time.Millisecond
	const maxChunk = 4096
	chunk := maxChunk
	for written < len(frame) {
		var n uint32
		gate(func() bool {
			if err = ctx.Err(); err != nil {
				return false
			}
			// Windows can reject the mode switch while previously written
			// bytes remain buffered. Do not write until the switch succeeds.
			if !w.nonblocking {
				err = w.enableNonblocking()
				if errors.Is(err, windows.ERROR_PIPE_BUSY) {
					err = nil
					return false
				}
				if err != nil {
					return false
				}
			}
			end := min(written+chunk, len(frame))
			err = windows.WriteFile(w.handle, frame[written:end], &n, nil)
			written += int(n)
			return written == len(frame)
		})
		if err != nil || written == len(frame) {
			return written, err
		}
		if n != 0 {
			chunk = maxChunk
			continue
		}
		// A full byte pipe reports a successful zero-byte write in this mode.
		// Some Windows pipes also report zero if the entire chunk won't fit.
		if w.nonblocking && chunk > 1 {
			chunk = max(1, min(chunk, len(frame)-written)/2)
			continue
		}
		if retry == nil {
			retry = time.NewTimer(retryDelay)
		} else {
			retry.Reset(retryDelay)
		}
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		case <-retry.C:
		}
	}
	return written, nil
}
