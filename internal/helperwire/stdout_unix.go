//go:build unix

package helperwire

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// NewStdoutOutput takes over stdout. Inherited stdout is normally blocking,
// so wrap a nonblocking duplicate in a new, pollable os.File before using it.
func NewStdoutOutput() (*Output, error) {
	fd, err := unix.FcntlInt(os.Stdout.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate helper stdout: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("make helper stdout interruptible: %w", err)
	}
	file := os.NewFile(uintptr(fd), "helper stdout")
	if err := file.SetWriteDeadline(time.Time{}); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("helper stdout does not support interruptible writes: %w", err)
	}
	raw, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := os.Stdout.Close(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return NewOutput(&stdoutWriter{File: file, raw: raw}), nil
}

type stdoutWriter struct {
	*os.File
	raw syscall.RawConn
}

func (w *stdoutWriter) writeContext(ctx context.Context, frame []byte, gate WriteGate) (written int, err error) {
	// Wake the poller without closing the descriptor. The write result tells
	// Output whether the stream is still at a frame boundary.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = w.SetWriteDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
			_ = w.SetWriteDeadline(time.Time{})
		}
	}()
	pollErr := w.raw.Write(func(fd uintptr) bool {
		for written < len(frame) {
			var n int
			gate(func() bool {
				if err = ctx.Err(); err == nil {
					n, err = unix.Write(int(fd), frame[written:])
					if n > 0 {
						written += n
					}
				}
				return written == len(frame)
			})
			switch err {
			case unix.EAGAIN:
				err = nil // RawConn owns the poll and reports its cancellation.
				return false
			case unix.EINTR:
				continue
			}
			if err != nil || n == 0 {
				return true
			}
		}
		return true
	})
	if err == nil {
		err = pollErr
	}
	if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() != nil {
		err = ctx.Err()
	}
	return written, err
}
