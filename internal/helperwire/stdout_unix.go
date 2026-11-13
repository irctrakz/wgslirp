//go:build unix

package helperwire

import (
	"context"
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

func (w *stdoutWriter) writeContext(ctx context.Context, frame []byte) (written int, err error) {
	pollErr := w.raw.Write(func(fd uintptr) bool {
		for written < len(frame) {
			if err = ctx.Err(); err != nil {
				return true
			}
			n, writeErr := unix.Write(int(fd), frame[written:])
			if n > 0 {
				written += n
			}
			switch writeErr {
			case unix.EAGAIN:
				return false
			case unix.EINTR:
				continue
			}
			if writeErr != nil || n == 0 {
				err = writeErr
				return true
			}
		}
		return true
	})
	if err == nil {
		err = pollErr
	}
	return written, err
}
