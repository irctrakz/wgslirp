package helperwire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type bufferOutput struct{ bytes.Buffer }

func (*bufferOutput) Close() error { return nil }

type cancelAtBoundary struct {
	bufferOutput
	cancel   context.CancelFunc
	complete bool
}

func (w *cancelAtBoundary) writeContext(ctx context.Context, frame []byte) (int, error) {
	if w.cancel == nil {
		return w.Write(frame)
	}
	var n int
	if w.complete {
		n, _ = w.Write(frame)
	}
	w.cancel()
	w.cancel = nil
	return n, ctx.Err()
}

func TestOutputDiagnosticAfterCancellationAtFrameBoundary(t *testing.T) {
	const diagnostic = `{"type":"session_error","code":"queue_full"}`
	for _, mode := range []string{"pre-cancelled", "zero-bytes", "after-lf"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sink := &cancelAtBoundary{cancel: cancel, complete: mode == "after-lf"}
			var want string
			var wantErr error
			if mode == "pre-cancelled" {
				cancel()
				sink.cancel = nil
			}
			if mode == "after-lf" {
				want = "{}\n"
			} else {
				wantErr = context.Canceled
			}
			out := NewOutput(sink)
			if err := out.WriteFrame(ctx, []byte("{}")); !errors.Is(err, wantErr) || sink.String() != want {
				t.Fatalf("cancelled response: %q (%v)", sink.String(), err)
			}
			if err := out.WriteFrame(context.Background(), []byte(diagnostic)); err != nil {
				t.Fatalf("terminal diagnostic: %v", err)
			}
			if got := sink.String(); got != want+diagnostic+"\n" {
				t.Fatalf("stdout = %q", got)
			}
		})
	}

}

type observedPipeWriter struct {
	*io.PipeWriter
	closed chan struct{}
}

func (w *observedPipeWriter) Close() error {
	err := w.PipeWriter.Close()
	close(w.closed)
	return err
}

func TestOutputBoundsAndDisconnect(t *testing.T) {
	var dst bufferOutput
	out := NewOutput(&dst)
	if err := out.WriteFrame(context.Background(), []byte(strings.Repeat("x", MaxFrameBytes+1))); err == nil || dst.Len() != 0 {
		t.Fatalf("oversize frame accepted: %v", err)
	}
	if err := out.WriteFrame(context.Background(), []byte(`{"id":1}`)); err != nil || dst.String() != "{\"id\":1}\n" {
		t.Fatalf("framing: %q (%v)", dst.String(), err)
	}

	reader, writer := io.Pipe()
	reader.Close()
	defer writer.Close()
	out = NewOutput(writer)
	if err := out.WriteFrame(context.Background(), []byte("{}")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("disconnected reader: %v", err)
	}
	if err := out.WriteFrame(context.Background(), []byte("{}")); !errors.Is(err, ErrOutputClosed) {
		t.Fatalf("write after disconnect: %v", err)
	}
}

func TestOutputStopsAfterPartialWrite(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan struct{})
	out := NewOutput(&observedPipeWriter{PipeWriter: writer, closed: closed})
	done := make(chan error, 1)
	go func() { done <- out.WriteFrame(ctx, []byte(`{"id":1}`)) }()
	prefix := make([]byte, 2)
	if _, err := io.ReadFull(reader, prefix); err != nil || string(prefix) != "{\"" {
		t.Fatalf("partial frame: %q (%v)", prefix, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("controller stayed blocked on the slow reader")
	}
	if err := out.WriteFrame(context.Background(), []byte("{}")); !errors.Is(err, ErrOutputClosed) {
		t.Fatalf("write after interrupted frame: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("retiring the output did not close the pipe")
	}
	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("retired pipe: read %d bytes (%v)", n, err)
	}
}
