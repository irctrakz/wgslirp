package wireguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPCAPRestrictsExistingFileAndCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	pcapConfig = nil
	pcapFailed = false
	if err := ConfigurePCAP(CaptureConfig{Path: path, MaxBytes: defaultPCAPLimit}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ClosePCAP(); pcapConfig = nil; pcapFailed = false })
	pcapWriteIPv4([]byte{0x45, 0, 0, 0})
	if err := ClosePCAP(); err != nil {
		t.Fatal(err)
	}
	if err := ClosePCAP(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions=%o", info.Mode().Perm())
	}
	if info.Size() != 24+16+4 {
		t.Fatalf("capture size=%d", info.Size())
	}
	// Restore diagnostic globals for other tests; no packet goroutines are running.
	pcapFailed = false
}
