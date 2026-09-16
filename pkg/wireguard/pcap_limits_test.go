package wireguard

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func captureForTest(t *testing.T, limit string) string {
	t.Helper()
	_ = ClosePCAP()
	pcapFailed = false
	path := filepath.Join(t.TempDir(), "capture.pcap")
	t.Setenv("WG_PCAP", path)
	t.Setenv("WG_PCAP_MAX_BYTES", limit)
	t.Cleanup(func() { _ = ClosePCAP(); pcapFailed = false })
	return path
}

func TestPCAPConcurrentLimitStopsAtCompleteRecord(t *testing.T) {
	path := captureForTest(t, "44") // global header + one four-byte packet record
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); pcapWriteIPv4([]byte{0x45, 0, 0, 0}) }()
	}
	workers.Wait()
	pcapWriteIPv4([]byte{1}) // cannot reopen or truncate the completed capture
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 44 || binary.LittleEndian.Uint32(data[32:36]) != 4 {
		t.Fatalf("invalid bounded capture (%d bytes)", len(data))
	}
	if pcapEnabled || pcapFile != nil {
		t.Fatal("capture still open at limit")
	}
}

func TestPCAPInvalidLimitPreservesExistingFile(t *testing.T) {
	for _, limit := range []string{"0", "-1", "23", "invalid", "999999999999999999999"} {
		t.Run(limit, func(t *testing.T) {
			path := captureForTest(t, limit)
			if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			pcapWriteIPv4([]byte{0x45})
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "keep" {
				t.Fatalf("file modified: %q %v", data, err)
			}
		})
	}
}

func TestPCAPSnapLength(t *testing.T) {
	path := captureForTest(t, "100000")
	pcapWriteIPv4(make([]byte, 65536))
	_ = ClosePCAP()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 24+16+65535 || binary.LittleEndian.Uint32(data[32:36]) != 65535 || binary.LittleEndian.Uint32(data[36:40]) != 65536 {
		t.Fatal("invalid snap length record")
	}
}
