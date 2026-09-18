package wireguard

import (
	"encoding/binary"
	"fmt"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"io"
	"os"
	"sync"
	"time"
)

// Simple PCAP writer (DLT_RAW) for plaintext IPv4 frames.
// Enabled when WG_PCAP is set to a writable filepath.

var (
	pcapConfig  *CaptureConfig
	pcapMu      sync.Mutex
	pcapEnabled bool
	pcapFile    *os.File
	pcapFailed  bool
	pcapBytes   int64
	pcapLimit   int64
)

const defaultPCAPLimit int64 = 64 * 1024 * 1024

// ConfigurePCAP freezes the process-wide capture policy and opens the optional
// capture before packet workers start. Repeating the same configuration is safe;
// neither environment changes nor calls after ClosePCAP reopen/truncate a file.
func ConfigurePCAP(c CaptureConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	pcapMu.Lock()
	defer pcapMu.Unlock()
	if pcapConfig != nil {
		if *pcapConfig != c {
			return fmt.Errorf("capture configuration is already fixed")
		}
		if pcapFailed && pcapFile == nil {
			return fmt.Errorf("capture is closed or failed")
		}
		return nil
	}
	if pcapFailed {
		return fmt.Errorf("capture is closed or failed")
	}
	pcapConfig = &c
	if c.Path == "" {
		return nil
	}
	path := c.Path
	pcapLimit = c.MaxBytes
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		pcapFailed = true
		return fmt.Errorf("PCAP open failed: %w", err)
	}
	if err = f.Chmod(0600); err == nil {
		err = f.Truncate(0)
	}
	if err != nil {
		f.Close()
		pcapFailed = true
		return fmt.Errorf("PCAP initialization failed: %w", err)
	}
	// PCAP Global Header
	// magic 0xa1b2c3d4, version 2.4, tz 0, sigfigs 0, snaplen 65535, network LINKTYPE_RAW (101)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	// 8:12 thiszone (0), 12:16 sigfigs (0)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], 101)
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		pcapFailed = true
		return fmt.Errorf("PCAP header write failed: %w", err)
	}
	pcapFile = f
	pcapEnabled = true
	pcapBytes = 24
	return nil
}

// pcapWriteIPv4 writes one raw IPv4 packet to the PCAP file if enabled.
func pcapWriteIPv4(b []byte) {
	if len(b) == 0 {
		return
	}
	pcapMu.Lock()
	defer pcapMu.Unlock()
	if !pcapEnabled || pcapFile == nil {
		return
	}
	originalLen := len(b)
	if len(b) > 65535 {
		b = b[:65535]
	}
	if int64(16+len(b)) > pcapLimit-pcapBytes {
		logging.Warnf("PCAP size limit reached (%d bytes); capture stopped", pcapLimit)
		if err := pcapFile.Close(); err != nil {
			logging.Warnf("PCAP close failed: %v", err)
		}
		pcapFile = nil
		pcapEnabled = false
		pcapFailed = true
		return
	}
	// per-packet header: ts_sec, ts_usec, incl_len, orig_len (all LE)
	ph := make([]byte, 16)
	now := time.Now()
	binary.LittleEndian.PutUint32(ph[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(ph[4:8], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(ph[8:12], uint32(len(b)))
	binary.LittleEndian.PutUint32(ph[12:16], uint32(originalLen))
	record := append(ph, b...)
	n, err := pcapFile.Write(record)
	pcapBytes += int64(n)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	if err != nil {
		logging.Warnf("PCAP disabled after write failure: %v", err)
		pcapFile.Close()
		pcapFile = nil
		pcapEnabled = false
		pcapFailed = true
	}
}

// ClosePCAP releases the optional process-wide diagnostic capture.
func ClosePCAP() error {
	pcapMu.Lock()
	defer pcapMu.Unlock()
	pcapFailed = true
	pcapEnabled = false
	if pcapFile == nil {
		return nil
	}
	err := pcapFile.Close()
	pcapFile = nil
	return err
}
