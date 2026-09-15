package wireguard

import (
	"encoding/binary"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"os"
	"strings"
	"sync"
	"time"
)

// Simple PCAP writer (DLT_RAW) for plaintext IPv4 frames.
// Enabled when WG_PCAP is set to a writable filepath.

var (
	pcapMu      sync.Mutex
	pcapEnabled bool
	pcapFile    *os.File
	pcapFailed  bool
)

func initPCAP() {
	path := strings.TrimSpace(os.Getenv("WG_PCAP"))
	if path == "" || pcapEnabled || pcapFailed {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		pcapFailed = true
		logging.Warnf("PCAP open failed: %v", err)
		return
	}
	if err = f.Chmod(0600); err == nil {
		err = f.Truncate(0)
	}
	if err != nil {
		f.Close()
		pcapFailed = true
		logging.Warnf("PCAP initialization failed: %v", err)
		return
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
		logging.Warnf("PCAP header write failed: %v", err)
		return
	}
	pcapFile = f
	pcapEnabled = true
}

// pcapWriteIPv4 writes one raw IPv4 packet to the PCAP file if enabled.
func pcapWriteIPv4(b []byte) {
	if len(b) == 0 {
		return
	}
	pcapMu.Lock()
	defer pcapMu.Unlock()
	if !pcapEnabled {
		initPCAP()
	}
	if !pcapEnabled || pcapFile == nil {
		return
	}
	// per-packet header: ts_sec, ts_usec, incl_len, orig_len (all LE)
	ph := make([]byte, 16)
	now := time.Now()
	binary.LittleEndian.PutUint32(ph[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(ph[4:8], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(ph[8:12], uint32(len(b)))
	binary.LittleEndian.PutUint32(ph[12:16], uint32(len(b)))
	// write header then data
	_, err := pcapFile.Write(ph)
	if err == nil {
		_, err = pcapFile.Write(b)
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
