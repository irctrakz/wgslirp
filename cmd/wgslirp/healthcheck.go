package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/irctrakz/wgslirp/pkg/socket"
)

// tee processor to fan out host->guest packets to WG and a health sink.
type teeProcessor struct{ a, b core.PacketProcessor }

func newTeeProcessor(a, b core.PacketProcessor) core.PacketProcessor {
	return &teeProcessor{a: a, b: b}
}
func (t *teeProcessor) ProcessPacket(p core.Packet) error {
	// Copy before transferring ownership: A may release a pooled packet.
	var cp []byte
	if t.b != nil {
		cp = append([]byte(nil), p.Data()...)
	}
	var err error
	if t.a != nil {
		err = t.a.ProcessPacket(p)
	}
	if t.b != nil {
		_ = t.b.ProcessPacket(core.NewPacket(cp))
	}
	return err
}

func (t *teeProcessor) Metrics() map[string]uint64 {
	if m, ok := t.a.(interface{ Metrics() map[string]uint64 }); ok {
		return m.Metrics()
	}
	return nil
}

// healthSink captures packets for the health probe.
type healthSink struct{ ch chan []byte }

func newHealthSink() *healthSink { return &healthSink{ch: make(chan []byte, 16)} }
func (h *healthSink) ProcessPacket(p core.Packet) error {
	select {
	case h.ch <- append([]byte(nil), p.Data()...):
	default:
	}
	return nil
}

// runDirectEgressHealth performs DNS and HTTP using the host stack (not slirp) to detect container egress problems.
func runDirectEgressHealth(ctx context.Context) {
	target := os.Getenv("HEALTH_HTTP_URL")
	if target == "" {
		target = "https://httpbin.org/ip"
	}
	if err := checkHTTPHealth(ctx, target); err != nil {
		logging.Warnf("Health: direct HTTP GET failed: %v", err)
	} else {
		logging.Infof("Health: direct HTTP GET ok: %s", target)
	}
	// DNS resolve
	host := os.Getenv("HEALTH_DNS_NAME")
	if host == "" {
		host = "example.com"
	}
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(dnsCtx, host); err != nil {
		logging.Warnf("Health: direct DNS lookup failed: %v", err)
	} else {
		logging.Infof("Health: direct DNS lookup ok: %s", host)
	}
}

// runSlirpDNSHealth crafts a DNS query as a raw IPv4+UDP packet through slirp and waits for any reply.
func runSlirpDNSHealth(ctx context.Context, si *socket.SocketInterface, sink *healthSink) {
	dnsIP := os.Getenv("HEALTH_DNS_IP")
	if dnsIP == "" {
		dnsIP = "1.1.1.1"
	}
	dst := net.ParseIP(dnsIP).To4()
	if dst == nil {
		logging.Warnf("Health: invalid HEALTH_DNS_IP: %q", dnsIP)
		return
	}
	// Build a simple A query for example.com
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		logging.Warnf("Health: DNS ID generation failed: %v", err)
		return
	}
	txid := binary.BigEndian.Uint16(id[:])
	payload := buildDNSQuery(txid, "example.com")
	srcIP := [4]byte{10, 0, 0, 2}
	dstIP := [4]byte{dst[0], dst[1], dst[2], dst[3]}
	pkt := buildIPv4UDP(srcIP, dstIP, 40053, 53, payload)
	if err := si.WritePacket(core.NewPacket(pkt)); err != nil {
		logging.Warnf("Health: slirp DNS send failed: %v", err)
		return
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			logging.Warnf("Health: slirp DNS no valid reply from %s within timeout", dnsIP)
			return
		case p := <-sink.ch:
			if validDNSHealthReply(p, dstIP, srcIP, txid) {
				logging.Infof("Health: slirp DNS reply ok from %s", dnsIP)
				return
			}
		}
	}
}

func checkHTTPHealth(ctx context.Context, target string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP returned %s", resp.Status)
	}
	return nil
}

// A probe succeeds only for a complete, matching response with an A answer.
// Unrelated traffic, error responses, truncation and malformed packets cannot
// make an unhealthy DNS path appear healthy.
func validDNSHealthReply(p []byte, server, client [4]byte, id uint16) bool {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 {
		return false
	}
	ihl := int(p[0]&15) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if ihl < 20 || total < ihl+8 || total > len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return false
	}
	if string(p[12:16]) != string(server[:]) || string(p[16:20]) != string(client[:]) {
		return false
	}
	u := p[ihl:total]
	if binary.BigEndian.Uint16(u[:2]) != 53 || binary.BigEndian.Uint16(u[2:4]) != 40053 || int(binary.BigEndian.Uint16(u[4:6])) != len(u) {
		return false
	}
	var msg dnsmessage.Message
	if msg.Unpack(u[8:]) != nil || msg.ID != id || !msg.Response || msg.OpCode != 0 || msg.Truncated || msg.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 {
		return false
	}
	q := msg.Questions[0]
	if !strings.EqualFold(q.Name.String(), "example.com.") || q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
		return false
	}
	name := q.Name.String()
	// Follow only a bounded chain of aliases belonging to this question.
	for i := 0; i <= len(msg.Answers); i++ {
		next := ""
		for _, a := range msg.Answers {
			if a.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(a.Header.Name.String(), name) {
				continue
			}
			switch body := a.Body.(type) {
			case *dnsmessage.AResource:
				return body.A != [4]byte{}
			case *dnsmessage.CNAMEResource:
				next = body.CNAME.String()
			}
		}
		if next == "" {
			return false
		}
		name = next
	}
	return false
}

// Helpers (copied minimal from tests)
func buildDNSQuery(id uint16, name string) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	var qname []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		qname = append(qname, byte(len(label)))
		qname = append(qname, []byte(label)...)
	}
	qname = append(qname, 0x00)
	qt := make([]byte, 2)
	qc := make([]byte, 2)
	binary.BigEndian.PutUint16(qt, 1)
	binary.BigEndian.PutUint16(qc, 1)
	return append(append(append(hdr, qname...), qt...), qc...)
}

func buildIPv4UDP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	ihl := 20
	udpLen := 8 + len(payload)
	totalLen := ihl + udpLen
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = 0x00
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	ipcs := checksum(pkt[:20])
	pkt[10] = byte(ipcs >> 8)
	pkt[11] = byte(ipcs)
	off := 20
	binary.BigEndian.PutUint16(pkt[off:off+2], srcPort)
	binary.BigEndian.PutUint16(pkt[off+2:off+4], dstPort)
	binary.BigEndian.PutUint16(pkt[off+4:off+6], uint16(udpLen))
	copy(pkt[off+8:], payload)
	ucs := udpChecksum(pkt[off:off+udpLen], srcIP, dstIP)
	binary.BigEndian.PutUint16(pkt[off+6:off+8], ucs)
	return pkt
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(uint16(data[len(data)-1]) << 8)
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(udp []byte, srcIP, dstIP [4]byte) uint16 {
	sum := uint32(0)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i:]))
	}
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i:]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(uint16(udp[len(udp)-1]) << 8)
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
