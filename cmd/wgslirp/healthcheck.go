package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/irctrakz/wgslirp/internal/packetwire"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
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
func runDirectEgressHealth(ctx context.Context, cfg healthConfig) {
	target := cfg.HTTPURL
	if err := checkHTTPHealth(ctx, target); err != nil {
		logging.Warnf("Health: direct HTTP GET failed: %v", err)
	} else {
		logging.Infof("Health: direct HTTP GET ok: %s", target)
	}
	// DNS resolve
	host := cfg.DNSName
	dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(dnsCtx, host); err != nil {
		logging.Warnf("Health: direct DNS lookup failed: %v", err)
	} else {
		logging.Infof("Health: direct DNS lookup ok: %s", host)
	}
}

// runSlirpDNSHealth crafts a DNS query as a raw IPv4+UDP packet through slirp and waits for any reply.
func runSlirpDNSHealth(ctx context.Context, si *socket.SocketInterface, sink *healthSink, cfg healthConfig) {
	dnsIP := cfg.DNSIP
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
	payload := buildDNSQuery(txid, cfg.DNSName)
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
			if validDNSHealthReplyForName(p, dstIP, srcIP, txid, cfg.DNSName) {
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
	return validDNSHealthReplyForName(p, server, client, id, "example.com")
}

func validDNSHealthReplyForName(p []byte, server, client [4]byte, id uint16, name string) bool {
	// Apply the same wire validation as socket input before DNS-specific matching.
	p, ihl, err := packetwire.ParseTransport(p, 17)
	if err != nil {
		return false
	}
	if string(p[12:16]) != string(server[:]) || string(p[16:20]) != string(client[:]) {
		return false
	}
	u := p[ihl:]
	if binary.BigEndian.Uint16(u[:2]) != 53 || binary.BigEndian.Uint16(u[2:4]) != 40053 {
		return false
	}
	var msg dnsmessage.Message
	if msg.Unpack(u[8:]) != nil || msg.ID != id || !msg.Response || msg.OpCode != 0 || msg.Truncated || msg.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 {
		return false
	}
	q := msg.Questions[0]
	if !strings.EqualFold(q.Name.String(), strings.TrimSuffix(name, ".")+".") || q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
		return false
	}
	name = q.Name.String()
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
	if len(payload) > 65507 {
		return nil
	}
	pkt := make([]byte, 28+len(payload))
	packetwire.IPv4Header(pkt, srcIP, dstIP, 17, 0, 64, 0, 0)
	packetwire.UDP(pkt[20:], srcIP, dstIP, srcPort, dstPort, payload)
	return pkt
}
