package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPHealthStatusAndCancellation(t *testing.T) {
	for _, status := range []int{200, 204, 404, 503} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		err := checkHTTPHealth(context.Background(), server.URL)
		server.Close()
		if (err == nil) != (status >= 200 && status < 300) {
			t.Fatalf("status %d: %v", status, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkHTTPHealth(ctx, "http://127.0.0.1:1"); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestDNSHealthValidatesResponse(t *testing.T) {
	server, client := [4]byte{1, 1, 1, 1}, [4]byte{10, 0, 0, 2}
	name := dnsmessage.MustNewName("example.com.")
	valid := func() dnsmessage.Message {
		return dnsmessage.Message{
			Header:    dnsmessage.Header{ID: 123, Response: true},
			Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
			Answers:   []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}}},
		}
	}
	cases := []struct {
		name string
		edit func(*dnsmessage.Message)
		want bool
	}{
		{"valid", func(*dnsmessage.Message) {}, true},
		{"wrong ID", func(m *dnsmessage.Message) { m.ID++ }, false},
		{"query", func(m *dnsmessage.Message) { m.Response = false }, false},
		{"truncated", func(m *dnsmessage.Message) { m.Truncated = true }, false},
		{"server failure", func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeServerFailure }, false},
		{"no answers", func(m *dnsmessage.Message) { m.Answers = nil }, false},
		{"wrong question", func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.com.") }, false},
		{"unrelated answer", func(m *dnsmessage.Message) { m.Answers[0].Header.Name = dnsmessage.MustNewName("other.com.") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := valid()
			tc.edit(&m)
			body, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}
			p := buildIPv4UDP(server, client, 53, 40053, body)
			if got := validDNSHealthReply(p, server, client, 123); got != tc.want {
				t.Fatalf("valid=%v", got)
			}
		})
	}
	m := valid()
	body, _ := m.Pack()
	packet := buildIPv4UDP(server, client, 53, 40053, body)
	for i := 0; i < len(packet); i++ {
		if validDNSHealthReply(packet[:i], server, client, 123) {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	for _, offset := range []int{12, 16, 20, 22, 24} {
		p := append([]byte(nil), packet...)
		p[offset] ^= 1
		if validDNSHealthReply(p, server, client, 123) {
			t.Fatalf("accepted changed boundary at %d", offset)
		}
	}
	binary.BigEndian.PutUint16(packet[6:8], 0x2000)
	if validDNSHealthReply(packet, server, client, 123) {
		t.Fatal("accepted fragment")
	}
}

// Independent checksum repair keeps flag/option fixtures valid at the checksum
// boundary, so their rejection cannot accidentally be explained by corruption.
func repairHealthIPChecksum(p []byte) {
	ihl := int(p[0]&15) * 4
	p[10], p[11] = 0, 0
	var sum uint64
	for i := 0; i < ihl; i++ {
		if i%2 == 0 {
			sum += uint64(p[i]) * 256
		} else {
			sum += uint64(p[i])
		}
	}
	for sum > 65535 {
		sum = sum%65536 + sum/65536
	}
	binary.BigEndian.PutUint16(p[10:12], uint16(65535-sum))
}

func TestDNSHealthWirePolicy(t *testing.T) {
	server, client := [4]byte{1, 1, 1, 1}, [4]byte{10, 0, 0, 2}
	name := dnsmessage.MustNewName("example.com.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 123, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers:   []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}}},
	}
	body, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	base := buildIPv4UDP(server, client, 53, 40053, body)
	cases := []struct {
		name string
		edit func([]byte) []byte
		want bool
	}{
		{"valid", func(p []byte) []byte { return p }, true},
		{"link padding", func(p []byte) []byte { return append(p, 1, 2, 3) }, true},
		{"DF", func(p []byte) []byte { p[6] = 0x40; repairHealthIPChecksum(p); return p }, true},
		{"omitted UDP checksum", func(p []byte) []byte { p[26] = 0; p[27] = 0; return p }, true},
		{"bad IP checksum", func(p []byte) []byte { p[10] ^= 1; return p }, false},
		{"bad UDP checksum", func(p []byte) []byte { p[26] ^= 1; return p }, false},
		{"corrupt answer", func(p []byte) []byte { p[len(p)-1] ^= 1; return p }, false},
		{"reserved flag", func(p []byte) []byte { p[6] = 0x80; repairHealthIPChecksum(p); return p }, false},
		{"first fragment", func(p []byte) []byte { p[6] = 0x20; repairHealthIPChecksum(p); return p }, false},
		{"later fragment", func(p []byte) []byte { p[7] = 1; repairHealthIPChecksum(p); return p }, false},
		{"IP options", func(p []byte) []byte {
			out := append(bytes.Clone(p[:20]), 1, 1, 0, 0)
			out = append(out, p[20:]...)
			out[0] = 0x46
			binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
			repairHealthIPChecksum(out)
			return out
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.edit(bytes.Clone(base))
			before := bytes.Clone(p)
			if got := validDNSHealthReply(p, server, client, 123); got != tc.want {
				t.Fatalf("accepted=%v want=%v", got, tc.want)
			}
			if !bytes.Equal(p, before) {
				t.Fatal("input mutated")
			}
		})
	}
}
