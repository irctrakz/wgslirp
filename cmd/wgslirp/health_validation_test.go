package main

import (
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
