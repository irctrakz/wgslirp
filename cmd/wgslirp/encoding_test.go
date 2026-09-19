package main

import (
	"encoding/hex"
	"testing"
)

func TestHealthUDPUsesSharedWireEncoding(t *testing.T) {
	p := buildIPv4UDP([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 40000, 53, []byte{0xda, 0x61})
	if hex.EncodeToString(p[20:]) != "9c400035000affffda61" {
		t.Fatalf("UDP bytes: %x", p)
	}
	if p[4] != 0 || p[5] != 0 || p[8] != 64 {
		t.Fatal("health header policy changed")
	}
}
