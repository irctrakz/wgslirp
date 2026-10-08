package socket

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
)

// mockSocketWriter is a simple implementation of SocketWriter for testing
type mockSocketWriter struct {
	writePacketFunc func(packet core.Packet) error
	writeCount      uint64
}

// WritePacket implements SocketWriter
func (m *mockSocketWriter) WritePacket(packet core.Packet) error {
	atomic.AddUint64(&m.writeCount, 1)
	if m.writePacketFunc != nil {
		return m.writePacketFunc(packet)
	}
	return nil
}

// TestSocketPacketProcessor_ProcessPacket tests the ProcessPacket method
func TestSocketPacketProcessor_ProcessPacket(t *testing.T) {
	// Create a mock socket writer
	mockSocket := &mockSocketWriter{}

	// Create a socket packet processor
	processor := NewSocketPacketProcessor(mockSocket, 4).(*SocketPacketProcessor)

	// Start the processor
	err := processor.Start()
	if err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}
	defer processor.Stop()

	// Create a test packet (IPv4 header)
	// Version: 4, IHL: 5, Total Length: 20, TTL: 64, Protocol: 1 (ICMP), Source: 192.168.1.1, Dest: 192.168.1.2
	packetData := []byte{
		0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
	}
	packet := core.NewCopiedPacket(packetData)

	// Process the packet
	err = processor.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("Failed to process packet: %v", err)
	}

	// Wait for the packet to be processed
	time.Sleep(100 * time.Millisecond)

	// Check that the packet was written to the socket
	if atomic.LoadUint64(&mockSocket.writeCount) != 1 {
		t.Errorf("Expected writeCount to be 1, got %d", mockSocket.writeCount)
	}

	// Check metrics
	metrics := processor.Metrics()
	if metrics["packetsProcessed"] != 1 {
		t.Errorf("Expected packetsProcessed to be 1, got %d", metrics["packetsProcessed"])
	}
	if metrics["packetsDropped"] != 0 {
		t.Errorf("Expected packetsDropped to be 0, got %d", metrics["packetsDropped"])
	}
}

// TestSocketPacketProcessor_ProcessPacket_Error tests error handling in ProcessPacket
func TestSocketPacketProcessor_ProcessPacket_Error(t *testing.T) {
	// Create a mock socket writer that returns an error
	mockSocket := &mockSocketWriter{
		writePacketFunc: func(packet core.Packet) error {
			return errors.New("test error")
		},
	}

	// Create a socket packet processor
	processor := NewSocketPacketProcessor(mockSocket, 4).(*SocketPacketProcessor)

	// Start the processor
	err := processor.Start()
	if err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}
	defer processor.Stop()

	// Create a test packet (IPv4 header)
	packetData := []byte{
		0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
	}
	packet := core.NewCopiedPacket(packetData)

	// Process the packet
	err = processor.ProcessPacket(packet)
	if err != nil {
		t.Fatalf("Failed to process packet: %v", err)
	}

	// Wait for the packet to be processed
	time.Sleep(100 * time.Millisecond)

	// Check that the packet was attempted to be written to the socket
	if atomic.LoadUint64(&mockSocket.writeCount) != 1 {
		t.Errorf("Expected writeCount to be 1, got %d", mockSocket.writeCount)
	}
}

// TestSocketPacketProcessor_ProcessPacket_InvalidPacket tests handling of invalid packets
func TestSocketPacketProcessor_ProcessPacket_InvalidPacket(t *testing.T) {
	// Create a mock socket writer
	mockSocket := &mockSocketWriter{}

	// Create a socket packet processor
	processor := NewSocketPacketProcessor(mockSocket, 4).(*SocketPacketProcessor)

	// Start the processor
	err := processor.Start()
	if err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}
	defer processor.Stop()

	// Create an invalid packet (too short)
	packetData := []byte{0x45, 0x00, 0x00}
	packet := core.NewCopiedPacket(packetData)

	// Process the packet
	err = processor.ProcessPacket(packet)
	if err == nil {
		t.Fatal("Expected error for invalid packet, got nil")
	}

	// Check that the packet was not written to the socket
	if atomic.LoadUint64(&mockSocket.writeCount) != 0 {
		t.Errorf("Expected writeCount to be 0, got %d", mockSocket.writeCount)
	}

	// Check metrics
	metrics := processor.Metrics()
	if metrics["packetsDropped"] != 1 {
		t.Errorf("Expected packetsDropped to be 1, got %d", metrics["packetsDropped"])
	}
}

// TestSocketPacketProcessor_ProcessPacket_UnsupportedVersion tests handling of unsupported IP versions
func TestSocketPacketProcessor_ProcessPacket_UnsupportedVersion(t *testing.T) {
	// Create a mock socket writer
	mockSocket := &mockSocketWriter{}

	// Create a socket packet processor
	processor := NewSocketPacketProcessor(mockSocket, 4).(*SocketPacketProcessor)

	// Start the processor
	err := processor.Start()
	if err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}
	defer processor.Stop()

	// Create a packet with unsupported IP version (IPv6)
	packetData := []byte{
		0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	packet := core.NewCopiedPacket(packetData)

	// Process the packet
	err = processor.ProcessPacket(packet)
	if err == nil {
		t.Fatal("Expected error for unsupported IP version, got nil")
	}

	// Check that the packet was not written to the socket
	if atomic.LoadUint64(&mockSocket.writeCount) != 0 {
		t.Errorf("Expected writeCount to be 0, got %d", mockSocket.writeCount)
	}

	// Check metrics
	metrics := processor.Metrics()
	if metrics["packetsDropped"] != 1 {
		t.Errorf("Expected packetsDropped to be 1, got %d", metrics["packetsDropped"])
	}
}

// TestSocketPacketProcessor_Start_Stop tests the Start and Stop methods
func TestSocketPacketProcessor_Start_Stop(t *testing.T) {
	// Create a mock socket writer
	mockSocket := &mockSocketWriter{}

	// Create a socket packet processor
	processor := NewSocketPacketProcessor(mockSocket, 4).(*SocketPacketProcessor)

	// Start the processor
	err := processor.Start()
	if err != nil {
		t.Fatalf("Failed to start processor: %v", err)
	}

	// Stop the processor
	err = processor.Stop()
	if err != nil {
		t.Fatalf("Failed to stop processor: %v", err)
	}
}
