package socket

import (
	"os"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
)

// mockPacketProcessor is a mock implementation of core.PacketProcessor
type mockPacketProcessor struct {
	processPacketFunc func(packet core.Packet) error
	packets           []core.Packet
}

// ProcessPacket implements core.PacketProcessor
func (m *mockPacketProcessor) ProcessPacket(packet core.Packet) error {
	if m.processPacketFunc != nil {
		return m.processPacketFunc(packet)
	}
	m.packets = append(m.packets, packet)
	return nil
}

// TestSocketInterface_Start tests the Start method
func TestSocketInterface_Start(t *testing.T) {
	// Create a mock socket interface
	config := Config{
		IPAddress: "127.0.0.1",
		MTU:       1500,
		Debug:     true,
	}
	socket := NewMockSocketInterface(config)

	// Set a mock packet processor
	processor := &mockPacketProcessor{}
	socket.SetPacketProcessor(processor)

	// Start the socket interface
	err := socket.Start()
	if err != nil {
		t.Fatalf("Failed to start socket interface: %v", err)
	}

	// Stop the socket interface
	err = socket.Stop()
	if err != nil {
		t.Fatalf("Failed to stop socket interface: %v", err)
	}
}

// TestSocketInterface_WritePacket tests the WritePacket method
func TestSocketInterface_WritePacket(t *testing.T) {
	// Create a mock socket interface
	config := Config{
		IPAddress: "127.0.0.1",
		MTU:       1500,
		Debug:     true,
	}
	mockSocket := NewMockSocketInterface(config)

	// Set a mock packet processor
	processor := &mockPacketProcessor{}
	mockSocket.SetPacketProcessor(processor)

	// Start the socket interface
	err := mockSocket.Start()
	if err != nil {
		t.Fatalf("Failed to start socket interface: %v", err)
	}
	defer mockSocket.Stop()

	// Create a test packet (IPv4 header)
	// Version: 4, IHL: 5, Total Length: 20, TTL: 64, Protocol: 1 (ICMP), Source: 192.168.1.1, Dest: 192.168.1.2
	packetData := []byte{
		0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
	}
	packet := core.NewCopiedPacket(packetData)

	// Write the packet
	err = mockSocket.WritePacket(packet)
	if err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	// Check metrics
	metrics := mockSocket.Metrics()
	if metrics.PacketsSent != 1 {
		t.Errorf("Expected PacketsSent to be 1, got %d", metrics.PacketsSent)
	}
	if metrics.BytesSent != uint64(len(packetData)) {
		t.Errorf("Expected BytesSent to be %d, got %d", len(packetData), metrics.BytesSent)
	}

	// Check that the packet was stored
	sentPackets := mockSocket.GetSentPackets()
	if len(sentPackets) != 1 {
		t.Errorf("Expected 1 sent packet, got %d", len(sentPackets))
	}
}

// TestSocketInterface_Metrics tests the Metrics method
func TestSocketInterface_Metrics(t *testing.T) {
	// Create a socket interface
	config := Config{
		IPAddress: "127.0.0.1",
		MTU:       1500,
		Debug:     true,
	}
	socket := NewSocketInterface(config)

	// Check initial metrics
	metrics := socket.Metrics()
	if metrics.PacketsSent != 0 {
		t.Errorf("Expected initial PacketsSent to be 0, got %d", metrics.PacketsSent)
	}
	if metrics.PacketsReceived != 0 {
		t.Errorf("Expected initial PacketsReceived to be 0, got %d", metrics.PacketsReceived)
	}
	if metrics.BytesSent != 0 {
		t.Errorf("Expected initial BytesSent to be 0, got %d", metrics.BytesSent)
	}
	if metrics.BytesReceived != 0 {
		t.Errorf("Expected initial BytesReceived to be 0, got %d", metrics.BytesReceived)
	}
	if metrics.Errors != 0 {
		t.Errorf("Expected initial Errors to be 0, got %d", metrics.Errors)
	}
}

// TestSocketInterface_Integration tests the socket interface with a simulated packet
func TestSocketInterface_Integration(t *testing.T) {
	// Create a mock socket interface
	config := Config{
		IPAddress: "127.0.0.1",
		MTU:       1500,
		Debug:     true,
	}
	mockSocket := NewMockSocketInterface(config)

	// Create a channel to receive processed packets
	packetCh := make(chan core.Packet, 10)

	// Set a mock packet processor that sends packets to the channel
	processor := &mockPacketProcessor{
		processPacketFunc: func(packet core.Packet) error {
			packetCh <- packet
			return nil
		},
	}
	mockSocket.SetPacketProcessor(processor)

	// Start the socket interface
	err := mockSocket.Start()
	if err != nil {
		t.Fatalf("Failed to start socket interface: %v", err)
	}
	defer mockSocket.Stop()

	// Create a test ICMP Echo Request packet
	// IPv4 header + ICMP Echo Request
	packetData := []byte{
		// IPv4 header
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
		// ICMP Echo Request
		0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	packet := core.NewCopiedPacket(packetData)

	// Simulate receiving a packet
	err = mockSocket.SimulatePacketReceived(packet)
	if err != nil {
		t.Fatalf("Failed to simulate packet reception: %v", err)
	}

	// Wait for the packet to be processed
	select {
	case <-packetCh:
		// Packet received
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for packet")
	}

	// Check metrics
	metrics := mockSocket.Metrics()
	if metrics.PacketsReceived != 1 {
		t.Errorf("Expected PacketsReceived to be 1, got %d", metrics.PacketsReceived)
	}
	if metrics.BytesReceived != uint64(len(packetData)) {
		t.Errorf("Expected BytesReceived to be %d, got %d", len(packetData), metrics.BytesReceived)
	}

	// Check that the packet was stored
	receivedPackets := mockSocket.GetReceivedPackets()
	if len(receivedPackets) != 1 {
		t.Errorf("Expected 1 received packet, got %d", len(receivedPackets))
	}
}

// TestRealSocketInterface_Start tests the Start method with a real socket
// This test requires root privileges and is skipped by default
func TestRealSocketInterface_Start(t *testing.T) {
	// Skip this test if not running as root
	if os.Getuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	// Create a socket interface with a non-privileged address
	config := Config{
		IPAddress: "127.0.0.1",
		MTU:       1500,
		Debug:     true,
	}
	socket := NewSocketInterface(config)

	// Set a mock packet processor
	processor := &mockPacketProcessor{}
	socket.SetPacketProcessor(processor)

	// Start the socket interface
	err := socket.Start()
	if err != nil {
		t.Fatalf("Failed to start socket interface: %v", err)
	}

	// Stop the socket interface
	err = socket.Stop()
	if err != nil {
		t.Fatalf("Failed to stop socket interface: %v", err)
	}
}
