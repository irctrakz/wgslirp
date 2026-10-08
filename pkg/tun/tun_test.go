//go:build integration
// +build integration

package tun

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/irctrakz/wgslirp/pkg/core"
)

// mockPacketProcessor is a mock implementation of core.PacketProcessor for testing
type mockPacketProcessor struct {
	processedPackets []core.Packet
	shouldError      bool
	mu               sync.Mutex
	packetReceived   chan struct{}
}

// ProcessPacket implements core.PacketProcessor
func (m *mockPacketProcessor) ProcessPacket(packet core.Packet) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldError {
		return errors.New("mock processor error")
	}

	// Make a copy of the packet data to avoid any race conditions
	data := make([]byte, packet.Length())
	copy(data, packet.Data())

	m.processedPackets = append(m.processedPackets, core.NewCopiedPacket(data))

	// Signal that a packet was received
	if m.packetReceived != nil {
		select {
		case m.packetReceived <- struct{}{}:
		default:
			// Channel is full or closed, ignore
		}
	}

	return nil
}

// GetProcessedPackets returns the processed packets in a thread-safe way
func (m *mockPacketProcessor) GetProcessedPackets() []core.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Make a copy to avoid race conditions
	result := make([]core.Packet, len(m.processedPackets))
	copy(result, m.processedPackets)
	return result
}

// TestMockTUNDevice tests the mock TUN device
func TestMockTUNDevice(t *testing.T) {
	// Create a mock TUN device
	tun := NewMockTUNDevice("mock-tun", 1500)

	// Create a mock packet processor
	processor := &mockPacketProcessor{}
	tun.SetPacketProcessor(processor)

	// Start the TUN device
	if err := tun.Start(); err != nil {
		t.Fatalf("Failed to start TUN device: %v", err)
	}

	// Simulate receiving a packet
	testData := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02}
	mockTun := tun.(*MockTUNDevice) // Type assertion to access mock-specific methods
	if err := mockTun.SimulatePacketReceived(testData); err != nil {
		t.Fatalf("Failed to simulate packet received: %v", err)
	}

	// Wait a bit for the packet to be processed
	time.Sleep(100 * time.Millisecond)

	// Check if the packet was processed
	processedPackets := processor.GetProcessedPackets()
	if len(processedPackets) != 1 {
		t.Fatalf("Expected 1 processed packet, got %d", len(processedPackets))
	}

	// Check the packet data
	packet := processedPackets[0]
	if packet.Length() != len(testData) {
		t.Fatalf("Expected packet length %d, got %d", len(testData), packet.Length())
	}

	// Check metrics
	metrics := tun.Metrics()
	if metrics.PacketsReceived != 1 {
		t.Fatalf("Expected 1 packet received, got %d", metrics.PacketsReceived)
	}
	if metrics.BytesReceived != uint64(len(testData)) {
		t.Fatalf("Expected %d bytes received, got %d", len(testData), metrics.BytesReceived)
	}

	// Test writing a packet
	testPacket := core.NewCopiedPacket(testData)
	if err := tun.WritePacket(testPacket); err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	// Check if the packet was written
	writtenPackets := mockTun.GetWrittenPackets()
	if len(writtenPackets) != 1 {
		t.Fatalf("Expected 1 packet written, got %d", len(writtenPackets))
	}

	// Check metrics again
	metrics = tun.Metrics()
	if metrics.PacketsSent != 1 {
		t.Fatalf("Expected 1 packet sent, got %d", metrics.PacketsSent)
	}
	if metrics.BytesSent != uint64(len(testData)) {
		t.Fatalf("Expected %d bytes sent, got %d", len(testData), metrics.BytesSent)
	}

	// Stop the TUN device
	if err := tun.Stop(); err != nil {
		t.Fatalf("Failed to stop TUN device: %v", err)
	}
}

// TestMockTUNDeviceWithErrorProcessor tests the mock TUN device with a processor that returns an error
func TestMockTUNDeviceWithErrorProcessor(t *testing.T) {
	// Create a mock TUN device
	tun := NewMockTUNDevice("mock-tun", 1500)

	// Create a mock packet processor that returns an error
	processor := &mockPacketProcessor{shouldError: true}
	tun.SetPacketProcessor(processor)

	// Start the TUN device
	if err := tun.Start(); err != nil {
		t.Fatalf("Failed to start TUN device: %v", err)
	}

	// Simulate receiving a packet
	testData := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02}
	mockTun := tun.(*MockTUNDevice) // Type assertion to access mock-specific methods
	if err := mockTun.SimulatePacketReceived(testData); err != nil {
		t.Fatalf("Failed to simulate packet received: %v", err)
	}

	// Wait a bit for the packet to be processed
	time.Sleep(100 * time.Millisecond)

	// Check metrics
	metrics := tun.Metrics()
	if metrics.Errors != 1 {
		t.Fatalf("Expected 1 error, got %d", metrics.Errors)
	}

	// Stop the TUN device
	if err := tun.Stop(); err != nil {
		t.Fatalf("Failed to stop TUN device: %v", err)
	}
}

// TestTUNLoopback tests the TUN device by writing a packet and verifying it's received
func TestTUNLoopback(t *testing.T) {
	// Create a mock TUN device
	tun := NewMockTUNDevice("mock-tun-loopback", 1500)
	mockTun := tun.(*MockTUNDevice) // Type assertion to access mock-specific methods

	// Create a packet processor with a channel to signal when a packet is received
	packetReceived := make(chan struct{}, 1)
	processor := &mockPacketProcessor{
		packetReceived: packetReceived,
	}
	tun.SetPacketProcessor(processor)

	// Start the TUN device
	if err := tun.Start(); err != nil {
		t.Fatalf("Failed to start TUN device: %v", err)
	}

	// Create a test packet (IPv4 ICMP echo request)
	testData := []byte{
		// IPv4 header
		0x45, 0x00, 0x00, 0x54, // Version, IHL, Type of Service, Total Length
		0x00, 0x00, 0x40, 0x00, // Identification, Flags, Fragment Offset
		0x40, 0x01, 0x00, 0x00, // TTL, Protocol (ICMP), Header Checksum
		0x0a, 0x00, 0x00, 0x01, // Source IP (10.0.0.1)
		0x0a, 0x00, 0x00, 0x02, // Destination IP (10.0.0.2)

		// ICMP header
		0x08, 0x00, 0x00, 0x00, // Type (Echo Request), Code, Checksum
		0x00, 0x01, 0x00, 0x01, // Identifier, Sequence Number

		// ICMP payload (32 bytes)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	// Simulate receiving a packet
	if err := mockTun.SimulatePacketReceived(testData); err != nil {
		t.Fatalf("Failed to simulate packet received: %v", err)
	}

	// Wait for the packet to be received or timeout
	select {
	case <-packetReceived:
		// Packet was received, check if it matches
		processedPackets := processor.GetProcessedPackets()
		if len(processedPackets) == 0 {
			t.Fatalf("No packets received")
		}

		// Check the packet data
		packet := processedPackets[0]
		packetData := packet.Data()

		// Log the received packet for debugging
		t.Logf("Received packet of length %d", packet.Length())

		// Check if the packet length matches
		if packet.Length() != len(testData) {
			t.Fatalf("Expected packet length %d, got %d", len(testData), packet.Length())
		}

		// Check if the packet data matches
		for i := 0; i < len(testData); i++ {
			if packetData[i] != testData[i] {
				t.Fatalf("Packet data mismatch at index %d: expected %02x, got %02x", i, testData[i], packetData[i])
			}
		}

		t.Logf("Packet data matches")

		// Check metrics
		metrics := tun.Metrics()
		t.Logf("TUN Metrics - Packets Received: %d, Bytes Received: %d",
			metrics.PacketsReceived, metrics.BytesReceived)

		if metrics.PacketsReceived != 1 {
			t.Fatalf("Expected 1 packet received, got %d", metrics.PacketsReceived)
		}

		if metrics.BytesReceived != uint64(len(testData)) {
			t.Fatalf("Expected %d bytes received, got %d", len(testData), metrics.BytesReceived)
		}

	case <-time.After(2 * time.Second):
		// Timeout, no packet received
		t.Fatalf("No packet received within timeout")
	}

	// Test writing a packet
	testPacket := core.NewCopiedPacket(testData)
	if err := tun.WritePacket(testPacket); err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	// Check if the packet was written
	writtenPackets := mockTun.GetWrittenPackets()
	if len(writtenPackets) != 1 {
		t.Fatalf("Expected 1 packet written, got %d", len(writtenPackets))
	}

	// Check metrics
	metrics := tun.Metrics()
	t.Logf("TUN Metrics - Packets Sent: %d, Bytes Sent: %d",
		metrics.PacketsSent, metrics.BytesSent)

	if metrics.PacketsSent != 1 {
		t.Fatalf("Expected 1 packet sent, got %d", metrics.PacketsSent)
	}

	if metrics.BytesSent != uint64(len(testData)) {
		t.Fatalf("Expected %d bytes sent, got %d", len(testData), metrics.BytesSent)
	}

	// Stop the TUN device
	if err := tun.Stop(); err != nil {
		t.Fatalf("Failed to stop TUN device: %v", err)
	}
}
