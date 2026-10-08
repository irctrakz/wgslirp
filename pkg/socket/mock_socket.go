package socket

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

// MockSocketInterface is a mock implementation of the SocketInterface for testing
type MockSocketInterface struct {
	// Configuration
	config Config

	// Packet processor for handling packets from the socket
	processor core.PacketProcessor

	// Metrics
	metrics core.SocketMetrics

	// Control
	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Mock-specific fields
	receivedPackets []core.Packet
	sentPackets     []core.Packet
}

// Ensure MockSocketInterface implements both required interfaces
var _ core.SocketInterface = (*MockSocketInterface)(nil)
var _ SocketWriter = (*MockSocketInterface)(nil)

// NewMockSocketInterface creates a new mock socket interface
func NewMockSocketInterface(config Config) *MockSocketInterface {
	return &MockSocketInterface{
		config:          config,
		metrics:         core.SocketMetrics{},
		stopCh:          make(chan struct{}),
		receivedPackets: make([]core.Packet, 0),
		sentPackets:     make([]core.Packet, 0),
	}
}

// Start starts the mock socket interface
func (m *MockSocketInterface) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("socket interface already running")
	}

	if m.processor == nil {
		return fmt.Errorf("no packet processor set")
	}

	m.running = true
	logging.Infof("Mock socket interface started with IP: %s", m.config.IPAddress)
	return nil
}

// Stop stops the mock socket interface
func (m *MockSocketInterface) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	close(m.stopCh)
	m.wg.Wait()
	m.running = false

	logging.Infof("Mock socket interface stopped")
	return nil
}

// SetPacketProcessor sets the packet processor for handling packets from the socket
func (m *MockSocketInterface) SetPacketProcessor(processor core.PacketProcessor) {
	m.processor = processor
}

// WritePacket writes a packet to the mock socket
func (m *MockSocketInterface) WritePacket(packet core.Packet) error {
	m.mu.Lock()
	running := m.running
	m.mu.Unlock()

	if !running {
		return fmt.Errorf("socket interface not running")
	}

	// Get the packet data
	data := packet.Data()

	// Store the packet
	m.mu.Lock()
	m.sentPackets = append(m.sentPackets, core.NewPacket(append([]byte(nil), data...)))
	m.mu.Unlock()

	// Update metrics
	atomic.AddUint64(&m.metrics.PacketsSent, 1)
	atomic.AddUint64(&m.metrics.BytesSent, uint64(len(data)))

	logging.Debugf("Mock socket sent packet of length %d", len(data))
	return nil
}

// Metrics returns the metrics for the mock socket interface
func (m *MockSocketInterface) Metrics() core.SocketMetrics {
	return m.metrics
}

// SimulatePacketReceived simulates receiving a packet from the network
// This is a test-only method that doesn't exist in the real implementation
func (m *MockSocketInterface) SimulatePacketReceived(packet core.Packet) error {
	m.mu.Lock()
	running := m.running
	processor := m.processor
	m.mu.Unlock()

	if !running {
		return fmt.Errorf("socket interface not running")
	}

	if processor == nil {
		return fmt.Errorf("no packet processor set")
	}

	// Store the packet
	m.mu.Lock()
	m.receivedPackets = append(m.receivedPackets, packet)
	m.mu.Unlock()

	// Update metrics
	atomic.AddUint64(&m.metrics.PacketsReceived, 1)
	atomic.AddUint64(&m.metrics.BytesReceived, uint64(len(packet.Data())))

	// Process the packet
	if err := processor.ProcessPacket(packet); err != nil {
		atomic.AddUint64(&m.metrics.Errors, 1)
		return fmt.Errorf("failed to process packet: %v", err)
	}

	logging.Debugf("Mock socket received packet of length %d", len(packet.Data()))
	return nil
}

// GetSentPackets returns all packets that have been sent through the mock socket
// This is a test-only method that doesn't exist in the real implementation
func (m *MockSocketInterface) GetSentPackets() []core.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy to avoid race conditions
	packets := make([]core.Packet, len(m.sentPackets))
	copy(packets, m.sentPackets)
	return packets
}

// GetReceivedPackets returns all packets that have been received by the mock socket
// This is a test-only method that doesn't exist in the real implementation
func (m *MockSocketInterface) GetReceivedPackets() []core.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy to avoid race conditions
	packets := make([]core.Packet, len(m.receivedPackets))
	copy(packets, m.receivedPackets)
	return packets
}
