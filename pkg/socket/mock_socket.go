package socket

import (
	"context"
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
	mu       sync.Mutex
	running  bool
	stopped  bool
	stopDone chan struct{}
	stopCh   chan struct{}
	wg       sync.WaitGroup

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
		config:          config.Effective(),
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

	if m.stopped {
		return fmt.Errorf("socket interface stopped; create a new instance")
	}
	if m.running {
		return fmt.Errorf("socket interface already running")
	}

	if m.processor == nil {
		return fmt.Errorf("no packet processor set")
	}

	if err := m.config.Validate(); err != nil {
		return fmt.Errorf("socket config: %w", err)
	}
	m.running = true
	logging.Infof("Mock socket interface started with IP: %s", m.config.IPAddress)
	return nil
}

// Stop joins accepted work; callbacks must use RequestStop without waiting.
func (m *MockSocketInterface) Stop() error { return m.StopContext(context.Background()) }

func (m *MockSocketInterface) StopContext(ctx context.Context) error {
	done := m.RequestStop()
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RequestStop has the same callback-safe completion contract as SocketInterface.
func (m *MockSocketInterface) RequestStop() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return m.stopDone
	}
	m.stopped, m.running = true, false
	m.stopDone = make(chan struct{})
	close(m.stopCh)
	go func() { m.wg.Wait(); close(m.stopDone) }()
	return m.stopDone
}

// SetPacketProcessor configures delivery only before startup.
func (m *MockSocketInterface) SetPacketProcessor(processor core.PacketProcessor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running || m.stopped {
		logging.Warnf("Mock socket packet processor can only be configured before startup")
		return
	}
	m.processor = processor
}

// WritePacket writes a packet to the mock socket
func (m *MockSocketInterface) WritePacket(packet core.Packet) error {
	m.mu.Lock()
	running := m.running
	if running {
		m.wg.Add(1)
	}
	m.mu.Unlock()

	if !running {
		return fmt.Errorf("socket interface not running")
	}
	defer m.wg.Done()
	if packet == nil {
		return fmt.Errorf("nil packet")
	}

	// Get the packet data
	data := core.BorrowPacketData(packet)

	// Store the packet
	m.mu.Lock()
	m.sentPackets = append(m.sentPackets, core.NewCopiedPacket(data))
	m.mu.Unlock()

	// Update metrics
	atomic.AddUint64(&m.metrics.PacketsSent, 1)
	atomic.AddUint64(&m.metrics.BytesSent, uint64(len(data)))

	logging.Debugf("Mock socket sent packet of length %d", len(data))
	return nil
}

// Metrics returns the metrics for the mock socket interface
func (m *MockSocketInterface) Metrics() core.SocketMetrics {
	return loadSocketMetrics(&m.metrics)
}

// SimulatePacketReceived simulates receiving a packet from the network
// Ownership transfers to the processor on success; on error the caller retains
// ownership. The recorded history is a detached copy, including after release.
func (m *MockSocketInterface) SimulatePacketReceived(packet core.Packet) error {
	m.mu.Lock()
	running := m.running
	if running {
		m.wg.Add(1)
	}
	processor := m.processor
	m.mu.Unlock()

	if !running {
		return fmt.Errorf("socket interface not running")
	}
	defer m.wg.Done()
	if packet == nil {
		return fmt.Errorf("nil packet")
	}

	if processor == nil {
		return fmt.Errorf("no packet processor set")
	}

	// Copy before the callback can consume/release the packet.
	data := core.CopyPacketData(packet)
	size := len(data)
	m.mu.Lock()
	m.receivedPackets = append(m.receivedPackets, core.NewBorrowedPacket(data))
	m.mu.Unlock()

	// Update metrics
	atomic.AddUint64(&m.metrics.PacketsReceived, 1)
	atomic.AddUint64(&m.metrics.BytesReceived, uint64(size))

	// Process the packet
	if err := processor.ProcessPacket(packet); err != nil {
		atomic.AddUint64(&m.metrics.Errors, 1)
		return fmt.Errorf("failed to process packet: %w", err)
	}

	logging.Debugf("Mock socket received packet of length %d", size)
	return nil
}

// GetSentPackets returns all packets that have been sent through the mock socket
// This is a test-only method that doesn't exist in the real implementation
func (m *MockSocketInterface) GetSentPackets() []core.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy to avoid race conditions
	packets := make([]core.Packet, len(m.sentPackets))
	for i, packet := range m.sentPackets {
		packets[i] = core.NewCopiedPacket(core.BorrowPacketData(packet))
	}
	return packets
}

// GetReceivedPackets returns all packets that have been received by the mock socket
// This is a test-only method that doesn't exist in the real implementation
func (m *MockSocketInterface) GetReceivedPackets() []core.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy to avoid race conditions
	packets := make([]core.Packet, len(m.receivedPackets))
	for i, packet := range m.receivedPackets {
		packets[i] = core.NewCopiedPacket(core.BorrowPacketData(packet))
	}
	return packets
}
