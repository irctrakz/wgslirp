package tun

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

// MockTUNDevice is a mock implementation of core.TUNDevice for testing
// that doesn't require kernel access or elevated privileges.
type MockTUNDevice struct {
	name           string
	mtu            int
	processor      core.PacketProcessor
	running        bool
	stopCh         chan struct{}
	wg             sync.WaitGroup
	metrics        core.TUNMetrics
	packetCh       chan []byte
	mu             sync.Mutex
	packetsWritten [][]byte
}

// NewMockTUNDevice creates a new mock TUN device for testing
func NewMockTUNDevice(name string, mtu int) core.TUNDevice {
	return &MockTUNDevice{
		name:     name,
		mtu:      mtu,
		stopCh:   make(chan struct{}),
		packetCh: make(chan []byte, 100), // Buffer for incoming packets
		metrics:  core.TUNMetrics{},
	}
}

// Name returns the name of the TUN device
func (m *MockTUNDevice) Name() string {
	return m.name
}

// MTU returns the Maximum Transmission Unit of the TUN device
func (m *MockTUNDevice) MTU() (int, error) {
	return m.mtu, nil
}

// SetPacketProcessor sets the callback for processing packets from the TUN device
func (m *MockTUNDevice) SetPacketProcessor(processor core.PacketProcessor) {
	m.processor = processor
}

// WritePacket writes a packet to the TUN device
func (m *MockTUNDevice) WritePacket(packet core.Packet) error {
	// Get the packet data
	data := packet.Data()

	// Make a copy of the data to avoid any race conditions
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// Store the packet for inspection in tests
	m.mu.Lock()
	m.packetsWritten = append(m.packetsWritten, dataCopy)
	m.mu.Unlock()

	// Update metrics
	atomic.AddUint64(&m.metrics.PacketsSent, 1)
	atomic.AddUint64(&m.metrics.BytesSent, uint64(len(data)))

	logging.Debugf("Mock TUN device %s wrote packet of length %d", m.name, len(data))

	return nil
}

// Start starts the TUN device
func (m *MockTUNDevice) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("TUN device already running")
	}

	m.running = true

	// Start the read loop
	m.wg.Add(1)
	go m.readLoop()

	logging.Infof("Mock TUN device started: %s", m.name)

	return nil
}

// Stop stops the TUN device
func (m *MockTUNDevice) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	// Signal the read loop to stop
	close(m.stopCh)

	// Wait for the read loop to finish
	m.wg.Wait()

	m.running = false

	logging.Infof("Mock TUN device stopped: %s", m.name)

	return nil
}

// Metrics returns metrics for the TUN device
func (m *MockTUNDevice) Metrics() core.TUNMetrics {
	return core.TUNMetrics{
		PacketsSent:     atomic.LoadUint64(&m.metrics.PacketsSent),
		BytesSent:       atomic.LoadUint64(&m.metrics.BytesSent),
		PacketsReceived: atomic.LoadUint64(&m.metrics.PacketsReceived),
		BytesReceived:   atomic.LoadUint64(&m.metrics.BytesReceived),
		Errors:          atomic.LoadUint64(&m.metrics.Errors),
	}
}

// readLoop reads packets from the packet channel
func (m *MockTUNDevice) readLoop() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopCh:
			return
		case data := <-m.packetCh:
			// Update metrics
			atomic.AddUint64(&m.metrics.PacketsReceived, 1)
			atomic.AddUint64(&m.metrics.BytesReceived, uint64(len(data)))

			// Process the packet
			if m.processor != nil {
				packet := core.NewPacket(data)
				if err := m.processor.ProcessPacket(packet); err != nil {
					logging.Errorf("Failed to process packet: %v", err)
					atomic.AddUint64(&m.metrics.Errors, 1)
				}
			}
		}
	}
}

// SimulatePacketReceived simulates receiving a packet from the TUN device
// This is used for testing to inject packets into the mock TUN device
func (m *MockTUNDevice) SimulatePacketReceived(data []byte) error {
	m.mu.Lock()
	running := m.running
	m.mu.Unlock()

	if !running {
		return fmt.Errorf("TUN device not running")
	}

	// Make a copy of the data to avoid any race conditions
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// Send the packet to the packet channel
	select {
	case m.packetCh <- dataCopy:
		logging.Debugf("Mock TUN device %s received packet of length %d", m.name, len(data))
		return nil
	default:
		// Channel is full, drop the packet
		atomic.AddUint64(&m.metrics.Errors, 1)
		return fmt.Errorf("packet channel full, packet dropped")
	}
}

// GetWrittenPackets returns the packets that have been written to the TUN device
// This is used for testing to verify that packets were written correctly
func (m *MockTUNDevice) GetWrittenPackets() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Make a copy to avoid any race conditions
	result := make([][]byte, len(m.packetsWritten))
	for i, packet := range m.packetsWritten {
		result[i] = make([]byte, len(packet))
		copy(result[i], packet)
	}

	return result
}

// ClearWrittenPackets clears the list of packets that have been written to the TUN device
// This is used for testing to reset the state between tests
func (m *MockTUNDevice) ClearWrittenPackets() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.packetsWritten = nil
}
