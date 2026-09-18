package socket

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/irctrakz/wgslirp/pkg/core"
	"github.com/irctrakz/wgslirp/pkg/logging"
)

const ipv4MinHeaderSize = 20

// SocketWriter is an interface for writing packets to a socket
type SocketWriter interface {
	WritePacket(packet core.Packet) error
}

// SocketPacketProcessor implements core.PacketProcessor
type SocketPacketProcessor struct {
	// The socket interface
	socket  SocketWriter
	buffers PacketBufferReserver

	// Worker pool
	workerCount int
	packetCh    chan queuedPacket
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	started     bool
	stopped     bool
	stopOnce    sync.Once

	// Metrics
	packetsProcessed uint64
	packetsDropped   uint64
	queueFullDrops   uint64
}

type queuedPacket struct {
	packet  core.Packet
	release func()
}

func (q queuedPacket) close() {
	core.ReleasePacket(q.packet)
	q.release()
}

// NewSocketPacketProcessor creates a new socket packet processor
func NewSocketPacketProcessor(socket SocketWriter, workerCount int) core.PacketProcessor {
	if workerCount <= 0 {
		workerCount = 4
	}
	// Env overrides for workers and queue capacity.
	if v := strings.TrimSpace(os.Getenv("PROCESSOR_WORKERS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			workerCount = n
		}
	}
	qcap := 1000
	if v := strings.TrimSpace(os.Getenv("PROCESSOR_QUEUE_CAP")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			qcap = n
		}
	}

	return &SocketPacketProcessor{
		socket:      socket,
		buffers:     PacketBufferBudgetFor(socket),
		workerCount: workerCount,
		packetCh:    make(chan queuedPacket, qcap),
		stopCh:      make(chan struct{}),
	}
}

// Start starts the packet processor
func (p *SocketPacketProcessor) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return fmt.Errorf("packet processor stopped; create a new instance")
	}
	if p.started {
		return fmt.Errorf("packet processor already started")
	}
	if p.socket == nil {
		return fmt.Errorf("packet processor requires a socket writer")
	}
	p.started = true
	// Start the worker pool
	p.wg.Add(p.workerCount)
	for i := 0; i < p.workerCount; i++ {
		go p.worker(i)
	}

	logging.Infof("Socket packet processor started with %d workers", p.workerCount)
	return nil
}

// Stop stops the packet processor
func (p *SocketPacketProcessor) Stop() error {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.stopped = true
		close(p.stopCh)
		p.mu.Unlock()
		p.wg.Wait()
		// Accepted packets belong to this processor even if shutdown prevents
		// processing them. Drain and release; packetCh is never closed.
		for {
			select {
			case packet := <-p.packetCh:
				packet.close()
			default:
				return
			}
		}
	})

	logging.Infof("Socket packet processor stopped")
	return nil
}

// ProcessPacket implements core.PacketProcessor
func (p *SocketPacketProcessor) ProcessPacket(packet core.Packet) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started || p.stopped {
		return fmt.Errorf("packet processor not running")
	}
	if packet == nil {
		return fmt.Errorf("nil packet")
	}
	// Basic validation
	data := packet.Data()
	if len(data) < ipv4MinHeaderSize {
		atomic.AddUint64(&p.packetsDropped, 1)
		return fmt.Errorf("packet too short")
	}

	// Check IP version
	ver := data[0] >> 4
	if ver != 4 {
		atomic.AddUint64(&p.packetsDropped, 1)
		return fmt.Errorf("unsupported IP version: %d", ver)
	}

	// Admission transfers ownership only on success. A rejected packet remains
	// the caller's responsibility, including any pooled buffer.
	release, err := p.buffers.ReservePacketBuffer(core.PacketBufferSize(packet))
	if err != nil {
		atomic.AddUint64(&p.packetsDropped, 1)
		return err
	}
	select {
	case p.packetCh <- queuedPacket{packet: packet, release: release}:
		// Packet sent to worker pool
		atomic.AddUint64(&p.packetsProcessed, 1)
	default:
		release()
		// Channel is full, drop the packet
		atomic.AddUint64(&p.packetsDropped, 1)
		atomic.AddUint64(&p.queueFullDrops, 1)
		return fmt.Errorf("packet dropped: worker pool is full")
	}

	return nil
}

// worker processes packets from the channel
func (p *SocketPacketProcessor) worker(id int) {
	defer p.wg.Done()

	logging.Debugf("Socket packet processor worker %d started", id)

	for {
		select {
		case <-p.stopCh:
			logging.Debugf("Socket packet processor worker %d stopped", id)
			return
		case packet, ok := <-p.packetCh:
			if !ok {
				// Channel closed
				return
			}

			// Process the packet
			err := p.processQueuedPacket(packet)
			if err != nil {
				logging.Errorf("Failed to process packet in worker %d: %v", id, err)
			}
		}
	}
}

func (p *SocketPacketProcessor) processQueuedPacket(packet queuedPacket) error {
	// Keep storage charged until the synchronous writer returns, even though
	// dequeue has already made room for another entry.
	defer packet.release()
	return p.processPacketInternal(packet.packet)
}

// processPacketInternal processes a packet in a worker
func (p *SocketPacketProcessor) processPacketInternal(packet core.Packet) error {
	// Ensure any pooled packet buffer is released after processing completes.
	defer core.ReleasePacket(packet)
	// Forward the packet to the socket interface
	err := p.socket.WritePacket(packet)
	if err != nil {
		return fmt.Errorf("failed to write packet to socket: %v", err)
	}

	logging.Debugf("Forwarded packet to socket: length=%d", packet.Length())
	return nil
}

// Metrics returns metrics for the packet processor
func (p *SocketPacketProcessor) Metrics() map[string]uint64 {
	return map[string]uint64{
		"packetsProcessed": atomic.LoadUint64(&p.packetsProcessed),
		"packetsDropped":   atomic.LoadUint64(&p.packetsDropped),
		"queueFullDrops":   atomic.LoadUint64(&p.queueFullDrops),
	}
}
