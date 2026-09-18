package core

// TUNDevice represents a virtual network interface
type TUNDevice interface {
	// Name returns the name of the TUN device
	Name() string

	// MTU returns the Maximum Transmission Unit of the TUN device
	MTU() (int, error)

	// SetPacketProcessor sets the callback for processing packets from the TUN device
	SetPacketProcessor(processor PacketProcessor)

	// WritePacket writes a packet to the TUN device
	WritePacket(packet Packet) error

	// Start starts the TUN device
	Start() error

	// Stop stops the TUN device
	Stop() error

	// Metrics returns metrics for the TUN device
	Metrics() TUNMetrics
}

// PacketProcessor processes packets from a TUN device
type PacketProcessor interface {
	// ProcessPacket transfers ownership on success. Accepted pooled packets must
	// eventually be released. A rejecting producer releases its packet; a
	// synchronous consumer may already have released it before returning an error.
	ProcessPacket(packet Packet) error
}

// TUNMetrics contains metrics for a TUN device
type TUNMetrics struct {
	// PacketsReceived is the number of packets received from the TUN device
	PacketsReceived uint64

	// PacketsSent is the number of packets sent to the TUN device
	PacketsSent uint64

	// BytesReceived is the number of bytes received from the TUN device
	BytesReceived uint64

	// BytesSent is the number of bytes sent to the TUN device
	BytesSent uint64

	// Errors is the number of errors encountered
	Errors uint64
}
