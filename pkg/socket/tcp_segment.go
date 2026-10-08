package socket

import (
	"encoding/binary"
	"fmt"
)

// tcpSegment is a borrowed view of a validated IPv4/TCP packet. No handler
// retains its slices; asynchronous dial failures copy their bounded quote.
type tcpSegment struct {
	pkt, payload         []byte
	ihl, tcpOff, dataOff int
	srcIP, dstIP         [4]byte
	srcPort, dstPort     uint16
	seq, ack             uint32
	flags                byte
	key                  string
}

const (
	fFIN = 0x01
	fSYN = 0x02
	fRST = 0x04
	fPSH = 0x08
	fACK = 0x10
)

// parseTCPSegment validates before exposing bounded borrowed header/payload views.
func parseTCPSegment(pkt []byte) (tcpSegment, error) {
	pkt, ihl, err := parseTransport(pkt, 6)
	if err != nil {
		return tcpSegment{}, err
	}

	var srcIP, dstIP [4]byte
	copy(srcIP[:], pkt[12:16])
	copy(dstIP[:], pkt[16:20])

	tcpOff := ihl
	dataOff := int((pkt[tcpOff+12] >> 4) * 4)
	if dataOff < 20 || len(pkt) < tcpOff+dataOff {
		return tcpSegment{}, fmt.Errorf("tcp: header length invalid")
	}
	flags := pkt[tcpOff+13]
	seq := binary.BigEndian.Uint32(pkt[tcpOff+4 : tcpOff+8])
	ack := binary.BigEndian.Uint32(pkt[tcpOff+8 : tcpOff+12])
	srcPort := binary.BigEndian.Uint16(pkt[tcpOff : tcpOff+2])
	dstPort := binary.BigEndian.Uint16(pkt[tcpOff+2 : tcpOff+4])
	payload := pkt[tcpOff+dataOff:]

	key := fmt.Sprintf("%d.%d.%d.%d:%d-%d.%d.%d.%d:%d",
		srcIP[0], srcIP[1], srcIP[2], srcIP[3], srcPort,
		dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort,
	)

	return tcpSegment{pkt: pkt, ihl: ihl, tcpOff: tcpOff, dataOff: dataOff,
		srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort,
		seq: seq, ack: ack, flags: flags, payload: payload, key: key}, nil
}
