package socket

import (
	"context"
	"errors"
	"net"
	"sync"
)

var ErrPeerInactive = errors.New("guest source is not active")

// peerWork owns admission and work for one source address. Closing admission
// serializes with both worker creation and publication of dial results.
type peerWork struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	work   sync.WaitGroup
	conns  map[*net.TCPConn]struct{} // guarded by mu, independent of flow state locks
}

func (p *peerWork) begin() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return false
	}
	p.work.Add(1)
	return true
}

// EnablePeerAdmission enables source ownership for a restricted socket.
// The application calls it before Start, including when there are no peers.
func (s *SocketInterface) EnablePeerAdmission() {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peers == nil {
		s.peers = make(map[[4]byte]*peerWork)
	}
}

// AdmitPeerSource publishes an address whose WireGuard ownership was verified.
func (s *SocketInterface) AdmitPeerSource(source [4]byte) {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peers[source] == nil {
		ctx, cancel := context.WithCancel(context.Background())
		s.peers[source] = &peerWork{ctx: ctx, cancel: cancel, conns: make(map[*net.TCPConn]struct{})}
	}
}

// QuiescePeerSource closes admission and interrupts host I/O. The caller
// must retire the source before reopening it after a verified failed update.
func (s *SocketInterface) QuiescePeerSource(source [4]byte) {
	s.peerMu.Lock()
	p := s.peers[source]
	s.peerMu.Unlock()
	if p == nil {
		return
	}
	p.mu.Lock()
	p.cancel()
	// Host writes can hold a flow lock while WireGuard waits for the
	// receive worker. Close without acquiring any flow lock.
	for conn := range p.conns {
		_ = conn.Close()
	}
	p.mu.Unlock()
}

// RetirePeerSource joins admitted work and releases the source's state.
// The application serializes peer changes and quiesces the source first.
func (s *SocketInterface) RetirePeerSource(source [4]byte) {
	s.peerMu.RLock()
	p := s.peers[source]
	s.peerMu.RUnlock()
	if p == nil {
		return
	}
	// TCP is the only transport admitted by the restricted socket.
	for _, flow := range s.tcp.flowSnapshot() {
		if flow.srcIP == source {
			s.tcp.removeFlowIf(flow, nil)
		}
	}
	p.work.Wait()
	if s.fragments != nil {
		s.fragments.retireSource(source)
	}
	s.peerMu.Lock()
	delete(s.peers, source)
	s.peerMu.Unlock()
}

func (r *ipv4Fragments) retireSource(source [4]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, datagram := range r.entries {
		if key.src == source {
			delete(r.entries, key)
			r.releaseLocked(datagram)
		}
	}
	delete(r.denials, source)
}
