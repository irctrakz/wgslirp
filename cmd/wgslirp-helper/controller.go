package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	goruntime "runtime"
	"syscall"

	"github.com/irctrakz/wgslirp/internal/application"
	"github.com/irctrakz/wgslirp/pkg/socket"
)

type managedRuntime interface {
	Status() (application.Status, error)
	AddPeer(string, netip.Addr) error
	RemovePeer(string) error
	Close() error
}

type controller struct {
	session     *session
	diagnostics io.Writer
	start       func(context.Context, application.Config, application.Observers) (managedRuntime, error)
	runtime     managedRuntime
	highID      uint64
	revision    uint64
}

type response struct {
	ID       uint64         `json:"id"`
	Op       string         `json:"op"`
	Instance string         `json:"instance_id"`
	Revision uint64         `json:"revision"`
	OK       bool           `json:"ok"`
	Result   any            `json:"result,omitempty"`
	Error    *responseError `json:"error,omitempty"`
}

type responseError struct {
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

func (c *controller) execute() (end completion) {
	s := c.session
	defer func() {
		if c.runtime != nil && c.runtime.Close() != nil {
			end.reply, end.failed = nil, true
		}
	}()
	for {
		select {
		case <-s.ctx.Done():
			return end
		case frame := <-s.requests:
			if s.ctx.Err() != nil {
				return end
			}
			reply, terminal := c.handle(frame)
			if terminal {
				return completion{reply: reply}
			}
			if s.ctx.Err() != nil {
				return end
			}
			if err, usable := s.respond(*reply); err != nil {
				failed := !usable || !errors.Is(err, s.ctx.Err())
				s.stop("", failed)
				return completion{failed: failed}
			}
		}
	}
}

func (c *controller) handle(frame object) (*response, bool) {
	s := c.session
	id, idOK := integer(frame["id"], 1, maxExactInteger)
	op, opOK := patterned(frame["op"], opPattern)
	if !idOK || !opOK {
		s.stop("invalid_frame", true)
		return nil, true
	}
	reply := &response{ID: id, Op: op, Instance: s.instance, Revision: c.revision}
	params, paramsOK := frame["params"].(object)
	if c.highID == 0 {
		supported, valid := helloVersions(params)
		if id != 1 || op != "hello" || !paramsOK || !exactFields(frame, "id", "op", "params") || !valid {
			s.stop("invalid_frame", true)
			return nil, true
		}
		c.highID = id
		if !supported {
			if !s.stop("", true) {
				return nil, true
			}
			return reply.reject("unsupported_version"), true
		}
		return reply.success(object{
			"version": 1, "binary_version": binaryVersion(), "os": goruntime.GOOS, "arch": goruntime.GOARCH,
			"capabilities": []string{"restricted_tcp", "live_peers"},
		}), false
	}
	if id <= c.highID {
		return reply.reject("duplicate_id"), false
	}
	c.highID = id
	instance, instanceOK := patterned(frame["instance_id"], instancePattern)
	if !exactFields(frame, "id", "op", "instance_id", "params") || !instanceOK || !paramsOK || op == "hello" {
		return reply.reject("invalid_request"), false
	}
	if instance != s.instance {
		return reply.reject("wrong_instance"), false
	}

	switch op {
	case "validate", "start":
		return c.configure(reply, params)
	case "status", "stop":
		if len(params) != 0 {
			return reply.reject("invalid_request"), false
		}
		if op == "stop" {
			if !s.stop("", false) {
				return nil, true
			}
			return reply.success(object{}), true
		}
		status, err := c.status()
		if err != nil {
			s.stop("runtime_state_uncertain", true)
			return nil, true
		}
		return reply.success(status), false
	case "peer_add", "peer_remove":
		return c.updatePeer(reply, params)
	default:
		return reply.reject("unknown_operation"), false
	}
}

func helloVersions(params object) (supported, valid bool) {
	versions, ok := params["versions"].([]any)
	if !ok || !exactFields(params, "versions") || len(versions) < 1 || len(versions) > 16 {
		return false, false
	}
	seen := make(map[uint64]bool, len(versions))
	for _, raw := range versions {
		version, ok := integer(raw, 1, 65535)
		if !ok || seen[version] {
			return false, false
		}
		seen[version] = true
	}
	return seen[1], true
}

func (c *controller) configure(reply *response, params object) (*response, bool) {
	cfg, mappings, ok := parseConfig(params)
	if !ok {
		return reply.reject("invalid_request"), false
	}
	if reply.Op == "start" && c.runtime != nil {
		return reply.reject("invalid_state"), false
	}
	policy, err := socket.NewDestinationPolicy(mappings)
	if err != nil {
		return reply.reject("invalid_config"), false
	}
	cfg.Socket.Destinations = policy
	if cfg.Validate() != nil {
		return reply.reject("invalid_config"), false
	}
	if reply.Op == "validate" {
		return reply.success(object{}), false
	}

	s := c.session
	startFailed := false
	markFailure := func() { startFailed = s.stop("", true) }
	cfg = helperConfig(cfg, c.diagnostics)
	c.runtime, err = c.start(s.ctx, cfg, application.Observers{
		RegisterForwardingStop: s.registerForwarding,
		StartFailed:            markFailure,
		StateUncertain:         func() { s.stop("runtime_state_uncertain", true) },
	})
	if err != nil {
		if !startFailed && !s.stop("", true) {
			return nil, true
		}
		reply.reject("start_failed")
		reply.Error.Reason = startupReason(err)
		return reply, true
	}
	if s.ctx.Err() != nil {
		return nil, true
	}
	status, err := c.status()
	if err != nil {
		s.stop("runtime_state_uncertain", true)
		return nil, true
	}
	if !c.publishRevision(reply) {
		return nil, true
	}
	return reply.success(object{"listen_port": status.ListenPort, "server_public_key": status.ServerPublicKey}), false
}

func (c *controller) status() (application.Status, error) {
	if c.runtime == nil {
		return (*application.Runtime)(nil).Status()
	}
	return c.runtime.Status()
}

func (c *controller) updatePeer(reply *response, params object) (*response, bool) {
	expected, revOK := integer(params["expected_revision"], 0, maxExactInteger)
	var p peer
	var ok bool
	if reply.Op == "peer_add" {
		p, ok = parsePeer(params["peer"])
		ok = ok && exactFields(params, "expected_revision", "peer")
	} else {
		p.key, ok = patterned(params["public_key"], keyPattern)
		ok = ok && exactFields(params, "expected_revision", "public_key")
	}
	if !revOK || !ok {
		return reply.reject("invalid_request"), false
	}
	if c.runtime == nil {
		return reply.reject("invalid_state"), false
	}
	if expected != c.revision {
		return reply.reject("revision_conflict"), false
	}
	s := c.session
	if c.revision == maxExactInteger {
		s.stop("runtime_state_uncertain", true)
		return nil, true
	}
	var err error
	if reply.Op == "peer_add" {
		err = c.runtime.AddPeer(p.key, p.address)
	} else {
		err = c.runtime.RemovePeer(p.key)
	}
	switch {
	case err == nil:
		if !c.publishRevision(reply) {
			return nil, true
		}
		return reply.success(object{}), false
	case errors.Is(err, application.ErrInvalidPeer):
		return reply.reject("invalid_config"), false
	case errors.Is(err, application.ErrPeerConflict):
		return reply.reject("peer_conflict"), false
	case errors.Is(err, application.ErrPeerLimit):
		return reply.reject("peer_limit"), false
	case errors.Is(err, application.ErrPeerNotFound):
		return reply.reject("peer_not_found"), false
	case errors.Is(err, application.ErrPeerUpdate):
		return reply.reject("peer_update_failed"), false
	default:
		s.stop("runtime_state_uncertain", true)
		return nil, true
	}
}

// The worker owns the runtime for teardown even if it loses the race to
// publish readiness or a peer revision.
func (c *controller) publishRevision(reply *response) bool {
	s := c.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return false
	}
	c.revision++
	reply.Revision = c.revision
	return true
}

func (r *response) success(result any) *response {
	r.OK, r.Result = true, result
	return r
}

func (r *response) reject(code string) *response {
	r.Error = &responseError{Code: code}
	return r
}

func startupReason(err error) string {
	// Go's Windows socket errors retain the native Winsock errno.
	const wsaAddressInUse, wsaAccess = syscall.Errno(10048), syscall.Errno(10013)
	switch {
	case errors.Is(err, syscall.EADDRINUSE), goruntime.GOOS == "windows" && errors.Is(err, wsaAddressInUse):
		return "address_in_use"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM), goruntime.GOOS == "windows" && errors.Is(err, wsaAccess):
		return "permission_denied"
	default:
		return "other"
	}
}
