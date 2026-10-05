# Opt-in IPv4 fragment reassembly

Status: implementation and acceptance in progress. Default enablement is deferred
until protocol, ownership, bounded workload and actual-image evidence is accepted.
All forwarding remains in userspace with the existing privilege requirements.

## Sequence

- [x] Attempt later TUN batch packets after a rejection; return the first error
  and count only accepted packets/bytes. Focused native TUN tests pass.
- [ ] Validate fragment headers independently of complete transport datagrams.
- [ ] Add bounded reassembly with explicit retained-buffer ownership and expiry.
- [ ] Integrate opt-in startup configuration, shutdown and fixed diagnostics.
- [ ] Validate malformed/overlapping/reordered/duplicate fragments, exhaustion,
  expiry and concurrent shutdown; fuzz boundaries and run race checks.
- [ ] Validate encrypted fragment traffic and floods alongside ordinary traffic
  in the actual non-root image, with resource and owned-cleanup gates.
- [ ] Review evidence before enabling support by default.

## Proposed containment

`IPV4_REASSEMBLY` defaults to false. A separate finite fragment storage ceiling
shares the existing aggregate socket buffer budget. Bound live datagrams,
datagrams per source and fragment ranges per datagram. Reserve the maximum
datagram storage and metadata before copying the first received fragment;
completion transfers that same allocation to synchronous transport dispatch.
Reservations include completed datagrams still being dispatched, and release
exactly once after dispatch, rejection, expiry or shutdown.

Keep stateless parsing in `internal/packetwire` and lifetime/state in `pkg/socket`.
Reassembly is independent of TCP stream reassembly and of overlay peer routing.
The cache key is source, destination, protocol and IP identification, scoped to
one socket interface. Peer identity is unavailable at this boundary; source
quotas are not per-user quotas. IPv4 options remain unsupported.

Use a fixed sixty-second lifetime from first arrival. Exact duplicates do not
extend it; conflicting overlaps discard the assembly. Preserve ECN congestion
marks, reject inconsistent headers/lengths, and validate transport checksums only
after completion. Counters distinguish fragment input from completed datagrams;
ordinary unfragmented traffic retains its existing metrics contract.

References: [RFC 1122 §3.3.2](https://www.rfc-editor.org/rfc/rfc1122.html#section-3.3.2),
[RFC 3168 §5.3](https://www.rfc-editor.org/rfc/rfc3168.html#section-5.3),
[RFC 8900](https://www.rfc-editor.org/rfc/rfc8900.html).
