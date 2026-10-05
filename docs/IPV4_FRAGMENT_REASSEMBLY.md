# Opt-in IPv4 fragment reassembly

Status: implementation and acceptance in progress. Default enablement is deferred
until protocol, ownership, bounded workload and actual-image evidence is accepted.
All forwarding remains in userspace with the existing privilege requirements.

## Sequence

- [x] Attempt later TUN batch packets after a rejection; return the first error
  and count only accepted packets/bytes. Focused native TUN tests pass.
- [x] Validate fragment headers independently of complete transport datagrams.
- [x] Add bounded reassembly with explicit retained-buffer ownership and expiry.
- [x] Integrate opt-in startup configuration, shutdown and fixed diagnostics.
- [ ] Validate malformed/overlapping/reordered/duplicate fragments, exhaustion,
  expiry and concurrent shutdown; fuzz boundaries and run race checks.
- [ ] Validate encrypted fragment traffic and floods alongside ordinary traffic
  in the actual non-root image, with resource and owned-cleanup gates.
- [ ] Review evidence before enabling support by default.

## Configuration and containment

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

Enable with `IPV4_REASSEMBLY=true`, or `socket.Config.IPv4Reassembly` for library
callers. `IPV4_FRAGMENT_BUFFER_CAP_BYTES` defaults to 4 MiB; zero selects that
finite default. Negative values fail startup, and enabled support requires room
for at least one 69,631-byte reservation. The existing aggregate socket budget
can refuse admission earlier. Increasing the fragment byte cap does not increase
the fixed limits: 32 live datagrams per interface, 8 per source and 128 disjoint
ranges per datagram. Reservations count completed datagrams during dispatch.
The quota is shared by sources across peers; it is not an authenticated-peer quota.

TCP, UDP and ICMP fragments are eligible; other protocols remain unsupported.
Options, DF combined with fragmentation, empty payloads, invalid header checksums,
non-final payload lengths not divisible by eight, oversize offsets, conflicting
final lengths, overlapping ranges and inconsistent DSCP/ECN fail closed.
Byte-identical ranges with matching final flags are duplicates, consume no extra
storage and do not extend expiry. IPv4 checksum/total length/fragment flags are
rebuilt on completion, then the existing transport validator checks the result.
Timeout sends best-effort ICMP Time Exceeded code 1 when fragment zero exists,
unless its source/destination or ICMP type suppresses error feedback. Feedback
uses the same finite aggregate budget and ordinary packet delivery interface.
No kernel fragment queues, raw sockets, added capabilities or sysctl writes are
introduced. Existing ICMP forwarding capability requirements are unchanged.

Text metrics expose `ipv4_fragments:`; JSON adds optional `ipv4_fragments` under
schema version 1. Fields are `received`, `completed`, `duplicates`, `rejected`,
`expired`, `cached`, `live`, `reserved_bytes` and `limit_bytes`. Received/rejected
include recognizable fragment headers failing validation. Buffered fragments are
accepted TUN frames; transport packet/byte metrics count completed datagrams.
Cache metadata is bounded separately; reserved bytes include a conservative
metadata allowance and do not represent process RSS or garbage awaiting GC.

## Default-enablement gate

Initial CI [run 37359016545](https://github.com/irctrakz/wgslirp/actions/runs/37359016545)
stopped at a new lifecycle test's unintended default ICMP socket mode on the
unprivileged Linux runner. Its fixture now selects ordinary TCP sockets, matching
the existing lifecycle tests; image construction and promotion were skipped.

Keep support off until the complete race/fuzz suite and both actual-image modes
pass. The enabled image must forward reordered/duplicate encrypted TCP/UDP,
reject overlaps, contain a forty-datagram flood at eight retained assemblies,
continue ordinary traffic during expiry, restore fragment admission afterward,
and terminate cleanly under traffic. Preserve the existing memory/PID event and
owned-image/network cleanup gates. Review production memory, timeout and
per-source fairness evidence separately before changing the default; the feature
does not promise reliable forwarding of every possible fragmented IPv4 stream.

References: [RFC 1122 §3.3.2](https://www.rfc-editor.org/rfc/rfc1122.html#section-3.3.2),
[RFC 3168 §5.3](https://www.rfc-editor.org/rfc/rfc3168.html#section-5.3),
[RFC 8900](https://www.rfc-editor.org/rfc/rfc8900.html).
