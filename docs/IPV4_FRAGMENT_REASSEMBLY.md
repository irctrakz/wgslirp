# Opt-in IPv4 fragment reassembly

Status: implemented and accepted as an opt-in feature. Default enablement remains
a separate deployment-evidence review.
All forwarding remains in userspace with the existing privilege requirements.

## Sequence

- [x] Attempt later TUN batch packets after a rejection; return the first error
  and count only accepted packets/bytes. Focused native TUN tests pass.
- [x] Validate fragment headers independently of complete transport datagrams.
- [x] Add bounded reassembly with explicit retained-buffer ownership and expiry.
- [x] Integrate opt-in startup configuration, shutdown and fixed diagnostics.
- [x] Validate malformed/overlapping/reordered/duplicate fragments, exhaustion,
  expiry and concurrent shutdown; fuzz boundaries and run race checks.
- [x] Validate encrypted fragment traffic and floods alongside ordinary traffic
  in the actual non-root image, with resource and owned-cleanup gates.
- [ ] Review evidence before enabling support by default.

## Configuration and containment

`IPV4_REASSEMBLY` defaults to false. A separate finite fragment storage ceiling
shares the existing aggregate socket buffer budget. Bound live datagrams,
datagrams per source and fragment ranges per datagram. Reserve the maximum
datagram storage and metadata before copying the first received fragment.
Small assemblies use inline storage; a range beyond 2,048 wire bytes promotes
once to full storage, with both tiers covered by that same reservation.
Completion transfers the active storage tier to synchronous transport dispatch.
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
At the fixed global limit, fragment reservations total at most 2,228,192 bytes;
one source can reserve at most 557,048 bytes. The byte cap may reduce admission
further but cannot expand those fixed quotas.
The quota is shared by sources across peers; it is not an authenticated-peer quota.

TCP, UDP and ICMP fragments are eligible; other protocols remain unsupported.
Options, DF combined with fragmentation, empty payloads, invalid header checksums,
non-final payload lengths not divisible by eight, oversize offsets, conflicting
final lengths, overlapping ranges and inconsistent DSCP/ECN fail closed.
Byte-identical ranges with matching final flags are duplicates, consume no extra
storage and do not extend expiry. IPv4 checksum/total length/fragment flags are
rebuilt on completion, then the existing transport validator checks the result.
Duplicate suppression is scoped to a live assembly. There is no completed-ID
replay cache: late fragments after dispatch may start an incomplete assembly,
which is subject to the same quotas and expiry.
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
Admission reasons and peaks add `source_limit`, `global_limit`, `storage_limit`,
`aggregate_limit`, `live_peak` and `source_peak`; see
[expanded encrypted evidence and fairness scope](ENCRYPTED_FRAGMENTS.md).

## Acceptance evidence

At `8054f40bfa0975ddb5712f171a2a8bb06e45c5e0`,
[run 37359184215](https://github.com/irctrakz/wgslirp/actions/runs/37359184215)
passed Linux build/vet, unit/race, integration-race, three ten-second fuzz stages,
both modes of all mixed/sustained/WAN/capacity workloads, and both actual-image
subtests. Native focused tests and a 537,517-case ten-second reassembly fuzz run
also passed; native Windows checks are supplemental to Linux acceptance.
The separate development-tag promotion job remained queued without a runner at
19:27 UTC; this is not an overall completed-CI claim. The tested candidate digest
and current promotion status are recorded in [RELEASE_IMAGE_TEST.md](RELEASE_IMAGE_TEST.md).

The actual image ran as UID 100 with all capabilities dropped, read-only root,
1 CPU, 256 MiB memory/no swap and 128 PIDs. Enabled-mode evidence records:

- Forty incomplete IDs retained exactly eight assemblies / 557,048 bytes.
- 223 verified ordinary TCP/UDP rounds continued during the sixty-second expiry.
- All eight assemblies expired, fragment reservations returned to zero, and
  reordered/duplicate fragmented TCP/UDP worked afterward.
- SIGTERM under fragmented traffic exited zero in 85 ms; default mode exited
  zero in 69 ms and preserved the sixteen-failure log-aggregation regression.
- Enabled runtime cgroup memory peak was 53,407,744 bytes; default mode recorded
  26,750,976 bytes. These workloads differ in duration and traffic volume; the
  values are bounded observations, not a direct memory-overhead comparison.
- All memory/PID-limit events were zero. Owned containers, networks, builder,
  cache volume and local tested image were removed; GHCR candidates are retained.

Initial CI [run 37359016545](https://github.com/irctrakz/wgslirp/actions/runs/37359016545)
stopped at a new lifecycle test's unintended default ICMP socket mode on the
unprivileged Linux runner. Its fixture now selects ordinary TCP sockets, matching
the existing lifecycle tests; image construction and promotion were skipped.

## Remaining default-enablement work

The completed race/fuzz and actual-image gates establish opt-in acceptance.
Before changing the default:

The [expanded profile](ENCRYPTED_FRAGMENTS.md) declares workload/resource criteria
before acceptance and records its separate default-policy decision.
Its finite-uplink ordinary/race profiles and full image/promotion pipeline passed
in [run 37376714607](https://github.com/irctrakz/wgslirp/actions/runs/37376714607).
The evidence records RSS retention, quota recovery, profiling and cleanup, plus
the still-unresolved unpaced failure. Default-policy review remains separate,
and the default is false.

- [x] Expand bounded encrypted evidence to realistic MTU-sized fragments and
  larger datagrams, mixed short/bulk/UDP traffic, loss/reordering and multiple
  sources competing for the global quota.
- [x] Measure sustained allocation/RSS and recovery across repeated expiry,
  late duplicates and quota saturation; retain the current resource/cleanup gates.
- [ ] Complete the separately sequenced [reassembly allocation-churn and
  unpaced encrypted acceptance work](ENCRYPTED_FRAGMENTS.md#remaining-work-allocation-churn-and-unpaced-acceptance).
  Finite-rate acceptance above does not resolve the original unpaced failures.
  [Allocation-churn implementation and measurements](REASSEMBLY_ALLOCATION_CHURN.md)
  track the storage change and its separate acceptance gates.
- [ ] Review deployment counters and per-source fairness, then make a separate
  default-policy change preserving an explicit `IPV4_REASSEMBLY=false` escape hatch.

The feature does not promise reliable forwarding of every possible fragmented
IPv4 stream. Raising a byte budget does not resolve the fixed range/source quotas.

References: [RFC 1122 §3.3.2](https://www.rfc-editor.org/rfc/rfc1122.html#section-3.3.2),
[RFC 3168 §5.3](https://www.rfc-editor.org/rfc/rfc3168.html#section-5.3),
[RFC 8900](https://www.rfc-editor.org/rfc/rfc8900.html).
