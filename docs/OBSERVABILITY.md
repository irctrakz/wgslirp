# Observability and metrics

`SocketInterface.DetailedMetrics().Admission` and the JSON reporter's additive
`admission` object expose the same fixed set of cumulative counters. Text metrics
include an `admission:` line with the same names. Enable metrics with
`METRICS_LOG=true` or `METRICS_INTERVAL=30s` (explicit `METRICS_LOG=false` disables
reporting). Counters are owned by one socket interface, start at zero, survive
`Stop`, and are not reset by reporting. Snapshots are detached and safe to mutate.
Concurrent snapshots are individually race-safe, not a transaction across all
bridge counters. There are no peer addresses, flow identifiers or dynamic labels.

| Counter | Counted event | Operator guidance |
|---|---|---|
| `tcp_flow_limit` | A new TCP flow fails the active-flow cap, either before dialing or at the insertion recheck. | Inspect active flows, idle lifetime and `MAX_TCP_FLOWS`. |
| `udp_flow_limit` | A new UDP flow fails the active-flow cap. | Inspect active flows, idle lifetime and `MAX_UDP_FLOWS`. |
| `icmp_echo_limit` | A datagram echo request exceeds the fixed 1,024 pending-request cap. | Inspect echo rate and destination reachability; requests expire after five seconds. Existing requests are preserved. |
| `pending_dial_limit` | A SYN cannot reserve a dial slot, before any host dial. | Inspect host reachability/latency and `MAX_PENDING_TCP_DIALS`; fast and async fallback share one reservation. |
| `tcp_pending_limit` | Guest payload exceeds the flow's pre-connect pending-byte cap. | Inspect slow dials and `TCP_PEND_CAP_BYTES`. |
| `tcp_reassembly_limit` | New/merged out-of-order guest data exceeds the flow's unique-byte reassembly cap. | Inspect packet loss/reordering and `TCP_REASSEMBLY_CAP_BYTES`. |
| `aggregate_buffer_limit` | A valid reservation exceeds available shared buffer capacity. | Inspect `socket_buffer_bytes`, `socket_buffer_peak`, flow counts and `SOCKET_BUFFER_CAP_BYTES`; this includes bridge scratch, packet synthesis and downstream queues sharing this budget. |
| `invalid_buffer_request` | A reservation has a negative size or cannot represent its metadata charge. | Check the library caller's size/accounting logic; increasing limits will not fix it. |
| `tcp_retransmit_waits` | A flow transitions into an observed full retransmit-cap wait. | Inspect guest ACK progress/loss and `TCP_RETRANSMIT_CAP_BYTES`. This is backpressure, **not a drop/refusal**. Repeated polls while full do not increment it. A later observed recovery and new blockage starts another episode. |

Use changes between samples to diagnose pressure. Raising caps increases memory
or socket demand; investigate the cause and measure headroom before changing them.

## Units and counting ownership

Enabled IPv4 reassembly adds a separate fixed `IPv4Fragments` snapshot and optional
JSON `ipv4_fragments` object under schema version 1. Text uses `ipv4_fragments:`.
[Its counters and gauges](IPV4_FRAGMENT_REASSEMBLY.md) distinguish received
fragments, completions, duplicate/rejected/expired input and reserved storage.
Per-source/datagram/range refusals appear in its `rejected` counter; a failed
shared-budget reservation also increments `aggregate_buffer_limit`. Transport
counters count completed datagrams; accepted TUN byte counts include buffered
fragments. The object is absent when the feature is disabled.

Each failed admission check increments its owner exactly once. Wrappers, error
propagation, ACK scheduling and teardown do not repeat that count. Per-flow pending
and reassembly checks precede aggregate reservation, so the same requested payload
reservation is attributed to one limiting check. Fully duplicated reassembly data
does not reserve storage or produce a refusal. The early TCP flow-cap check returns
immediately; it cannot also fail the later insertion check on the same attempt.

These are **attempt counters**, not unique packets, clients or lost bytes. Repeated
SYNs or retried reservations are new attempts. In particular, a host reader waiting
for aggregate capacity can fail multiple reservation attempts for one eventual
read. If constructing an ACK/RST after a rejection also fails to reserve memory,
that is a separate `aggregate_buffer_limit` event; the original flow or per-flow
reason is not counted twice. Do not interpret a sum as a unique-packet drop count.
Standalone adapter budgets for custom writers are outside a socket interface's
shared-budget metrics. Queue-slot fullness is already reported by processor/TUN
queue metrics and is separate from these byte/flow/dial limits.

## Protocol behavior and compatibility

- TCP flow/dial-cap refusal keeps the existing best-effort RST/ACK response and
  `ErrFlowLimit` / `ErrDialLimit` result. It does not evict established flows.
- UDP flow-cap refusal keeps its best-effort ICMP destination-unreachable response
  and `ErrFlowLimit` result. Existing mappings continue forwarding. UDP error/refusal
  replies now reserve shared storage before synthesis and release it on delivery
  rejection, so their own allocation failures are visible and respect the budget.
- Pending/reassembly limits do not acknowledge refused payload bytes. Existing
  accepted data remains owned; ACKs request guest retransmission from the accepted
  sequence. Retransmit-cap pressure pauses host reads/sends until ACKs free space.
- Aggregate exhaustion retains existing behavior at each owner: decline/drop a
  queued packet, defer a host read, or reset a flow whose accepted bytes cannot be
  retained. Refusal responses are best effort and can themselves lack capacity.
- Existing JSON fields, `TCPExt` names, errors and queue metrics remain available.
  `tcp_ext.dial_refused` overlaps `pending_dial_limit`;
  `tcp_ext.socket_buffer_refused` overlaps aggregate plus invalid reservations.
  Legacy `buffer_dropped` and `pend_drop` also overlap subsets and can include
  non-admission failures. **Do not add legacy and new counters together.**

## Versioned reporting contract (F09)

JSON reports now include `schema_version: 1` and `wg_available`. Existing JSON
keys remain available, including legacy null objects. This is the first explicitly
versioned schema. Additive keys may appear; consumers should ignore unknown keys.
Existing field names remain stable, but the erroneous counting described below is
corrected; dashboards must not assume continuity with previously inflated totals.
Text reports identify the schema and WireGuard-state availability too.

Each periodic reporter owns its previous RTO sample. The first delta is the
current cumulative value; a decrease is treated as a counter reset and the delta
is the new value. Independent reporters never consume each other's history.
One-shot reports have no previous sample. Counters are not reset by reporting.

WireGuard monitoring and reporting use the same peer-state parser. Each peer
section is counted once, including peers that have never completed a handshake.
Unknown fields and malformed numeric values are ignored; device secrets are not
retained by the parser. Never-handshaken peers are stale. Freshness uses the
larger of 60 seconds and three keepalive intervals. Future handshake timestamps
have age zero. Oldest/newest ages cover completed handshakes only; zero can mean
no completed handshakes. `wg_available=false` means the device/state was
unavailable, not that the device has no peers. Host statistics that cannot be read
are omitted from `srv_limits`; text displays `unavailable` instead of a false zero.

## Packet, byte, failure and lifecycle units

| Field | Counting boundary |
| --- | --- |
| `total.pkts_sent` / `bytes_sent` | IPv4 frames dispatched to a supported bridge with a nil result by the running public socket write path, and their declared IP length (headers included, padding excluded). TCP control packets and consumed retransmissions count. This is not proof of delivery to the host. |
| `tcp` / `udp` `pkts_sent` / `bytes_sent` | Successful host socket write operations and payload bytes, excluding guest IP/transport headers. TCP reassembly/pending flushes may change the number of writes. UDP includes empty datagrams, which are now forwarded instead of silently skipped. These are not additive with the frame totals. |
| `total`, `tcp`, `udp` `pkts_recv` / `bytes_recv` | Synthesized frames accepted by the downstream packet processor and full frame bytes, including control/error replies attributed to their producing bridge. Retransmissions and UDP fragments are individual frames. Acceptance into a queue is not eventual wire delivery. |
| `tcp.delivery_refused` / `udp.delivery_refused` | Synthesized frames rejected by the downstream delivery collaborator. Allocation refusal before a frame exists remains in admission/buffer metrics. |
| `total.errors` | Failures of running public writes, unsupported protocols consumed without forwarding, and handled/background bridge failures. Returned bridge errors are counted once at the public boundary. Direct bridge calls do not increment public write-failure counts. |
| `tcp.errors` / `udp.errors` | Errors returned by the bridge plus handled/background failures owned by it. These overlap total errors; do not sum them. Delivery refusal is counted separately. Normal close/cancellation is not a read error. |
| `conns_created` / `conns_closed` | Cumulative admitted flow insertion/removal, not dial attempts. Closed TIME-WAIT host sockets can still occupy active TCP flow slots. |
| `tcp_active` / `udp_active` | Current registry entries. Snapshots are race-safe, not transactional across every field. |
| `wg.plaintext_from_wg` | IPv4 bytes accepted by successful TUN writes, including overlay forwarding. Earlier successes survive a later failure in the same batch. |
| `wg.plaintext_to_wg` | Bytes accepted into the TUN read queue, counted once on enqueue. Reading a queued frame does not count it again. |
| `wg.queue_drops` | TUN enqueue failures from queue-slot or retained-byte admission limits. |
| `udp.tx_enq` / `udp.tx_proc` | Frame delivery attempts / accepted deliveries, scoped to one socket interface. |

`errors` is not an exhaustive packet-loss count: admission refusals, downstream
rejections, retransmissions and resource-driven resets have separate counters
where documented. Do not infer successful delivery from a zero error count.

The public total outbound frame counters no longer also add TCP/UDP host payload
writes. Queue saturation tracks consecutive `ErrQueueFull` outcomes in serialized
injection order; the maximum updates when a failure occurs, and success or another
error ends the current streak. Burst and maximum counts are cumulative. Snapshot
maps are detached. `ResetMetrics` uses atomic stores, but resetting several fields
is not an atomic transaction and resets can intentionally discard concurrent work.

## Dependencies, diagnostics and probes

`core.PacketWriter` and `core.PacketBufferReserver` define the neutral borrowing
and reservation contracts; the existing `socket` names are compatibility aliases.
The TUN still uses the socket budget factory for its compatible finite fallback,
but its writer and reservation collaborators use neutral interfaces.
TCP/UDP bridges expose private dial/delivery collaborators for focused tests.
Their constructors launch no maintenance workers; the socket lifecycle explicitly
starts reaping/health work. Existing lifecycle ownership and stop bounds still
apply. TCP close-time checks already accept an explicit time for deterministic
fixtures. No generic scheduler or packet framework is introduced.

`wireguard.ErrQueueFull` identifies queue-slot saturation with `errors.Is`;
reservation failures remain distinct. Worker errors preserve the wrapped writer
cause. Repetitive socket read/deadline, ICMP parse, processor write, TCP close-expiry and host
socket-option warnings are limited to one per 30 seconds per owning limiter;
metrics continue counting every event. Existing periodic health/handshake logs and
one-time capture/MTU warnings retain their existing bounds.

Accepted guest frames above the configured `WG_MTU` produce no warning. The
additive schema-1 `packet_size` map and text line expose cumulative
`accepted_oversized` and `local_size_rejected` counters. Accepted size uses the
original frame's declared IPv4 length, excludes padding, and counts fragments at
their original sizes. Retention of an incomplete fragment is acceptance, not a
completed datagram or proof of remote delivery. Malformed, unsupported and
refused input does not increment the accepted counter. Debug logging optionally
reports accepted oversize events.

An actual local host size rejection (`EMSGSIZE`) increments
`local_size_rejected`, preserves the operating-system cause and returns packet
size context plus advice to reduce datagram size or check the host path MTU.
The executable's existing TUN error logger emits that specific failure; no
duplicate warning is emitted. Other errors retain their own reason without
speculative MTU advice. The rejected counter applies regardless of configured
MTU. Library callers remain responsible for logging returned errors. Neither
counter detects silent drops elsewhere in the network.

Startup health probes are one-shot diagnostics of direct host egress and slirp DNS.
They are not a persistent liveness/readiness endpoint or a proof of sustained
forwarding. The health tee exposes the primary processor's metrics without
resetting or hiding them. No endpoint is added without a deployment requirement.


The optional socket worker processor retains `packetsProcessed` as the legacy
queue-admission counter. Additive `packetsDelivered`, `writeErrors`, and
`shutdownDropped` distinguish successful writer completions, failed writes, and
queued work discarded at shutdown. `packetsDropped` / `queueFullDrops` describe
pre-enqueue rejection. These counters are not interchangeable. The metrics
reporter consumes narrow snapshot/state interfaces; sampling and emission are
separate, so fixtures require no live WireGuard device or socket bridge.
