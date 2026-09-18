# Admission metrics

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
| `pending_dial_limit` | A SYN cannot reserve a dial slot, before any host dial. | Inspect host reachability/latency and `MAX_PENDING_TCP_DIALS`; fast and async fallback share one reservation. |
| `tcp_pending_limit` | Guest payload exceeds the flow's pre-connect pending-byte cap. | Inspect slow dials and `TCP_PEND_CAP_BYTES`. |
| `tcp_reassembly_limit` | New/merged out-of-order guest data exceeds the flow's unique-byte reassembly cap. | Inspect packet loss/reordering and `TCP_REASSEMBLY_CAP_BYTES`. |
| `aggregate_buffer_limit` | A valid reservation exceeds available shared buffer capacity. | Inspect `socket_buffer_bytes`, `socket_buffer_peak`, flow counts and `SOCKET_BUFFER_CAP_BYTES`; this includes bridge scratch, packet synthesis and downstream queues sharing this budget. |
| `invalid_buffer_request` | A reservation has a negative size or cannot represent its metadata charge. | Check the library caller's size/accounting logic; increasing limits will not fix it. |
| `tcp_retransmit_waits` | A flow transitions into an observed full retransmit-cap wait. | Inspect guest ACK progress/loss and `TCP_RETRANSMIT_CAP_BYTES`. This is backpressure, **not a drop/refusal**. Repeated polls while full do not increment it. A later observed recovery and new blockage starts another episode. |

Use changes between samples to diagnose pressure. Raising caps increases memory
or socket demand; investigate the cause and measure headroom before changing them.

## Units and counting ownership

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

This change adds admission diagnostics only. General packet/error counter cleanup,
reporter-owned interval state and broader metrics contracts remain architectural
F09 work.
