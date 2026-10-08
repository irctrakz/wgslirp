# Performance engineering review (2026-10-07)

## Assessment

Reviewed source `18bf76b`, including packet ownership, WireGuard adapters, TCP
buffers/recovery, UDP readers, flow registries and IPv4 reassembly. The architecture
is already reasonably efficient and bounded. There are a few worthwhile candidates,
especially avoidable per-packet formatting and temporary storage, but no evidence
supports a broad data-structure rewrite or a promise of a large speedup.

This is an evaluation, not authorization to implement every candidate. Optimize
only when a representative paired comparison improves throughput or latency without
breaking ownership, protocol behavior, resource containment or readability.

## Measured context and limits

Existing [sustained evidence](POOLING_SUSTAINED_ACCEPTANCE.md) and the
[three-policy comparison](SELECTIVE_PACKET_POOLING.md) are more relevant than
isolated allocation counts. The latter's six full-pooling CPU profiles show:

| Function | Median share | Interpretation |
| --- | ---: | --- |
| `internal/runtime/syscall.Syscall6` | 36.25% flat | Socket operations across router, guest and echo endpoints |
| `runtime.memmove` | 2.46% flat | One copy helper across the fixture, not total copy cost |
| `runtime.duffcopy` | 4.62% flat | Another copy helper, including fixed-size structure copies |
| `runtime.memclrNoHeapPointers` | 1.35% flat | Memory clearing across the whole fixture |
| `runtime.mallocgc` | 5.81% cumulative | Allocation path, including its callees |
| `fmt.Sprintf` | 2.13% cumulative | Formatting across the whole fixture |
| `socket.parseTCPSegment` | 3.17% cumulative | TCP validation/tuple construction, including formatting |

[All 42 selected profile rows](PERFORMANCE_REVIEW_PROFILE_SAMPLES.csv) are retained
from [run 37697847115](https://github.com/irctrakz/wgslirp/actions/runs/37697847115).
That run uses source `7fcaa40` with the full-pooling policy files restored from
`90e4df7`; it is supporting evidence, not a new profile of the default-on source.
The router, encrypted guest and echo endpoints share one process and one CPU.
Nested cumulative percentages overlap and must not be added. A large cumulative
`writeToSocket` share is the complete forwarding path, not the cost of its copy.
These profiles do not isolate production router CPU or loss-heavy recovery cost.
`memmove` alone is not a total or upper bound on copying. A focused call-graph
review of the first full-pooling profile attributes 0.73 of its 0.79 seconds in
`duffcopy` to upstream WireGuard `StdNetBind.putMessages`, rather than the router's
TUN queue. This attribution is one profile, not a six-profile median. Do not
equate that dependency's message reset/reuse work with an avoidable payload copy.
Earlier [unpaced fragment allocation profiles](ENCRYPTED_FRAGMENTS.md) identified
upstream WireGuard message buffers as the largest sampled live allocation source.
That argues against assuming that further fragment-cache tuning will materially
reduce total process memory. Measure the deployed router separately before
changing dependency buffer policy or runtime GC settings.

## Candidates, in practical order

### 1. Avoid formatting diagnostics that will not be emitted

[`SocketInterface.WritePacket`](../pkg/socket/socket.go) constructs two IPv4
address strings with `fmt.Sprintf` on every accepted packet before calling
`logging.Debugf`. This work occurs at the normal quiet log level too; rejecting
the log entry cannot undo evaluation of its arguments.

Gate the diagnostic block on the logger's actual enabled level, using a narrow
logging helper if needed. Keep packet parsing and forwarding outside that block.
This removes work while retaining readable debug output and has little protocol
risk. First verify allocations/CPU in the full socket path: the existing ACK
benchmark enters the TCP bridge directly and does not exercise this logging block.
The 2.13% formatting profile share is not a forecast of this change's speedup.

### 2. Use a compact typed tuple for private flow lookups

[`parseTCPSegment`](../pkg/socket/tcp_segment.go) and
[`udpBridge.flowKey`](../pkg/socket/udp_bridge.go) format the IP/port tuple into
a string for each packet. The addresses and ports already exist as fixed-size
values. A comparable struct containing two `[4]byte` addresses and two `uint16`
ports could key the private maps directly; format the tuple only for diagnostics.

This is a clean data-structure improvement with a plausible allocation benefit,
not a measured throughput gain. It touches active-flow and pending-dial identity
paths, so preserve replacement identity, cancellation, admission and expiry
behavior, plus existing human-readable diagnostics. Do not replace the maps with
custom hashing or an elaborate cache. Benchmark established ACK/UDP lookup and
short-connection churn, then verify the encrypted mixed workload.

### 3. Evaluate reuse of TCP reader scratch

[`tcpBridge.reader`](../pkg/socket/tcp_runtime.go) allocates a buffer of up to
32 KiB for each read attempt, including attempts ending at its 250 ms deadline.
[`udpBridge.reader`](../pkg/socket/udp_bridge.go) already reuses one accounted
receive buffer for its lifetime. A similarly owned TCP scratch buffer could
avoid repeated bulk/idle allocations.

Keep the full retained capacity charged while the buffer exists, including idle
and ACK-wait periods. The current per-read release gives idle flows their budget
back; reuse trades that headroom for lower churn. At 64 default TCP flows,
32 KiB per flow is 2 MiB before other storage. Budget exhaustion must still allow
progress and shutdown. Measure bulk throughput and idle-allocation rate before
choosing this tradeoff; do not add a second global pool by default.

### 4. Audit one synchronous copy before redesigning asynchronous ownership

[`WGTun.writeToSocket`](../pkg/wireguard/wg_tun_wg.go) copies incoming bytes before
calling a synchronous writer. The documented
[`PacketWriter`](../pkg/core/socket.go) contract borrows only until return;
retaining consumers must copy. Borrowing the WireGuard input directly during that
call is therefore a credible experiment, provided every maintained transport and
custom-writer compatibility test obeys that contract. Retained pending TCP data,
reassembly data and asynchronous error quotes must keep their independent storage.

The reverse path copies synthesized packets into the TUN queue and then into
WireGuard-owned read buffers. Its first copy might eventually be avoided by an
explicit owned-packet enqueue path. That changes asynchronous lifetime, rejection,
close/drain and shared reservation accounting. It is a higher-risk project, not
a simple deletion: retain the public copying API and do not introduce unaccounted
or prematurely returned buffers. The whole-fixture copy-helper shares do not
attribute this boundary's cost; pursue it only if a router-isolated profile
demonstrates a consequential bottleneck.

### 5. Profile repeated SACK snapshots under loss before changing recovery

[`isSACKed`](../pkg/socket/tcp_recovery.go) copies the scoreboard for each lookup.
Recovery loops can invoke it repeatedly across the retransmission queue. One
stable snapshot per recovery pass might reduce copies under substantial loss,
while preserving locks and the state observed by that pass.

The clean mixed profiles do not prove this is expensive. Use the existing
loss/reordering fixtures with allocation profiles first. Preserve sequence wrap,
stale-block pruning, partial ACKs, retransmission order and concurrency guarantees.
Do not remove `stateMu`, `txMu` or `sackMu` as a performance shortcut.

## Structures and copies worth keeping

- Fixed IPv4 address arrays are compact values, with no address-object graph.
  Flow maps are suitable for the bounded default populations; sharding or lock-free
  maps have no demonstrated contention justification.
- IPv4 reassembly has 32 global datagrams, eight per source, fixed inline storage,
  128 compact ranges and bounded small-object reuse. It promotes payload storage
  once and returns completed storage directly rather than copying completion.
  Linear scans at these caps are understandable; trees add allocation and invariants.
- TCP out-of-order slices merge retained ranges, avoid allocation for covered
  duplicates and clear removed references. Adversarial contiguous arrivals can
  repeatedly copy merged data, but changing that representation also changes host
  write batching. Keep it unless reordering profiles show meaningful cost.
- Retransmission payload copies preserve bytes after the reusable host-read buffer
  changes. Removing them through shared slices would need carefully managed parent
  lifetimes and could retain large backing arrays for tiny outstanding segments.
- ACK processing clears popped payload references; teardown returns reservations.
  Compact metadata or ring queues may be useful at much larger windows, but are
  not justified by current evidence.
- UDP's 65,535-byte receive buffer per live reader supports large datagrams and
  fragmentation without truncation. A smaller MTU-sized buffer is not an equivalent
  optimization. At 256 default flows, this is about 16 MiB of deliberate storage.
- Bounded packet pooling, reservation before allocation, explicit release and
  reuse clearing are sound. More aggressive pooling, object arenas, unsafe code,
  reference-counted packet graphs or GC tuning would add complexity without a
  demonstrated deployment benefit.

## Tail-latency coverage worth adding before structural optimization

[`writeTCP`](../pkg/socket/tcp_runtime.go) performs a host write with a five-second
deadline while the flow state is held. The application forwards inline, and
[`WGTun.Write`](../pkg/wireguard/wg_tun_wg.go) dispatches each buffer synchronously.
A blocked host write therefore delays later packets in that batch. This is a
bounded behavior, not evidence of global starvation, but the clean echo profiles
do not establish latency isolation when an upstream stops reading.

A realistic follow-up is one deliberately backpressured upstream alongside short
requests and UDP, measuring unaffected traffic and shutdown. Keep the finite
deadline and all storage caps. Only redesign per-flow write dispatch if that
measurement shows a deployment-relevant problem; introducing asynchronous writes
changes admission, acknowledgment and ownership semantics and is not a cleanup.

## Recommendation

Start with disabled-debug formatting. Consider typed flow keys next if the paired
measurement supports them. Then profile reader scratch and the synchronous ingress
copy independently. Keep SACK/reassembly representation and asynchronous ownership
changes conditional on loss-specific or router-isolated evidence.

Use unchanged finite budgets and fresh counterbalanced processes. Check verified
throughput and TCP/UDP tail latency first, followed by CPU, allocation rate, heap/RSS,
capacity recovery and shutdown. Include idle-open connections and realistic loss,
not only clean bulk transfers. Retain adverse samples. If a candidate offers no
repeatable practical improvement, stop and keep the simpler existing implementation.
