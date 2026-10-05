# TCP responsibility boundaries

This refactoring preserves userspace TCP/UDP forwarding, admission policy,
protocol behavior, public APIs and existing lock ownership. It adds no network
privileges or runtime configuration.

## Further simplification (2026-10-04)

### Single-dial handoff

The fast wait and async completion now consume one unbuffered dial-result
channel. Crossing the fast-wait deadline neither cancels nor replaces the host
dial. A bridge-owned worker retains its reservation and undelivered socket;
successful channel delivery transfers socket ownership to the receiver. An
abandoned worker closes a late socket itself. Cancellation alone never releases
a still-running dial's reservation; shutdown joins both dial and completion
workers. The once-only release also permits a receiver to release promptly after
receiving the completed dial, preserving immediate admission accounting.

Default total dial time is five seconds from the original attempt. Explicit
fast waits greater than five seconds remain honored as the total deadline;
there is no second five-second attempt. Immediate failures retain configured
RST/ICMP/silent signaling before SYN-ACK. Async publication still owns the sole
initial SYN-ACK under `stateMu`; completion attaches only after that lock is
released, or closes its socket if the flow was removed. Pending bytes still
flush before host write-half-close. No existing lock is removed or reordered.

Tests control dial completion/cancellation with channels and cover one attempt,
one SYN-ACK, fast/async failure policies, reset/shutdown, late successful sockets,
SYN-ACK refusal, quote-budget failure, duplicate candidates and pending FIN.
The independent-peer mixed gate additionally requires zero empty host accepts
and exactly 130 payload connections. At `6a2b78b`,
[run 37246793917](https://github.com/irctrakz/wgslirp/actions/runs/37246793917)
passed build/vet, unit/integration race, fuzz, both modes of mixed/sustained/WAN/
capacity workloads, actual-image validation and same-digest development promotion.
The mixed race run exercised 46 async handoffs with zero empty host connections;
all owned-resource cleanup checks passed.

### Earlier private cleanup

`ed2a4d8` removes write-only retransmission flags (`rtx`, `pipeBytes`) and the
sole no-op `OnSent` callback. Actual retry counts still govern RTT sampling;
the local in-flight calculation still governs recovery. No lock, policy,
public API or protocol transition changed. Stale scheduler/watermark comments
now describe the actual ACK/window waits and retained-buffer budgets.

The new [independent-peer mixed gate](ENCRYPTED_MIXED.md) passed ordinary and
race execution. It also exposed the cost of fast-dial cancellation followed by
async redial: the accepted pair observed four and fifteen extra empty host
connections respectively. The single-dial handoff above addresses that residue;
the historical measurements remain in the workload document.

Keep the next changes independently reviewable:

1. Remove redundant `ccEnabled` state if non-nil `cc` fully represents the
   existing enabled condition in all constructors and tests.
2. Consolidate `clientMSS` and `mss` after distinguishing negotiated peer size
   from the dynamic bridge clamp and advertised SYN-ACK MSS. Preserve those
   distinct meanings and public diagnostics.
3. Simplify repeated dial accounting and host-write error handling only where
   metric timing, byte ownership and lock scope remain explicit.

Retain the existing lock boundaries and independent protocol fixtures. A shorter
function or fewer files alone is not evidence of a simpler state machine.

### Conservative lock audit

Overlapping `stateMu`, `txMu`, `sackMu` and related locks are audit candidates,
not presumed redundant. Before proposing removal, enumerate every protected
field's reader/writer, publication and teardown path, callback/re-entry path,
and lock acquisition order. Explain what invariant the lock currently preserves
and how that invariant survives all asynchronous paths without it. Review timer,
retransmission, diagnostics and shutdown interactions explicitly.

Require focused interleaving/cancellation/shutdown regressions and independent
review of that argument. A race-detector pass is supporting evidence, not proof
that the lock has no second-order purpose. Keep any lock whose role remains
uncertain; harmless redundant locking is preferable to an unproven simplification.
The current cleanup removes no locks and changes no lock ownership.

## Policy consolidation and establishment cleanup (2026-10-02)

The hardcoded 30-second health monitor is removed. `tcp_stall.go` supplies one
ACK-idle predicate for sender gating, metrics and the existing 15-second reaper.
Failure uses the configured gate, in-flight threshold and failure deadline;
zero gate disables ACK-idle handling, and zero failure timeout retains gating
without ACK-idle closure. This intentionally corrects the old monitor overriding
those settings. Advancing ACKs and opening windows count as progress; duplicate
ACKs with an unchanged window do not. FIN/TIME-WAIT and ordinary idle expiry
retain their separate policies. The maintenance pass only expires established
flows and rechecks state under the flow lock.

Establishment now has one initial SYN-ACK owner under the newly published
candidate's state lock. Async completion must acquire that lock: it either sees
successful delivery or a closed candidate, so its duplicate SYN-ACK branch and
the `synAckSent` flag are removed. MSS derivation and fast/async failure signaling
are shared helpers. Fast refusal, async timeout/cancellation, pending flushing,
per-flow locking and reservation release retain their ordering.

Focused local regressions pass for deadline/disabled/threshold behavior,
zero-window and window-opening behavior, advancing ACKs, TIME-WAIT exclusion,
sender/maintenance signaling, fast/async failure and exactly one SYN-ACK.
Existing dial cancellation, duplicate-candidate and rejected-delivery tests also
pass. Linux build/vet, race unit/integration, fuzzing and actual-image validation
passed in [CI run 37050502529](https://github.com/irctrakz/wgslirp/actions/runs/37050502529)
for `fb18c23` (following policy commit `1084361`). The non-root, capability-free
image forwarded encrypted TCP/UDP and exited zero on SIGTERM in 76 ms, with no
OOM/PID-limit events and verified cleanup. The same tested digest was promoted.
The earlier performance measurements below are not reruns of this change.

## Extraction sequence

1. Connection establishment and pending-write flushing (`tcp_connect.go`).
2. Registry, admission, expiry and shutdown (`tcp_registry.go`).
3. Validated incoming segments (`tcp_segment.go`), state dispatch and payload/FIN
   handling (`tcp_receive.go`), with bounded reassembly in `tcp_buffers.go`.
4. ACK/window handling and delayed ACK scheduling (`tcp_ack.go`), plus SACK
   and RTO recovery (`tcp_recovery.go`). Reader/segmentation stay in `tcp_runtime.go`.
5. Diagnostic snapshots and formatting (`tcp_diagnostics.go`); the socket facade
   requests TCP metrics through `snapshotMetrics` instead of reading TCP internals.

Each boundary is a separate local commit, with the tagged integration/race suite
as its behavior gate. Existing tests cover dial refusal/timeouts/cancellation,
duplicate candidates, admission, pending FIN flushing, teardown, ACK/SACK loss,
sequence wrap, encrypted forwarding and flow churn. Preserve independent packet
fixtures; do not replace them with tests that merely mirror extracted helpers.

## Ownership rules

- `HandleOutbound` admits one operation through `beginWork`; its deferred error
  counter update runs before `workers.Done`, including delegated handlers.
- Packet views borrow validated input only for the synchronous call. An async
  dial owns a separately reserved, copied ICMP quote.
- Dialing holds neither the registry lock nor a flow lock. Candidate publication
  takes candidate `stateMu` before the registry lock. A duplicate candidate closes
  its own connection and processes the existing flow before releasing its dial
  reservation. Async handoff retains its existing once-only release/cancel path.
- Existing-flow handling owns `stateMu`. Pending flush holds it through bounded
  host writes, reassembly flush, CloseWrite and reservation release.
- Registry snapshots release the registry lock before taking any flow's
  `stateMu`. Removal rechecks object identity, protecting tuple replacements.
- Flow state may acquire the registry, pending/reassembly/transmit/SACK or
  diagnostics locks. Do not introduce a reverse acquisition path or perform
  cross-flow diagnostic snapshots while holding one flow's state lock.
- Workers and timers stay bridge-owned and join on shutdown. Lock extraction
  does not permit callbacks to synchronously re-enter locked flow operations;
  the contract in [LIFECYCLE.md](LIFECYCLE.md) still applies.

## Bounded performance gate

Before examining measurements, the gate for `BenchmarkTCPHandleACK` is fixed:
no added allocations or bytes per operation, and at most a 25% increase in the
median of five 300 ms runs on the same one-CPU contained environment. A failure
requires investigation, not changing the threshold to fit the result. Compare
the original handler to the final extraction; record both measurements here.

This benchmark isolates established-flow ACK dispatch, locking, window/recovery
and diagnostic decisions. It is not a host-dial benchmark or a forwarding
throughput claim. The subsequent bounded throughput, latency-distribution, allocation and sampled
memory comparison is recorded in [PERFORMANCE.md](PERFORMANCE.md). It passed
the preselected loopback regression budgets; deployment-scale evidence remains F10.

Baseline (original handler, Go 1.23.12, one CPU): five runs measured 646.7,
651.6, 654.7, 658.1 and 693.1 ns/op; median **654.7 ns/op**, **34 B/op**,
**2 allocs/op**. The preselected latency ceiling is **818.375 ns/op**.
Baseline vet passed, peak container memory 365,428,736 bytes; zero resource-limit
events and independent zero-owned-residue check.

Final extraction measurements were 672.0, 671.6, 679.5, 689.4 and 697.3 ns/op;
median **679.5 ns/op** (+3.79%), with **34 B/op** and **2 allocs/op** unchanged.
The preselected gate passed; this is a small benchmark comparison, not proof of
statistically significant slowdown or full forwarding performance equivalence.
Final vet/benchmark peak was 367,788,032 bytes, with zero resource-limit events
and independent zero-owned-residue verification.

Reproduce inside the documented bounded Linux test environment:

```sh
go test -run='^$' -bench='^BenchmarkTCPHandleACK$' -benchmem -benchtime=300ms -count=5 -timeout=30s ./pkg/socket
```

All five structural stages passed the complete tagged integration suite with the
race detector, including ordinary unit tests, encrypted WireGuard TCP/UDP, churn,
concurrent snapshots and lifecycle/protocol regressions. Each stage restored the
remote pause guards and independently verified removal of its owned resources.
The architecture plan records per-stage evidence. Production packet encoding
now uses `internal/packetwire`, with allocation and reservation ownership retained
by the socket layer. Shared IPv4/transport validation also lives there, with
socket error compatibility retained by local wrappers (PR 4.2). PR 4.4 removed
uncalled private helpers and unused TCP state. The former send-gate logger had no
callers; its configuration remains accepted as a deprecated inactive setting.
Active ACK, handshake, admission-failure and RTO diagnostics retain their behavior.
The bounded PR 4.3 performance comparison is complete; independent review and
broader deployment performance/release evidence remain separate work.
