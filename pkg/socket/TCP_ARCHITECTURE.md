# TCP responsibility boundaries

This refactoring preserves userspace TCP/UDP forwarding, admission policy,
protocol behavior, public APIs and existing lock ownership. It adds no network
privileges or runtime configuration.

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
  the contract in [LIFECYCLE.md](../../LIFECYCLE.md) still applies.

## Bounded performance gate

Before examining measurements, the gate for `BenchmarkTCPHandleACK` is fixed:
no added allocations or bytes per operation, and at most a 25% increase in the
median of five 300 ms runs on the same one-CPU contained environment. A failure
requires investigation, not changing the threshold to fit the result. Compare
the original handler to the final extraction; record both measurements here.

This benchmark isolates established-flow ACK dispatch, locking, window/recovery
and diagnostic decisions. It is not a host-dial benchmark or a forwarding
throughput claim. The subsequent bounded throughput, latency-distribution, allocation and sampled
memory comparison is recorded in [PERFORMANCE.md](../../PERFORMANCE.md). It passed
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
