# Hardening, benchmarking and simplicity review — 2026-09-30

Assessed source: `3fe622ca65185b60db3bfdd1bc54f9718a50a967` on
`codex/architecture-hardening`. This is the current remaining-work summary;
the architecture plan and earlier assessment retain their historical evidence.
Independent code review and verified branch protections are assumed satisfied,
as requested. They are not remaining tasks.

## Judgment

**The principal resource, ownership and lifecycle hardening is implemented and
meaningfully tested. Release-artifact assurance is still unfinished. Benchmark
acceptance is established for specific bounded profiles, not for arbitrary WAN
load or sustained encrypted throughput. Code simplicity remains mixed.**

The earlier Strong ratings for KISS, DRY and readability were generous. Splitting
TCP into responsibility files improved navigation, but did not eliminate duplicate
branches, overlapping policy or obsolete state. For those three principles this
review assesses the remaining TCP work as Partial. This is a targeted revision,
not a newly calculated score across all 30 principles. There is no defensible
single percentage complete or basis for declaring the entire system Excellent.

Core TCP/UDP forwarding remains ordinary userspace sockets with an in-memory
WireGuard TUN. Nothing recommended here requires kernel routing, a kernel TUN,
root, or additional capabilities. Optional ICMP has a separate permission and
activation contract and must not broaden the default TCP/UDP privilege profile.

## Evidence and progress

This review inspected code, contracts, workflows and recorded results. It did
not run Go tests, benchmarks, containers or remote workloads. A read-only GitHub
API check returned no Actions runs for this development branch and no check runs
for the assessed HEAD. The source prerelease has no release assets. These facts
do not invalidate the recorded controlled tests, but provide no evidence that
the actual release-image gate has executed.

| Area | Current position | Limit of the evidence |
| --- | --- | --- |
| F01–F09 hardening | Typed validation, finite admission and memory budgets, ownership, lifecycle joins, TCP recovery/close behavior, metrics and responsibility extraction implemented | Remaining API and simplicity issues below still matter |
| F11/F12 containment | Bounded stages, resource monitoring, cleanup and negative controls implemented and exercised | No authorization or justification for unbounded/overnight testing |
| Latest ICMP merge | Sep 30 ordinary and race unit/integration, build/module verification, amd64/arm64 compilation, vet and workflow/shell checks passed | Component tests are not release-image startup/shutdown tests |
| ICMP fallback | Live capability-free ping-socket echo test required success; failure, limit, correlation and shutdown cases covered | Executable still selects TCP/UDP; raw ICMP deployment validation is separate |
| IPv6 defaults | Default sysctl writes removed; documented explicit compatibility opt-in retained | Hardened actual-image verification remains open |
| F10 baseline | Bounded loopback TCP/UDP and capacity/churn profiles accepted | Not a production/WAN/encrypted saturation claim |
| A1 / F10e.2 | Revised finite low-rate encrypted natural-GC acceptance passed in three ordinary and three race runs | Original tighter guard failed; larger profiles remain unproven |
| A2 release artifact | Runtime fixture/workflow implemented | Execution, artifact promotion and rollback evidence incomplete |

The latest four controlled stages recorded no memory/OOM/PID-limit events and
no owned residue after cleanup. Their largest cgroup peak, 924,692,480 bytes,
includes compiler/cache activity; it is not application RSS. Details remain in
[RELEASE_VALIDATION.md](RELEASE_VALIDATION.md).

### What the benchmark numbers actually say

From [PERFORMANCE.md](PERFORMANCE.md), five samples of the specified small
loopback profile:

- TCP median payload throughput: 26.890 → 27.870 MB/s; UDP: 51.690 → 54.048 MB/s.
  These passed acceptance, but do not establish statistically reliable speedups.
- TCP handshake p95 increased 30.13%, within the declared 35% threshold, with
  only eight handshakes per sample. This deserves measurement at meaningful
  handshake volume before any latency claim.
- UDP sampled heap increased 56.69%, from 1.383 to 2.168 MiB, within the absolute
  allowance; RSS was stable. Allocation counts were essentially unchanged.
  This is not evidence of a general allocation improvement.
- ACK microbenchmark time increased 3.79%; its 34 B/op and two allocations
  remained. The gate passed; the extraction was not a speed optimization.
- Default 64 TCP slots include four-minute TIME-WAIT. Roughly 16 host-first
  closes/minute consumes that steady-state capacity without headroom. The
  128-connection churn fixture used injected expiry, not elapsed-wall-clock soak.

From [ENCRYPTED_WORKLOADS.md](ENCRYPTED_WORKLOADS.md), the accepted profile uses
one TCP and one UDP encrypted link, a 90-second maximum, natural GC and exact
payload checks. Ordinary peak RSS was about 21 MiB; race runs reached roughly
243–248 MiB against a 256 MiB ceiling. Recorded drops/reordering exercised
recovery, but RTO count was zero: this does not demonstrate encrypted RTO-under-loss
recovery. The failed historical tight-guard experiment remains failed.

The current release tag `v0.1.0-dev.20260922` points to `3e38464`, before the ICMP
merge and documentation relocation. Choose the exact candidate deliberately;
testing that tag would not validate all code reviewed here.

## Remaining work, ordered by impact

**Implementation update (2026-10-02):** development-branch CI now builds once,
pulls/tests the candidate by digest and promotes that same manifest in a dependent
job. See [RELEASE_IMAGE_TEST.md](RELEASE_IMAGE_TEST.md). Actual execution remains
pending; R1/R2 are not closed. The master publisher, input pinning, invalid-config
image coverage and rollback evidence remain separate work.

Only unfinished work is listed. Each item should be a bounded, reviewable change;
do not combine the list into a general rewrite.

- [ ] **R1 — Close actual release-image assurance (A2; runtime part of A3).**
  Run the existing fixture against an explicitly selected candidate image with
  non-root identity, dropped capabilities, no-new-privileges, read-only root,
  explicit writable mounts and resource/deadline limits. Assert encrypted
  TCP/UDP forwarding and SIGTERM under traffic. Add invalid-config startup
  coverage. Record immutable image identity and cleanup evidence. The private
  server's previous restrictions are not relaxed by this review.
- [ ] **R2 — Make release publication consume the tested artifact (A2).**
  The current publisher rebuilds after Go checks; it does not promote the image
  that passed the runtime fixture. Gate promotion on that fixture, identify the
  tested digest, pin build inputs/toolchain with a documented update/scanning
  policy, and retain/test a bounded rollback path. Development pushes currently
  do not trigger the master-only push workflow; make the intended validation
  path explicit. Assumed branch protections do not supply artifact testing.
- [ ] **R3 — Unify TCP stall policy and simplify establishment (C1/C2 below).**
  First resolve competing timeout semantics with focused tests; then remove
  duplicated SYN-ACK work while preserving fast-refusal/asynchronous-dial
  behavior. These are higher-value simplifications than further file splitting.
- [ ] **R4 — Finish packet ownership semantics (A4; C4).**
  Correct the ICMP borrowed-data mutation, introduce explicit debug-independent
  copy/borrow paths where missing, migrate maintained callers, and preserve or
  deliberately deprecate the old public behavior. Verify aliasing, rejection,
  retention and exactly-once release at both debug settings.
- [ ] **R5 — Complete deployment guidance and optional ICMP policy (A3).**
  Remove private-key echo from README; show the tested hardened deployment.
  Explain executable TCP/UDP selection versus library ICMP and ping-socket/raw
  socket requirements. Decide which optional raw mode is supported and validate
  that scope, or explicitly exclude it. Do not reopen completed sysctl work.
- [ ] **R6 — Expand bounded workload evidence (A5 / remaining F10e).**
  Prioritize encrypted churn/cap sizing and meaningful handshake samples, then
  calibrated delay/loss/reordering with actual RTO and receiver-reneging cases.
  Include elapsed-wall-clock expiry; run full-sequence scenarios only when
  justified by supported workload claims. Declare duration/load/memory/failure
  criteria before each stage and stop on failure. No overnight tests. Recheck
  representative performance after the TCP simplifications.
- [ ] **R7 — Remove proven internal residue (C3/C5/C6).**
  Delete unused private state/methods/no-op callbacks and stale comments in one
  small change. Audit lock ownership before removing nested locks or snapshots.
  Retire the stress CLI only after preserving any unique bounded assertion.
- [ ] **R8 — Establish compatibility policy before larger deletions (A6/C7).**
  Add a concise changelog and API/config/metrics deprecation policy, including
  release-to-image mapping. Decide explicitly whether legacy exported adapters
  remain supported; repository-local non-use alone is insufficient evidence.

R5 and the proven-private subset of R7 are inexpensive and can be handled while
R1's execution environment is being arranged. No new framework, generic flow
registry, reference counting or configurable algorithm family is required.

## Ruthless simplicity review

### C1 — Two TCP stall policies compete

[tcp_registry.go](../pkg/socket/tcp_registry.go) runs a 15-second health monitor
which removes established flows after 30 seconds without ACK progress when at
least 1 KiB is in flight. [tcp_runtime.go](../pkg/socket/tcp_runtime.go) separately
applies configurable ACK-idle gate/failure policy (defaults six/120 seconds),
with different thresholds and reset signaling.

The hardcoded monitor can close a qualifying flow before the configured failure
timeout, including when that failure option is disabled. This is active overlap,
not harmless dead code. Use one explicit stalled-flow policy and maintenance
owner. Test disabled/custom thresholds, ACK progress, zero-window behavior,
signaling and stop before changing it. Keep distinct protocol RTO, FIN,
TIME-WAIT and lifecycle expiry semantics; those are not interchangeable timers.

### C2 — TCP establishment was moved, not sufficiently simplified

[tcp_connect.go](../pkg/socket/tcp_connect.go) still has a roughly 350-line
establishment routine. MSS/options/SYN-ACK work is repeated, and fast/asynchronous
dial failures repeat the error-signaling policy.

The newly registered flow keeps `stateMu` locked through immediate SYN-ACK
delivery. The asynchronous completion takes that same lock and checks `closed`.
Successful delivery sets `synAckSent`; failed delivery closes the flow. Under
this ordering the async `!synAckSent` send branch cannot run for a live flow.
It still recomputes options and assigns window scale before that check.

Make one SYN-ACK owner and one small failure-policy helper. Verify successful,
refused, slow, timed-out and canceled dials, registration races and delivery
rejection, then remove the unreachable send branch and redundant setup. Keep
the observable fast pre-dial versus asynchronous fallback behavior. Do not
replace it with a speculative connection-establishment framework.

### C3 — Small internal deletions are well supported

Tracked-source reference inspection supports removing:

- `tcpFlow.mu`: unused mutex; it is not the live `stateMu` or registry mutex.
- `pipeBytes` and retransmit-entry `rtx`: written but never read. Preserve the
  live retransmission `retries` and accounting fields.
- Private TCP/UDP/ICMP bridge `Name()` methods and the empty ICMP `stop()`:
  no caller/interface requires them. WireGuard TUN `Name()` is a different case.
- `congestionControl.OnSent` and its call: the sole implementation is a no-op.
  The one-implementation interface and separate `ccEnabled` flag also deserve
  simplification, but NewReno itself remains necessary behavior.
- Unused private parameters, including `sendToGuest`'s flow argument and
  `effTosTTL`'s original-TTL argument, after updating callers coherently.
- Checks duplicated after the same boundary has already established the
  invariant: WGTun Read's local slice/offset checks, the packet processor's
  second nil-TUN check, and TCP header length revalidation after the shared
  parser. Keep validation at genuinely distinct external/injection boundaries.

Private constructors dereference their parent before later testing it for nil.
Those fallback branches do not provide nil safety. State a non-nil constructor
contract and remove imaginary fallback support after auditing call sites.

### C4 — Packet ownership is explicit internally, inconsistent publicly

[packet.go](../pkg/core/packet.go) still makes `NewPacket`/`SimplePacket.Data`
copying depend on global debug state. That makes ownership harder to infer.
Preserve legacy compatibility deliberately while maintained paths use explicit
copy/borrow semantics.

The recent [icmp_datagram.go](../pkg/socket/icmp_datagram.go) obtains a
`BorrowPacketData` slice and edits sequence/checksum bytes. The buffer is locally
owned, so this review is not asserting a demonstrated race, but it contradicts
the helper's read-only contract. Perform the wire edits inside the owned build
closure before wrapping the packet. Retain reservation-before-allocation,
failure cleanup and correlation behavior.

### C5 — Extra locks and SACK copies need an ownership audit

`stateMu` is documented as the owner of pending writes, retransmit state and
SACK state. Yet `pendMu`, `txMu` and `sackMu` remain around portions of that work.
[tcp_recovery.go](../pkg/socket/tcp_recovery.go)'s `isSACKed` copies the SACK list
for each lookup during retransmission scans.

Audit every production and test caller. If the flow lock already provides the
invariant, use explicit locked helpers and remove redundant snapshots/locks.
This is a candidate, not permission to mechanically remove synchronization.
Retain registry/lifecycle locks and lock-order guarantees. The separate RTO
diagnostic reset worker also merits consolidation, but its map feeds metrics
and a public reset operation; it is not merely disposable logging state.

### C6 — A weak stress executable duplicates stronger tests

[stress_wg_queue](../cmd/stress_wg_queue/main.go) has unvalidated size/load flags,
ignores processing errors, reports an error without a failing exit status, and
does not close/join its blocking TUN reader. It sends arbitrary bytes to exercise
a queue rather than validating forwarding. Its comments still reference removed
FlowManager behavior.

Prefer deletion once any unique queue assertion is represented in existing
bounded queue/ownership/lifecycle tests. Do not invest in another stress framework.
This finding is not evidence that this command caused the earlier host OOM.
Retiring a shipped command is an interface decision, unlike removing a private
field. Its use of `WrapPacket` also helps explain why that legacy wrapper remains.

### C7 — Compatibility residue is real, but public non-use is not dead-code proof

The deprecated JSON/YAML config model, old core router contracts, exported mock
types, always-unsupported kernel-TUN constructors, unused exported setters and
logging wrappers are candidates for a separately versioned cleanup. Do not
delete them solely because the executable does not call them. Never implement
kernel TUN support to make an obsolete adapter useful.

WGTun's custom Event type and per-`Events()` translating goroutine serve an old
non-WireGuard abstraction even though the current implementation always depends
on WireGuard. Direct use of the required event type could remove that layer;
preserve exported compatibility via aliases where feasible. Required external
interface methods are not dead simply because local search finds no calls.

### C8 — Documentation and comments overstate simplicity

Remove references to a removed FlowManager/scheduler and a supposed alternative
to the sole simple mode. Correct WGTun offset comments to match its actual
behavior. Historical assessment addenda are useful evidence, but readers should
not need to reconcile stale open items to discover current status. This document
is the consolidated remaining-work entry point, not another replacement history.

## What must survive cleanup

Keep ordinary userspace TCP/UDP sockets and in-memory TUN; finite flow/dial/byte
budgets; queue ownership and release; cancellation and joined shutdown; sequence
arithmetic; SACK/RTO/congestion control; receive windows; FIN/half-close/TIME-WAIT;
and meaningful malformed-input/failure tests. Independent test wire builders and
checksum oracles are useful duplication, not DRY violations to eliminate.

After behavioral TCP changes, use the existing contained unit/race/integration,
build/vet and representative benchmark gates. Add focused tests for changed
policy, not tests mirroring deleted fields. Require exact payloads, recovery and
zero final reservations, not just a process exiting successfully. No performance
improvement should be claimed from reduced line count alone.

## Historical benchmark revision mapping

Earlier author-identity rewriting changed commit IDs without changing these
source trees. Preserve original evidence and use the reachable equivalents for
reproduction; none of this is a benchmark rerun of current HEAD.

| Recorded commit | Rewritten equivalent | Identical tree |
| --- | --- | --- |
| `5d6f291` | `3f1e140` | `c49708cae6479a9abd50178f07eae2119098f4f9` |
| `fb99a4c` | `e073c77` | `099ef737173e1562f2b5baf4b0a4177709bb6084` |
| `1ef5ca7` | `76eb0ce` | `be93db89ddbdd6f817749d94d9cd5dc2e3df1240` |
