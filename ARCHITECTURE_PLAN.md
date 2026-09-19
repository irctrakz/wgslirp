# Architecture improvement plan

## Objective and evidence

Bring all 30 reviewed principles to **Strong**, with **Excellent** reserved for areas supported by sustained operational evidence. Prioritize preventable crashes, secret exposure, unsafe releases, and ineffective limits before refactoring.

Baseline: static review of commit `aded0ae`. Builds, tests, and race detection were not run because Go was unavailable on PATH. Findings below must be reproduced or verified against the implementation before fixes are considered complete. Repository settings such as required reviews and branch protection remain unverified.

This document combines historical checkpoints with an implementation backlog. Earlier "uncommitted" and "remaining" statements describe those checkpoints, not current status. The checked F-items below are the current completion record; local commits do not imply upstream publication or independent review.

### Linux verification update

Verification uses a Go 1.23.12 Linux container. After the TCP ownership batch,
build, vet, ordinary tests, race tests, and explicitly tagged integration tests
with and without race detection all pass. Environment-specific execution helpers are local tooling
and are not part of the repository's supported development interface.

### Rating definitions

- **Strong:** relevant contracts are explicit, implementation follows them, meaningful regression checks pass, and ordinary failure paths are covered.
- **Excellent:** Strong plus evidence from repeated releases, fault/load testing, compatibility checks, and real operation. Avoid adding frameworks or speculative features merely to improve a score.
- Process principles require evidence from repository settings and actual practice; code alone cannot establish them.

## Execution rules

### Implementation checkpoint — first batch

Implemented locally (not yet committed, published, or independently reviewed):

- Reusable CI checks now gate Docker publication on the same revision, including race and tagged integration tests. Package-write permission is restricted to the publication job.
- Duplicate integration capture helpers are consolidated; asynchronous test reads use synchronized snapshots. Integration tests wait for bridge teardown rather than assuming host close means teardown completed. Missing TCP receive counters are populated on accepted delivery.
- Raw WireGuard UAPI configuration/state logs are removed. Configuration replacement uses a private temporary file and atomic rename; existing PCAP files are restricted before truncation, write failures are surfaced, and capture has an explicit close operation.
- TUN startup events no longer race a delayed sender against close. Injection is serialized with close, metrics use atomic snapshots, overlay accounting no longer counts twice, and invalid read/write offsets or undersized read buffers return errors.
- Packet processors reject invalid lifecycle transitions, permit repeated/concurrent stop, and release accepted queued pooled buffers during shutdown.
- Health fan-out copies before ownership transfer, preserves forwarding errors, forwards metrics, and starts after socket initialization.
- WireGuard configuration validates keys, ports, MTUs, peer prefixes/endpoints and keepalive values before device creation. Listed peers without keys fail explicitly.
- Metrics intervals fail validation before runtime startup. Startup failures execute deferred cleanup; metrics and WireGuard handshake reporters have cancellation paths.
- Remote verification downloads logs and removes the run's temporary source/cache directory, named container, and labeled network by default. Cleanup handles read-only Go cache directories and reports failure. Earlier retained workspaces were removed.

First-batch Linux verification: build, vet, ordinary tests, and tagged integration tests passed; production TCP races remained. These reproduced races are addressed in the next checkpoint. No claim is made that Phase 0/1 or all principles are complete.

The subsequent lifecycle/health/capture checkpoint addresses the remaining socket/UDP synchronization, health response validation, and capture size policy. Repository branch protection, independent approvals, workflow execution, container release checks, and dependency-tidy verification are not yet verified remotely in GitHub.

### Implementation checkpoint — TCP ownership and shutdown

Implemented locally (not yet committed, published, or independently reviewed). Linux Go 1.23.12 verification passed: build, vet, unit tests, race tests, and tagged integration tests both with and without race detection.

- A per-flow state lock owns connection attachment, sequence/window state, retransmission decisions, delayed ACKs, and teardown. Registry snapshots avoid taking flow locks while holding the registry lock. Runtime MSS/pacing controls use atomic values.
- TCP bridge shutdown rejects new work, cancels context-aware dials, closes connections, and joins its readers, ACK timers, retransmission workers, and diagnostics. Host writes have a five-second deadline. Closing a flow is idempotent and an old reader cannot delete a replacement flow with the same tuple.
- The sender advances sequence state per emitted segment, honors zero receive windows, and releases state before blocking reads or ACK waits. Unconfigured interfaces retain an MTU fallback.
- Regression tests cover concurrent sending/ACKs/metrics, shutdown of a zero-window sender, and replacement-flow isolation. Retransmission assertions count newly emitted packets instead of repeatedly counting the original packet.
- CI runs tagged integration tests with race detection. The expanded check exposed a mock TUN metrics race; its snapshot now uses atomic reads.

Scope limits: this is not a complete TCP protocol redesign. The existing short FIN grace period remains; full FIN recovery, socket/UDP lifecycle synchronization, effective resource controls, and dependency separation remain work items. Packet delivery callbacks must return promptly and must not synchronously re-enter the same TCP flow while its state lock is held. Process controls and independent review still require external verification.

### Implementation checkpoint — socket/UDP lifecycle, health, and capture

The preceding verified batches are committed locally as `e7805ba`; nothing has been pushed. This checkpoint is new, uncommitted work. Linux Go 1.23.12 verification passed: build, vet, unit tests, race tests, and tagged integration tests both with and without race detection.

- Socket shutdown stops admissions, closes descriptors before waiting, joins packet handlers and bridge workers, and lets concurrent Stop callers await the same completion. Bridge references remain stable for metrics. Restart is explicitly rejected; processor configuration is restricted to before startup.
- UDP shutdown joins readers and the reaper, rejects late flow insertion, and shares identity-checked removal/accounting across read failure, expiry and shutdown.
- Startup health probes are canceled and joined. HTTP requires 2xx status; DNS validates packet boundaries, tuple, ID, response flags, question and answer. Documentation describes startup-only behavior.
- PCAP defaults to a 64 MiB file cap, accepts an explicit finite byte limit, and stops before exceeding it. Invalid limits preserve existing files; records respect the declared snap length. Capture failure or exhaustion leaves forwarding active.
- New tests cover concurrent traffic/metrics/Stop, rejected restart, UDP replacement isolation, malformed/error DNS responses, HTTP status and cancellation, and concurrent capture limits.

Remaining work includes enforcing configured resource budgets, auditing other mock lifecycles, protocol recovery and metrics semantics, and verifying external review/release controls. No principle is marked Strong solely because these changes exist.

### Implementation checkpoint — packet boundaries

New uncommitted work. Linux Go 1.23.12 verification passed: build, vet, unit tests, race tests, and tagged integration tests with and without race detection. The 10-second parser fuzz campaign passed 263,566 executions without a failure.

- Shared IPv4 validation bounds parsing by declared datagram length, ignores trailing padding, and rejects malformed lengths, reserved flags, and unsupported incoming fragments before forwarding.
- TCP, UDP and ICMP bridge entry points validate protocol and transport bounds. UDP lengths must match the declared IP payload; TCP data offsets must fit the datagram.
- Exported malformed-packet and unsupported-fragment errors remain discoverable through socket error wrapping using `errors.Is`.
- Regression coverage checks malformed packets at public and direct bridge boundaries and confirms UDP padding is not forwarded. A bounded parser fuzz campaign is included in CI.

This completes another Phase 1 boundary-hardening slice; checksum validation, full IP-option semantics and incoming fragment reassembly are not implemented by this change. The next major priority remains Phase 2: make configuration effective and enforce atomic, bounded resource admission.

### Implementation checkpoint — effective resource configuration and admission

New uncommitted work. Linux Go 1.23.12 verification passed: build, vet, unit tests, race tests, tagged integration tests with and without race detection, and 261,289 parser fuzz executions. The concurrent admission regression admits exactly two of 24 distinct flow attempts at a configured cap of two.

- Application-boundary parsing wires ACK delay, TCP/UDP idle lifetime, TCP reassembly capacity and active-flow caps into typed socket configuration. Invalid numeric values and duration overflow fail before network startup.
- TCP now applies its previously ignored configuration fields. ACK delay no longer depends on a bridge-constructor environment read; the effective application default remains 10 ms.
- TCP insertion rechecks the flow cap under the registry lock after dialing. Concurrent candidates cannot exceed the registered-flow limit. TCP and UDP expose a shared admission-limit sentinel error.
- Regression tests check effective bridge settings, invalid startup configuration, environment parsing and concurrent admission against a two-flow cap.

This is a slice of PR 2.1/2.2, not completion of all resource budgeting. Zero flow caps remain unlimited for compatibility. Pending-dial admission, aggregate buffering, measured finite defaults, remaining runtime environment reads and distinct admission metrics still require implementation.

### Open follow-up register

Every implementation deferral must be recorded here with its destination and completion evidence before closing that batch. Check an item only after its acceptance criteria are verified; record the implementing commit and results. This register tracks deferred work from completed batches; the phase backlog below remains authoritative for the wider plan.

#### Current implementation — dial and buffer reservations

Committed locally in `c7686b2`. Linux Go 1.23.12 verification passed before the remote-testing pause: build, vet, unit tests, race tests, tagged integration tests with and without race detection, and 271,459 parser fuzz executions. Resource regressions cover fast-dial saturation, fallback/RST cancellation, hard failures, duplicate successful dials, overlapping reassembly, flush/ACK/teardown release, retransmission backpressure, shared TCP/UDP storage, and isolation of an existing flow during aggregate exhaustion. Implementing commit: `c7686b2`; nothing pushed.

- F01 implementation reserves before preliminary dialing and transfers the same reservation through asynchronous fallback. Dial contexts cancel on RST/flow removal and bridge shutdown; all exit paths release once. Saturation rejects before opening another socket.
- F02 implementation introduces a shared socket buffer budget covering retained TCP pending/reassembly/retransmission data, queue-entry allowances, asynchronous ICMP quotes and TCP/UDP reader buffers. Reassembly reserves before allocation and accounts unique bytes plus temporary merge storage; ACK, flush and teardown release ownership. Per-flow retransmission storage applies backpressure; global send-storage exhaustion resets only the affected flow.
- Finite defaults are 64 pending dials, 64 MiB shared storage, 64 KiB per-flow pending payload and 1 MiB retransmission payload. New zero-valued controls select these defaults; they do not request unlimited resources. F03 remains open for representative workload measurements and tuning.
- Typed configuration and additive metrics expose the budgets, peaks and refusal attempts. F05 remains open for consistent reason-specific admission metrics across all resource types.

**F02 queue ownership/accounting checkpoint (2026-09-17):** the WireGuard output queue and socket processor queue now share the socket's reservation budget through a narrow `PacketBufferReserver` interface. WireGuard rejects full queues before reservation/allocation and reserves before its synchronous copy; the redundant processor copy is removed. Socket processor admission charges retained slice capacity plus the entry allowance, transfers packet ownership only on success, and keeps in-flight work charged until the writer returns. Reservations release once on rejection, worker/read completion (including undersized-read failure) and shutdown drain. A TUN read already in flight keeps ownership until it returns, even if Close has returned. Existing constructors remain compatible; custom writers without the interface get a finite 64 MiB budget per adapter. Custom packets must expose retained slice storage through `Data`.

**Queue checkpoint validation:** Linux Go 1.23.12 build, vet, unit, race, tagged integration and tagged integration-race stages all passed sequentially under the F12 containment model. Each stage retained 1 CPU, 2 GiB memory/no swap, 128 PIDs, bounded tmpfs and a 600-second deadline. Maximum observed cgroup memory was 458,141,696 bytes (436.92 MiB); every stage reported zero memory-limit/OOM/OOM-kill and PID-limit events. Automatic cleanup plus independent checks confirmed no owned containers, networks, workspaces or lock after each run; pause guards were restored. Go formatting and diff whitespace checks passed. Environment-specific harness files and evidence remain local and ignored. These tests establish the queue reservation contracts, not sustained-load memory recovery.

**F02 synthesis/pool checkpoint (2026-09-17):** production TCP/ICMP synthesis now reserves before building and transfers the reservation with the releasable packet. UDP reserves the complete datagram and constructs one independently reserved fragment at a time, eliminating the all-fragments allocation and redundant delivery copies. Raw ICMP reader/reply storage, ICMP scratch and WireGuard-to-socket copies are accounted; internal read-only views avoid debug-copy allocations. Rejected initial SYN-ACKs remove their candidates so later SYNs can retry. Empty pooled packets also release their ownership callback exactly once. Custom packet processors must release accepted pooled packets; synchronous socket writers must copy anything retained after returning. The mock writer now follows that borrowing contract.

| Storage boundary | Admission and release |
| --- | --- |
| TCP pending/reassembly/retransmission and reader storage | Existing shared reservations; ACK/flush/teardown release; replacement storage reserved while old data remains live. |
| Synthesized TCP/ICMP packets | Reserve payload capacity (rounded to pool class when enabled) plus entry allowance before building; retain through downstream ownership. |
| UDP replies/fragments | Reserve complete datagram and each live fragment; downstream release or refusal returns ownership; stop fragment construction on refusal. |
| Raw ICMP and WireGuard socket writes | Reserve reader, parser/marshal scratch and copy storage before use; release after synchronous operation or packet consumption. |
| WireGuard/socket queues | Existing queue reservations persist through reads/writes and shutdown drains. Conservative overlap charges may count a packet at two ownership boundaries. |
| Idle packet pools | Separate process-wide ceiling of 960 KiB: 32 buffers per 2/4/8/16 KiB class. Full pools discard returns; reuse clears stale header/checksum bytes. |

**Controlled recovery evidence:** a finite fixture performs 4,096 allocation attempts with 16 workers over eight rounds under a 2 MiB shared budget, requires refusal under saturation and zero reservations after each drain, and measures heap/RSS before and after explicit GC/scavenging. This distinguishes retained storage from allocator caching; it does not demonstrate natural RSS decay or representative production throughput.

**Synthesis/pool validation (2026-09-18):** Linux Go 1.23.12 build and standalone unit/race stages passed during implementation. After the final ICMP allocation fix, tagged integration (including unit regressions), vet and tagged integration-race all passed. The final integration-race container peaked at 463,331,328 bytes (441.87 MiB); no run reported memory-limit/OOM/OOM-kill or PID-limit events. Each completed run, including the initial failed test fixture, had successful cleanup and an independent zero-owned-residue check; pause guards were restored. The initial fixture failure came from lowering a budget below its historical peak and was corrected by constructing a fresh budget. The controlled recovery sample recorded peak reservations of 2,096,640 bytes, 2,080 refusals, heap 127,536 to 99,040 bytes and RSS 6,344 to 7,176 KiB after explicit GC/scavenging. Formatting and whitespace checks passed. Environment-specific drivers and evidence remain local and excluded from commits.

**F02/F03 mixed-workload checkpoint (2026-09-18):** added a reproducible integration fixture using real loopback TCP/UDP peers, production socket bridges and the bounded socket processor queue. Profiles cover 8 TCP/32 UDP, 64 TCP/256 UDP, a repeated capacity cycle and the capacity cycle with pooling. Each peer completes 66 verified 1 KiB echoes; at most 16 UDP requests are in flight against the shared echo socket. Every profile verifies flow-cap refusal, shared-budget refusal, post-exhaustion payload recovery, zero reservations and empty flow registries after teardown. Heap/RSS/stack/GC samples are taken during traffic and for three seconds idle without forced GC. Final normal traffic peaked at 19,038,464 accounted bytes (18.16 MiB); sampled process RSS peaked at 66,888 KiB including fixture peers. RSS remained above a cold baseline after teardown, consistent with allocator caching; the shared budget is not an RSS ceiling. See [RESOURCE_BUDGETS.md](RESOURCE_BUDGETS.md) for measurements and reproduction.

**F03 default decision:** `socket.DefaultConfig()` and unset application settings now select 64 TCP and 256 UDP active flows, matching the measured capacity profile. Keep the 64 MiB aggregate budget and existing 64 pending dials, 64 KiB per-flow pending data and 1 MiB per-flow retransmission limits. The measured normal packet storage leaves more than threefold aggregate headroom; this is a conservative operating point rather than an optimal throughput claim. Explicit zero flow caps retain unlimited admission, including hand-built Go configs. Tests cover unset, zero/unlimited and positive overrides. The separate 960 KiB idle-pool ceiling remains in place.

**Remaining workload breadth:** encrypted WireGuard end-to-end transport, WAN loss/latency, long-idle expiry, larger deployment profiles and long-duration soak evidence remain F10 release/workload coverage. Reason-specific refusal counters are complete in F05. F02/F03 are complete for the documented finite bridge/queue workload and default-selection scope; they do not promise immediate natural RSS return to a cold baseline or validate arbitrary unlimited/custom implementations.

**Mixed-workload validation:** build, vet, tagged integration (including unit/default-override regressions) and tagged integration-race passed. The race stage peaked at 845,574,144 bytes (806.40 MiB), with no memory/PID-limit events; the normal integration stage peaked at 410.64 MiB including compilation/caches. Resource ceilings were unchanged. Every completed stage, including the initial unpaced UDP fixture failure, had independently verified cleanup, and pause guards were restored. Environment-specific scripts and raw evidence remain local and ignored.

#### Completed: resource budgets and configuration (PR 2.1/2.2)

- [x] **F01 — Bound pending TCP dials.** Reserve capacity atomically **before the preliminary fast dial**, share the budget with asynchronous fallback, and release reservations on success, failure, duplicate-flow races, cancellation and shutdown. Define timeout, queue/rejection behavior and refusal signaling. **Acceptance:** concurrent SYN storms never exceed the configured dial budget, established flows keep working, and reservations return to zero after cancellation/shutdown.
  - Implementation and regression verification recorded in `c7686b2`. This closes the pending-dial implementation item, not the independent remote-test containment review in F11.
- [x] **F02 — Bound total buffering.** Inventory pending client data, out-of-order reassembly, retransmission queues and delivery queues; enforce per-flow and aggregate byte budgets before allocation/enqueue. Define ownership and release on ACK, flush, rejection, expiry and teardown, including retransmission and overlap handling. **Acceptance:** concurrent saturation cannot exceed accounted budgets; teardown releases all reservations; memory trends back toward baseline; one overloaded flow does not stop unrelated traffic.
  - [x] Socket-owned budgets and downstream queue ownership/accounting are implemented. Regression coverage includes shared cross-component exhaustion, retained capacity, caller ownership on rejection, exact-once concurrent release, full-queue rejection before reservation, pooled-input copy safety, blocked-worker ownership, undersized reads, shutdown drain and concurrent TUN read/inject/close.
  - [x] Production transient synthesis/copy accounting and finite idle-pool retention are implemented; controlled contention/drain/recovery coverage is included.
  - [x] Finite mixed TCP/UDP workload with natural heap/RSS sampling and overload recovery verified under the existing F12 ceilings; measured scope and limitations recorded above. Broader encrypted/WAN/soak coverage stays under F10.
- [x] **F03 — Select measured finite defaults.** Measure representative connection counts, memory use and overload recovery, then choose defaults for flows, pending dials and buffers. Document any unlimited override and migration from today's zero/unlimited flow caps. **Acceptance:** reproducible load evidence supports the defaults and tests verify default and override behavior.
- [x] **F04 — Finish typed configuration migration.** Move remaining packet/flow-time environment reads (dial timing, congestion control, socket buffers, window scaling and SACK) and other constructor tuning into validated configuration. Resolve JSON/YAML adapters, precedence and inactive controls as described in PR 2.1. **Acceptance:** each supported setting has effective-value coverage; environment changes after construction cannot alter existing components.
  - [x] **F04a - TCP and IP-header snapshot.** Added typed transport defaults/validation and an explicit `socket.ConfigFromEnv` adapter; removed environment reads from socket startup, TCP bridge construction, flow creation, SYN-ACK/SACK handling and congestion control. Snapshot caller-owned configuration. Apply host socket options consistently to fast and asynchronous dials. Preserve zero/default semantics where practical and document stricter validation, CC/log aliases and zero ACK-idle-failure behavior. Tests cover every new setting's parsed value, bridge settings, both dial paths, real Linux socket buffers, SYN-ACK options, congestion windows, invalid values, defaults and post-construction environment/template mutation.
  - **F04a validation (2026-09-18):** Linux Go 1.23.12 unit tests, tagged integration with the race detector, build and vet passed. Gofmt and whitespace checks passed. The largest container peak was 828,776,448 bytes (790.38 MiB) during integration-race; all stages had zero memory/OOM/PID-limit events. Each stage independently verified no owned container, network, workspace or lock residue, and restored remote pause guards. Environment-specific scripts and raw evidence remain local and ignored.
  - [x] **F04b - Remaining constructor and diagnostic configuration.** Migrate WireGuard device debug/overlay/IPv6 settings and TUN queue sizing, the optional library socket processor's worker/queue settings, lazy PCAP configuration and process-wide pooling controls into validated startup configuration. Preserve exported constructors through explicit compatibility adapters/deprecation; test that environment changes cannot redirect capture or alter existing components. Keep IPv6 default-privilege changes in PR 2.3; do not silently change them as part of parsing.
  - [x] **F04c - Application configuration contract.** Inventory/deprecate or adapt the separate public `pkg/config` JSON/YAML model (no production imports found during F04a review; external consumers remain possible). Document precedence, add an opt-in sanitized effective-configuration summary, warn that processor-worker settings are inactive in the executable's inline path, correct examples and finish effective-value coverage for remaining application settings. Do not remove exported APIs or create an unnecessary worker pool.

  - **F04b/F04c completion (2026-09-18):** the executable now parses one environment snapshot into validated device, socket, TUN, capture, pooling, health and metrics configuration before creating resources. WireGuard startup reads typed options, including cloned exclusion prefixes; capture opens at startup and cannot follow environment changes or reopen after closure/limit failure. Pooling is fixed before interface/packet creation, with idempotent same-policy configuration and rejection of conflicting changes. Added bounded explicit TUN/processor constructors and retained deprecated legacy adapters with warnings/default fallback. `DeviceConfig.LoadFromEnv` updates its receiver only on success. `PRINT_CONFIG` reports sanitized effective values, including resolved zero-as-default resource settings, while excluding keys, endpoints, prefixes and diagnostic paths/targets. Health DNS configuration now drives both probes. The executable warns about inactive processor controls, examples remove them and fix the peer index, and public `pkg/config` JSON/YAML APIs are retained with documented deprecation and caller-controlled legacy precedence. See [CONFIGURATION.md](CONFIGURATION.md) for defaults, compatibility changes and migration.
  - **F04b/F04c validation:** Linux Go 1.23.12 unit tests passed during implementation. After the final effective-default resolution and real WireGuard startup fixture, tagged integration with the race detector, build and vet passed, including all unit regressions. Coverage includes late environment/template mutation, typed and compatibility constructors, invalid settings before queue allocation, frozen pooling/capture policies, summary redaction, configured health DNS query/reply validation and actual device routing/closure. Gofmt and whitespace checks passed. Peak container memory was 840,290,304 bytes (801.36 MiB); no stage reported memory/OOM/PID-limit events. Every stage independently verified no owned container, network, workspace or lock residue and restored pause guards. Environment-specific harnesses and raw evidence remain local and ignored. F04 is complete; admission observability is F05 and the unchanged IPv6 sysctl/default-privilege behavior remains PR 2.3.

- [x] **F05 — Make admission failures observable (also PR 3.1/3.2).** Distinguish active-flow, pending-dial, per-flow-buffer and aggregate-buffer refusals using bounded-cardinality counters and actionable errors. **Acceptance:** saturation fixtures prove exact counts and protocol-appropriate behavior, without counting one rejection multiple times.
  - **F05 implementation (2026-09-18):** added per-interface cumulative admission counters for TCP/UDP flow caps, pending dials, pending/reassembly byte caps, aggregate reservations and invalid reservation sizes. Retransmit-cap backpressure counts observed wait episodes rather than polling iterations or drops. Fixed-cardinality detached snapshots survive shutdown and reach both JSON (`admission`) and text metrics; legacy counters remain compatible, with overlap and attempt-versus-packet semantics documented in [OBSERVABILITY.md](OBSERVABILITY.md). Each denied reservation is counted by its limiting owner only; a separately refused ACK/RST/ICMP allocation is a distinct attempt. Final review also moved UDP error/refusal replies to shared-budget synthesis and rejection-safe delivery, closing their prior accounting/ownership gap.
  - **F05 validation:** Linux Go 1.23.12 unit tests passed during implementation. Final tagged integration with the race detector (including all unit regressions and mixed TCP/UDP traffic), build and vet passed after the UDP reply fix. Fixtures verify exact concurrent flow/dial/aggregate counts, exclusive per-flow versus aggregate reasons, duplicate reassembly, recovery, detached snapshots, post-stop counters, backpressure episode counts, real JSON/text reporting, RST/ACK and ICMP signaling, no ACK advancement for refused bytes, refusal-response allocation failure, and release on rejected UDP error delivery. Gofmt and whitespace checks passed. The final integration-race container peaked at 827,949,056 bytes (789.59 MiB); the largest F05 run peaked at 797.62 MiB. All runs had zero memory/OOM/PID-limit events, independently verified zero owned container/network/workspace/lock residue, and restored remote pause guards. Environment-specific scripts and raw evidence remain local and ignored. Broader packet/error counter semantics and reporter-owned interval state remain explicitly tracked in F09; lifecycle/callback audits remain F06.

#### Lifecycle, correctness and verification work

- [x] **F06 — Finish lifecycle audits (PR 1.2/5.1).** Audit remaining mocks and callback ownership; address blocking or reentrant delivery callbacks and stale flow-identity removal in maintenance paths. **Acceptance:** targeted concurrent Start/Stop/Close, expiry/replacement and blocked-callback tests pass under race detection with documented shutdown bounds.
  - **F06 implementation (2026-09-18):** audited socket/processor/WireGuard TUN teardown and the remaining mock socket/TUN lifecycles. Added concrete `RequestStop`/`StopContext` methods to sockets and mocks: the request closes admission synchronously; one finalizer signals both bridge domains before joining and publishes completion only after accepted work returns. Callbacks can request shutdown without joining themselves; context deadlines bound the caller's completion wait without pretending to terminate custom callbacks. Mock lifecycle transitions, processor configuration, metric snapshots, queue draining and detached history now follow explicit ownership rules. Missing WireGuard sinks reject packet ownership. TCP expiry, health/manual resets and RTO tracking retain flow identity; expiry/health predicates are rechecked before removal, and manual reset counts report actual removals. [LIFECYCLE.md](LIFECYCLE.md) records supported re-entry, synchronous callback/file-I/O limits, per-write deadlines and downstream queue ownership. Arbitrary synchronous re-entry into locked TCP flow operations remains outside the callback contract; this change does not add unbounded delivery goroutines or promise forcibly cancellable callbacks.
  - **F06 validation:** Linux Go 1.23.12 unit tests and tagged integration with the race detector passed, including mixed TCP/UDP traffic and existing processor/TUN Close regressions. After adding cleanup on early fixture failure, the final standalone race suite, build and vet passed. New regressions cover concurrent Start/Stop, blocked callbacks and bounded waits, callback-initiated shutdown, admission closure, mock queue draining, released-packet history, detached snapshots, rejection ownership and wrapped causes, stale replacement/RTO identities, refreshed-flow expiry and exact reset counts. Gofmt and whitespace checks passed. The largest container peak was 844,509,184 bytes (805.39 MiB); every stage reported zero memory/OOM/PID-limit events, independently verified zero owned container/network/workspace/lock residue, and restored pause guards. Environment-specific drivers and raw evidence remain private/ignored; nothing was pushed upstream. F06 is complete within the documented callback contract; F07 FIN recovery is next.
  - **Subsequent harness negative controls (2026-09-18):** five disposable copies of `76bef3f` injected a unit assertion failure, a real data race, an integration-tag-only assertion failure, an undefined build symbol and a compilable printf/vet violation. Every unchanged stage command emitted the intended diagnostic, exited 1 and was rejected by the harness; none emitted a success marker. Every run verified zero memory/OOM/PID-limit events and independent zero owned remote residue. Disposable copies were removed, the original repository/helpers stayed unchanged and paused, and nothing was committed or pushed for the controls. The outer runner's first local copy cleanup needed a Windows read-only Git-object fix; remote cleanup had already succeeded. This verifies representative failure propagation, not exhaustive application-test coverage.
  - **Documentation alignment:** corrected current F03/default-sizing and F05/refusal status in the README/plan; labeled older checkpoint statements as historical. Configuration, admission metrics and workload evidence documents match the completed implementation and retain their stated F09/F10 limits.
- [x] **F07 — Complete TCP FIN recovery (PR 5.1/5.2).** Replace reliance on the current short FIN grace period with explicit, bounded close-state and retransmission behavior. **Acceptance:** lost/duplicate FIN and ACK, half-close and shutdown-under-traffic fixtures show no premature data loss or leaked workers.
  - **F07 implementation (2026-09-18):** replaced the 50 ms EOF removal and collapsed FIN-wait path with explicit FIN-WAIT-1/2, CLOSE-WAIT, CLOSING, LAST-ACK and TIME-WAIT states. FIN sequence ownership/retries share the existing bounded retransmission worker; ACK/data processing continues in half-close states, pending data drains before CloseWrite, and duplicate/out-of-order/payload-bearing FINs do not prematurely consume bytes. Progress-based close expiry and bounded TIME-WAIT are documented in [LIFECYCLE.md](LIFECYCLE.md). High-churn capacity sizing remains explicitly F10.
  - **F07 validation:** Linux Go 1.23.12 unit and standalone race suites passed during implementation. Final tagged integration with race detection (including all unit tests and mixed TCP/UDP traffic), build and vet passed after restoring exact-size pending-buffer allocation and strengthening assertions to verify close removal before test cleanup. Fixtures exercise lost data/FIN/final ACK, both half-close orders, responses spanning multiple guest windows, simultaneous close, duplicate/reordered/payload-bearing FIN, third-handshake-ACK payload/FIN, pre-dial pending flush, refusal without premature FIN acknowledgment, FIN/cumulative-ACK sequence wrap, invalid ACK rejection, progress-only deadline refresh, bounded TIME-WAIT/expiry and shutdown under unacknowledged traffic. The initial pending-FIN fixture omitted its per-flow pending allowance and failed as expected for that invalid fixture; it was corrected to use the production default. Gofmt and whitespace checks passed. Final integration-race peaked at 846,999,552 bytes (807.76 MiB); the largest F07 run peaked at 853,942,272 bytes (814.38 MiB). Every run, including the failed fixture, had zero memory/OOM/PID-limit events, independently verified zero owned container/network/workspace/lock residue, and restored pause guards. Environment-specific drivers/raw evidence stay private and ignored. F07 is complete for the documented close policy; high-churn sizing remains F10 and the remaining packet-validation/support policy is F08.
- [x] **F08 — Resolve remaining packet-validation scope (PR 1.4/5.1).** Define and test checksum-validation and IP-option policy. Record an explicit support decision for incoming fragment reassembly; retain tested rejection unless a supported use case justifies bounded reassembly. **Acceptance:** supported and rejected cases are documented and covered by regression/fuzz tests. Fragment reassembly is not implicitly promised by this item. F07 fixes FIN/cumulative-ACK wrap comparisons; wrap-spanning out-of-order payload reassembly remains unsupported and its policy/coverage belongs here.
  - **F08 implementation (2026-09-18):** strict guest IPv4/TCP/ICMP and nonzero UDP checksum validation; explicit all-IPv4-options rejection; retained fragment rejection with no speculative cache. Documented finalized-checksum input requirements and limited TCP receive-wrap policy in [PACKET_VALIDATION.md](PACKET_VALIDATION.md). Refused wrap-spanning future payloads keep the cumulative ACK and budget unchanged; obsolete pre-wrap queue entries release after in-order wrap.
  - **F08 validation:** Linux Go 1.23.12 tagged integration including all unit regressions passed with race detection, followed by the expanded 10-second single-worker fuzz target (172,363 executions), build and vet. Regression fixtures reject corrupt IPv4/TCP/UDP/ICMP packets at both public and direct bridge boundaries without flows, replies or retained budget; cover DF, padding, TCP options, odd lengths, UDP omitted/computed-zero checksums, IP-option/fragment rejection, and wrap refusal followed by exact in-order delivery and reservation release. Existing fixtures that modify TCP windows now finalize their checksums. Gofmt and whitespace checks passed. The largest/final integration-race container peak was 787,623,936 bytes (751.14 MiB); every stage had zero memory/OOM/PID-limit events, independently verified zero owned container/network/workspace/lock residue, and restored pause guards. Environment-specific drivers and raw evidence remain private and ignored. F08 is complete for the documented support policy; broader wrap/SACK workload verification and independent release review remain F10. No upstream push.
- [x] **F09 — Finish metrics semantics and dependency separation (PR 3.1/3.2/4.1).** Complete the phase backlog for exact counters, reporter-owned state, stable snapshots/contracts and narrow bridge collaborators. **Acceptance:** deterministic metrics fixtures and independent component tests demonstrate the contracts, not merely file movement.
  - **F09 implementation (2026-09-18):** reporter-owned reset-safe RTO deltas, shared peer-state parser, additive schema/availability fields, corrected socket/TUN/streak and per-interface UDP counters, typed queue errors, bounded repetitive diagnostics, neutral writer/reservation contracts, injectable delivery/dial collaborators and explicit bridge maintenance startup. Contracts and compatibility are documented in [OBSERVABILITY.md](OBSERVABILITY.md). Reporter sampling/emission use narrow snapshot interfaces; worker admission, delivery, write-error and shutdown-discard counts are distinct. Error publication precedes completion of admitted bridge work, preserving shutdown snapshot ordering. Empty UDP datagrams now reach the host socket and count as zero-byte writes.
  - **F09 validation:** Linux Go 1.23.12 unit tests passed, including real empty-UDP forwarding. Final tagged integration including all unit regressions passed with race detection after the lifecycle accounting-order fix; build and vet passed afterward. Deterministic fixtures cover peer/handshake counts and invalid/future timestamps, multiple/reset/concurrent reporters, schema and unavailable values, health metric passthrough, partial TUN batches/overlay delivery, concurrent saturation streaks, frame versus payload counts, wrapped failures and rejected delivery, per-interface UDP history, explicit maintenance lifecycle, worker completion counts, atomic resets and bounded diagnostic emission. The initial run correctly failed two incomplete fixtures (missing sink and a manually built bridge missing its delivery collaborator); both were corrected to use valid setup. Gofmt and whitespace checks passed. The largest/final integration-race peak was 816,136,192 bytes (778.33 MiB). Every stage, including the failed run, recorded zero memory/OOM/PID-limit events, independently verified zero owned container/network/workspace/lock residue, and restored pause guards. Environment-specific drivers and raw evidence remain private/ignored. F09's behavioral contracts are complete; independent external review, release controls and production/load verification remain F10. Work remains on `codex/architecture-hardening`, with no upstream push.
- [ ] **F10 — Verify external review/release controls (Phase 0/5/6).** Confirm branch protection and independent approvals, execute workflows and container release checks, verify dependency tidy checks, and add production-path/load coverage, including high TCP connection churn and default flow-cap sizing with F07 TIME-WAIT slot retention, plus long-lived TCP sequence-wrap/SACK loss-recovery workloads to assess the remaining protocol limits documented by F08. **Acceptance:** record actual settings and run evidence; passing local tests alone does not close this item. Respect the current instruction not to push upstream.


  - [x] **F10a — Bounded production-path and capacity evidence (2026-09-18).** Added real encrypted WireGuard TCP/UDP loopback round trips through production WGTun/socket/processor components, plus 128 real short TCP connections in two default-capacity batches. Churn verifies exact payloads, host socket closure, TIME-WAIT admission refusal, simulated expiry/re-admission and zero final reservations. Retain the 64-flow default for the documented small profile, with the explicit approximately 16 host-first closes/minute steady-state constraint before active-flow/burst headroom; see [RESOURCE_BUDGETS.md](RESOURCE_BUDGETS.md). This does not validate high-throughput deployment sizing.
  - [x] **F10b — Seeded sequence-wrap loss recovery.** A failing regression exposed missed partial-ACK recovery across zero, dropped wrap-spanning SACK blocks and stale SACK retention. SACK normalization now uses outstanding-window-relative ordering and serial comparisons; acknowledged/unsent blocks are discarded. Hole selection and the exclusive recovery endpoint handle wrap, including zero, and the third duplicate ACK no longer emits the same hole twice in one pass. Regression fixtures check exact retransmitted payloads, partial ACKs, final-byte recovery and released reservations. Receive-side out-of-order limitations remain as documented in [PACKET_VALIDATION.md](PACKET_VALIDATION.md).
  - [x] **F10c — Dependency verification and finite CI deadlines.** Actual `go mod tidy` and `go mod verify` passed inside the contained build stage; both module-file checksums stayed unchanged. Added explicit Go/image job deadlines and an overall fuzz-test deadline. Workflow configuration has been reviewed locally but not executed on GitHub.
  - **F10 validation:** Linux Go 1.23.12 tagged integration (including all unit regressions) passed under race detection after the fix and again with the zero-recovery-endpoint/final-byte cases. Build with module tidy/checksum verification and vet passed. The initial pre-fix run failed the intended SACK regressions, demonstrating failure propagation. Final integration-race peak was 816,525,312 bytes (778.70 MiB); build/tidy peaked at 442,585,088 bytes and vet at 409,071,616 bytes. Every run, including the expected failure, recorded zero memory-limit/OOM/PID-limit events, independently verified zero owned container/network/workspace/lock residue, and restored pause guards. Gofmt and whitespace checks passed. The actual release image and GitHub workflows were not executed. Environment-specific drivers/raw evidence remain private and ignored. Work stays on `codex/architecture-hardening`; local commit only, no upstream push.
  - [ ] **F10d — External enforcement, review and release-image evidence.** Branch-protection inspection returned HTTP 401; actual protection/rulesets and bypass permissions remain unknown. Independent approval, exact-candidate workflow runs, image startup/encrypted forwarding/SIGTERM validation, publication and digest/rollback evidence remain pending. No workflow was dispatched or settings changed; the remote harness's cached test image does not authorize building/pulling release images on the server. [RELEASE_VALIDATION.md](RELEASE_VALIDATION.md) records each evidence requirement and blocker.
  - [ ] **F10e — Extended workload breadth.** Full-sequence-cycle long-lived transfers, WAN latency/loss/reordering and receiver-reneging behavior, wall-clock long-idle/close expiry, finite-duration soak and larger mixed encrypted/high-churn profiles remain pending with explicit finite resource/traffic/deadline plans. Seeded sequence arithmetic and simulated expiry do not substitute for these workloads. The actual application executable in its release image also remains unverified. F10 stays open until these gates have results or an explicit scope decision.

### Rules for subsequent batches

**Remote testing paused after reported host-memory incident (2026-09-16).** The user reported overnight memory exhaustion requiring a physical restart. Post-restart inspection cannot establish the cause; no attribution is confirmed. Do not treat earlier passing tests or cleanup checks as proof that the harness could not have contributed. F11 containment-only probes were subsequently authorized and completed as recorded below; the pause guards have been restored. The user subsequently approved F12's bounded stage sequence, completed on 2026-09-17. That batch is finished and pause guards are restored; no unattended or unbounded workload is authorized.

- [x] **F11 — Verify remote test containment before resuming (immediate priority).** Review the harness for orphaned work and concurrent-run accumulation. Add a single-run admission lock, an independent hard deadline inside the container, explicit memory/swap/PID/CPU limits, and cleanup on timeout/disconnection. Fail closed if the requested Docker/cgroup limits cannot be verified. Bound log/cache storage, check host headroom, and retain a compact run manifest and resource/exit evidence locally. **Acceptance:** first perform local/static review; then obtain explicit agreement for a small, bounded remote containment check that demonstrates timeout/termination, enforced limits and zero owned leftovers. Resume full suites only after that evidence is reviewed. Preserve unrelated server services; use only the dedicated test resources and `/tmp` workspace. The incident cause remains unknown unless supporting evidence becomes available.
  - [x] **F11a — Local containment review and quarantine (2026-09-16).** Found no independent container deadline, no single-run lock, no explicit swap cap, writable host caches, unbounded logs, and no enforcement readback. Direct shell entrypoints bypassed the launcher pause. Removed the unsafe local launch/upload/format-import/cleanup paths; all shell entrypoints now refuse execution. No server connections or workloads were started during this review. These findings do not establish the incident cause.
  - [x] **F11b — Offline policy and fail-closed validation.** The locally ignored PowerShell helper now supports only offline review/self-tests (default invocation refuses). Prepared a smoke profile with immutable cached image identity, no network, non-root execution, readonly host input/root, 1 CPU, 2 GiB memory with no swap, 128 PIDs, bounded tmpfs/logs, and a 20-second in-container deadline plus 5-second kill grace. Evidence validation rejects missing/mismatched fields and host memory below 6 GiB available. These are review artifacts, not an implemented or runtime-verified launcher. Passed 81 offline assertions, PowerShell parsing/default-pause/JSON checks, static checks limiting shell stubs to diagnostic output plus exit, and Git-ignore checks. Git Bash execution was unavailable because its signal-pipe creation failed with Windows access denied; shell execution was not verified.
  - [x] **F11c — Implement and test the replacement supervisor locally while keeping remote execution paused (2026-09-16).** Implemented atomic local/server admission, owner/run/PID records, bounded SSH/Docker calls and output, host headroom/pressure/controller preflight, stopped-container configuration inspection, in-container cgroup/mount checks, and bounded local manifests. Cleanup verifies exact IDs/labels, distinguishes inspection errors from absence, handles partial upload/setup, waits or refuses if the original supervisor is alive, and releases the matching lock last. A crash can leave stale metadata/locks; recovery fails closed rather than promising unconditional zero residue. The first runnable path is deliberately a networkless 20-second smoke probe using only three size-limited, symlink/reparse-checked helper uploads; no source archives or Go suites are accepted. Full-suite source/network support is deferred until containment evidence and explicit resumption agreement. The ignored `scripts/README.md` records limits, implementation and recovery details.
    - **Local verification:** 15 regression test methods with parameterized failure cases passed against the actual supervisor/client/cleanup functions with mocked SSH/Docker, including disconnect, deadline, create/upload failure, daemon errors, foreign/replaced resources, repeated cleanup, live/dead lock owners, OOM/wrong exit/missing evidence, and bounded local child processes. PowerShell parse/default-pause/JSON checks, Bash syntax, actual shell refusal (exit 78), and Git-ignore checks passed. Bash and temporary-directory tests required local sandbox escalation; no server connections or Docker/Go workloads occurred. These tests replace the earlier duplicated offline policy assertions and do not prove remote enforcement.
  - [x] **F11d — Approved live containment and disconnect verification (2026-09-16).** With explicit user approval, verified the cached image and host headroom, then ran the networkless probe under the reviewed limits. Two initial probes exited immediately at interface validation, without OOM, and cleaned up successfully: the check incorrectly counted the kernel's `bonding_masters` control file. Corrected it to count interface symlinks. The successful probe verified cgroup memory/swap/CPU/PID values, readonly mounts and tmpfs capacities; exited 124 after approximately 20.1 seconds; recorded peak cgroup memory of 4,571,136 bytes (4.36 MiB), zero OOM/OOM-kill events, and no PID-limit events. A separate probe validated its boundaries before the local SSH client was forcibly terminated; all owned resources disappeared automatically within 22.73 seconds of disconnection, without recovery intervention. Final independent checks found no test-labeled containers/networks or `/tmp/wgslirp-test.*` workspaces/lock; the cached image ID was unchanged. No images or networks were created, and no Go suites ran. Final local regression/syntax checks passed and all remote pause guards were restored.
    - **Evidence limits:** local manifests retain inspected limits, logs, samples and cleanup checks. The disconnect case proves observed termination/removal after client loss; its final cgroup counters were not captured over the severed connection. These small probes do not establish production-load safety, prove all crash cases, or identify the original incident cause. Host available memory remained approximately 12.8 GiB with zero current memory PSI during final inspection.
- [x] **F12 — Prepare full-suite execution under the verified containment model.** Keep remote execution paused until a separate resumption agreement. Add bounded, symlink-safe source packaging and extraction only inside the container; a dedicated labeled network if dependency access is needed; memory-charged bounded caches; and a reviewed finite suite deadline. Retain the verified admission, enforcement readback, evidence and cleanup behavior. Run the smallest useful suite first, review its resource evidence, then expand deliberately. Do not treat F11 smoke results as permission or proof for sustained Go/race/fuzz workloads.
  - [x] **F12a — Bounded source preparation.** Implemented tracked regular-file-only USTAR packaging with symlink/reparse rejection, 4096-file/32 MiB content/40 MiB archive limits, digest verification, and rejection of traversal, duplicate/colliding paths, links, sparse/extended headers, unsafe modes and malformed trailers. The supervisor validates without host extraction; extraction occurs only in container tmpfs after a second digest check. Ignored environment-specific files are excluded. Local archive creation preserves pre-existing destinations on failure.
  - [x] **F12b — One finite stage per invocation.** Prepared config-package tests first (300-second container deadline); separate build, vet, unit, race, integration, integration-race and bounded fuzz stages have 600-second deadlines. There is no automatic full-suite chain. Preserved 1 CPU, 2 GiB RAM/no swap and 128 PIDs; source and all Go caches/temp files share the existing 768 MiB tmpfs. Added exact labeled-bridge creation/readback/cleanup for dependency traffic, restricted Go environment/toolchain behavior, bounded stage-specific supervision and success evidence. The bridge allows outbound traffic; it is not a destination firewall. No resource limit was increased.
  - [x] **F12c — Local verification.** 23 regression methods with parameterized cases passed, including malformed archives, ownership failures, missing/altered suite settings, partial setup, network failures/foreign endpoints, and mocked client/supervisor timeout/disconnection/recovery. Shell syntax, restored pause checks and offline PowerShell profile checks passed. Packaging the actual working tree produced a 77-file archive accepted by the system tar reader and excluded all ignored harness files; the temporary archive was removed. These checks used no SSH, Docker or Go workload and do not verify the new suite path on Linux.
  - [x] **F12d — Approved config-stage run and evidence review (2026-09-16).** Following explicit approval, ran `go test -timeout=90s -count=1 -parallel=1 ./pkg/config` with Go 1.23.12 in the bounded container. Dependency downloads, source digest verification and config tests passed; exit 0 after approximately 21.28 seconds including setup/compilation. Peak cgroup memory was 283,721,728 bytes (270.58 MiB), with zero memory-limit/OOM/OOM-kill or PID-limit events. The dedicated bridge, readonly source input, tmpfs caches and limits were verified; automatic cleanup and an independent final check confirmed zero owned containers, networks, workspaces or lock. Cached image identity was unchanged. An initial attempt failed locally before upload because the archive validator rejected valid cross-record tar padding; corrected the exact trailer-length calculation and added a regression (24 local test methods pass). No resource limit was increased. All remote pause guards were restored; broader stages remain unrun and require a separate decision.
  - [x] **F12e — Approved staged verification completed (2026-09-17).** Ran build, vet, unit, race, tagged integration, tagged integration-race and 10-second single-worker transport-boundary fuzz checks sequentially, reviewing each before proceeding. All seven exited 0; fuzzing completed 177,238 executions. Every stage recorded zero memory-limit/OOM/OOM-kill and PID-limit events, successful automatic cleanup, and an independent zero-owned-residue check. Resource ceilings were unchanged; each stage used a fresh cache and the same source digest `03fc49a3667d5e0b27fbe4738e19da6649c2d16bfcf1b513bcb99a0eb222492b`. Per-stage container duration / peak cgroup memory: build 29.72 s / 382.96 MiB; vet 34.98 s / 392.45 MiB; unit 40.93 s / 411.55 MiB; race 50.63 s / 443.28 MiB; integration 42.53 s / 408.31 MiB; integration-race 53.72 s / 442.01 MiB; fuzz 36.83 s / 313.84 MiB. Final host memory PSI averages were zero, with approximately 12.6 GiB available. Pause guards were restored and checked. Manifests, logs, samples, cleanup checks and a summary are retained locally by the ignored harness; none are intended for commit. These results verify this bounded test batch, not sustained production load or the cause of the original incident.

1. Work through the phases in order. Within a phase, use the numbered PR order. Later structural work depends on earlier correctness and test gates.
2. Keep behavior fixes separate from movement/formatting. Each PR addresses one failure mechanism or one coherent boundary.
3. Add a reproducer before each correctness fix where practical. Use deterministic synchronization instead of timing-dependent sleeps.
4. Preserve existing supported behavior unless a documented safety fix requires change. Record configuration, metrics, and Go API compatibility effects in the PR.
5. Every meaningful change receives independent review. The author cannot satisfy that requirement by self-review.
6. Every PR states problem, resulting behavior, tests, operational risk, and rollback. Revert individual changes using commit-addressed images; never roll back to known secret-exposing diagnostics as a routine mitigation.
7. Maintain a checklist of completed acceptance criteria. Reassess after each phase; do not mark a principle Strong merely because files were split.

## Phase 0 — Establish a trustworthy verification and release path

**Priority: immediate. Effort: small. Prerequisites: none.**

### PR 0.1 — Reproduce the baseline

- Provision a Go toolchain matching the declared supported version in a Linux development environment or CI runner.
- Run `go test -count=1 ./...`, `go vet ./...`, and `go test -race -count=1 ./...`; retain failures and skipped tests as the baseline.
- Build the production binary and container. Record platform support explicitly: Linux-specific syscall/procfs code currently exists in the command package.
- Inventory public Go interfaces, documented environment settings, emitted metrics, and constructor/lifecycle behavior. Distinguish active paths from test-only or unused paths.

**Acceptance:** reproducible commands and baseline results exist; every failure has an assigned follow-up; no unverified success claims.

### PR 0.2 — Gate publishing on the same revision's checks

- Align Go CI triggers with `master`, which the Docker workflow currently publishes from.
- Make publishing depend on successful build, unit/integration tests, and applicable static checks for the exact revision being published. Add a race gate as soon as baseline failures are repaired; do not silently waive failures.
- Replace CI's dependency-mutating `go mod tidy` setup with download/verification and a separate check that tidy produces no tracked changes.
- Separate build-only PR permissions from publication permissions; grant package write only to the publishing job.
- Keep immutable commit tags. Ensure PRs cannot publish images.
- Inspect and configure required checks, required independent approval, and protection against bypass on the release branch. Assign CODEOWNERS only to real maintainers who accept responsibility.

**Acceptance:** a deliberately failing test prevents publication; a PR builds without pushing; a successful release identifies its tested commit; review requirements are verified in repository settings.

**Principles:** 20, 25, 26, 27, 28.

## Phase 1 — Remove critical correctness and security defects

**Priority: highest runtime impact. Effort: medium. Depends on baseline verification.**

### PR 1.1 — Protect secrets and sensitive artifacts

- Replace raw WireGuard UAPI state logging with an allowlist of non-secret fields. Verify upstream state contents without writing secrets to logs.
- Remove private-key suffix logging; use peer public identifiers when diagnostic correlation is needed.
- Create secret-bearing configuration and plaintext captures with restrictive permissions. Account for existing files: creation modes alone do not tighten their permissions.
- Make configuration saves atomic where supported; preserve the previous valid file on failure.
- Give PCAP an explicit close lifecycle and actionable write/open failures. Document that captures contain plaintext traffic and provide a bounded capture policy when enabled.

**Acceptance:** sentinel private keys never appear in captured logs; sensitive files have intended permissions on the supported OS; failed save leaves the prior configuration readable; PCAP failures are visible and do not crash forwarding.

### PR 1.2 — Make component shutdown and ownership safe

- Fix delayed `EventUp` delivery racing with TUN event-channel closure.
- Choose and document a consistent lifecycle: initially prefer single-use components with repeated Stop/Close returning safely and restart explicitly rejected.
- Prevent concurrent writes/enqueues from accessing stopped bridges or closed channels. Initialize ICMP state during startup instead of unsynchronized first use.
- Stop producers, unblock I/O, and wait for owned goroutines in a defined order; do not wait while holding locks needed by those goroutines.
- Cancel metrics, handshake monitors, dial attempts, timers, and flow workers when their owner stops. Roll back resources on partial startup failure.
- Ensure queued pooled buffers are released exactly once during drop and shutdown paths.

**Acceptance:** immediate close after construction, double close, stop-before-start, start-after-stop, partial-start failure, and concurrent traffic/shutdown tests pass under the race detector; no owned goroutines remain after bounded shutdown.

### PR 1.3 — Repair health-check packet ownership and error propagation

- Copy health-observer data before the forwarding consumer may release it.
- Return forwarding failures to the bridge; health observation must not turn failed delivery into success.
- Start probes only after socket initialization completes.
- Check HTTP status and DNS transaction/result validity, not merely response arrival.
- Forward processor metrics through the health wrapper or collect metrics independently of wrappers.
- Keep health observation bounded and nonblocking; describe startup probes accurately rather than implying continuous readiness monitoring.

**Acceptance:** pooled and ordinary packets reach the observer intact; queue-full errors remain visible to senders; enabling health checks preserves forwarding metrics and outcomes; startup ordering is deterministic.

### PR 1.4 — Reject invalid configuration and packet boundaries

- Validate positive metrics intervals before ticker creation.
- Reject malformed supplied port, MTU, keepalive, queue, and buffer settings; report setting names and reasons without secret values.
- Reject incomplete explicitly listed peers instead of silently skipping them.
- Validate keys and routing settings before creating devices or starting goroutines.
- Validate negative offsets, slice lengths, IPv4 header/total lengths, and transport boundaries at external packet entry points.
- Define behavior for unsupported fragments and oversized frames. Return an explicit error/drop reason instead of silently truncating a TUN read.

**Acceptance:** table-driven invalid-input tests and packet fuzz seeds cover each boundary; malformed traffic/configuration cannot trigger slice/ticker panics; normal protocol tests remain passing.

**Principles:** 12–18, 20–22, 23.

## Phase 2 — Make configuration and resource limits truthful

**Priority: high. Effort: medium. Depends on Phase 1.**

### PR 2.1 — Introduce one validated configuration path

- Parse environment variables at the application boundary into typed configuration, then validate once.
- Pass configuration into constructors; remove environment reads from packet handlers, flow creation, and congestion control.
- Define precedence and defaults in one place. Emit a sanitized effective-configuration summary when requested.
- Apply TCP lifetime, ACK delay, reassembly capacity, and maximum-flow settings to the actual bridge.
- Inventory the separate `pkg/config` JSON/YAML path and public consumers. Consolidate it with adapters or deprecate it; do not remove exported APIs solely because the executable does not call them.
- Deprecate inactive processor-worker settings with a clear warning and migration note. Do not add a worker pool just to make an obsolete setting meaningful.
- Correct configuration examples, including mismatched peer indices and advertised defaults.

**Acceptance:** every supported setting has a test demonstrating its effective runtime value; changing a process environment variable after construction does not silently change an existing component; no documented no-op controls remain unexplained.

### PR 2.2 — Enforce bounded resource use

- Apply TCP and UDP flow caps to the production path; make admission atomic under concurrent creation.
- Bound pending dials, per-flow pending/reassembly/retransmission storage, and aggregate buffering where per-flow caps alone are insufficient.
- Give host dialing explicit cancellation and timeout semantics.
- Choose finite defaults using a representative memory/connection load baseline. Document any explicitly supported unlimited override and its consequences.
- Count admission failures distinctly and define protocol-appropriate refusal/drop behavior.

**Acceptance:** concurrent saturation stays within configured bounds, memory returns toward baseline after flow expiry, admission failures are observable, and existing traffic continues under overload within the stated resource budget.

### PR 2.3 — Make deployment privileges explicit

- Remove default application writes to IPv6 sysctls; move required namespace configuration into documented deployment configuration.
- Preserve non-root TCP/UDP operation. Document and verify the real ICMP activation path; granting a capability alone must not be presented as enabling a code path that is not started.
- Add a tested container example with dropped capabilities and read-only filesystem where compatible; explicitly mount writable capture/config paths when required.

**Acceptance:** the default container starts and forwards TCP/UDP without privileged mode or sysctl writes; optional ICMP behavior is verified in an explicit supported configuration.

**Principles:** 2–5, 11–17, 22, 23, 28, 29.

## Phase 3 — Make operational signals trustworthy

**Priority: high, after crash and configuration fixes. Effort: small–medium.**

### PR 3.1 — Correct metric semantics and synchronization

- Use atomic loads or owner-controlled snapshots for concurrently updated counters and flow state.
- Fix handshake peer double-counting, outbound overlay double-counting, and maximum saturation streak calculation.
- Move previous-snapshot state such as RTO deltas into the reporter instance; handle counter resets without unsigned underflow.
- Define units and meaning: accepted vs delivered vs dropped packets, bytes vs frames, active vs cumulative flows.
- Represent unavailable host statistics as unavailable, not valid zero values.

**Acceptance:** deterministic fixtures prove exact values; concurrent snapshot tests pass under race detection; health wrappers and multiple reporter instances do not change semantics.

### PR 3.2 — Stabilize errors and diagnostic contracts

- Replace error-string matching with typed or sentinel errors where callers make decisions.
- Preserve wrapped causes and attach actionable context at component boundaries.
- Add a metrics schema version additively and freeze existing documented keys until a deliberate migration.
- Separate parsing WireGuard state from formatting/logging it; reuse the parser for monitoring and metrics.
- Rate-limit repetitive failure logs and include useful drop/admission reasons. Avoid unbounded per-flow metric labels.
- Document startup probes, liveness, and readiness separately; introduce a persistent health endpoint only if deployment requirements justify it.

**Acceptance:** fixture tests protect metrics and error contracts; unknown state fields are tolerated; logs distinguish configuration failure, overload, and network failure without secret disclosure.

**Principles:** 2, 9, 14, 17–19, 21–24, 29.

## Phase 4 — Refactor around stable behavioral boundaries

**Priority: medium. Effort: large; several small PRs. Depends on Phases 1–3 and characterization tests.**

### PR 4.1 — Specify packet ownership and component dependencies

- Replace debug-dependent ownership semantics with explicit borrowed/copied/owned packet construction contracts.
- Document the transfer point, who releases a pooled buffer, whether retention is allowed, and behavior after release. Keep implementation economical; do not add reference counting unless fan-out actually requires it.
- Inject narrow dependencies for dialing, packet delivery, and scheduled work where tests need control.
- Move the shared packet-writer contract to its consumer or neutral boundary so WireGuard need not import a concrete socket package merely for an interface.
- Make constructors side-effect-free; start background work through explicit lifecycle methods.

**Acceptance:** packet behavior is independent of log level; each component can be constructed without network activity; ownership tests cover success, error, fan-out, and shutdown.

### PR 4.2 — Extract shared packet parsing and encoding

- Extract validated IPv4 parsing and common checksum/header construction used by production protocols and health probes.
- Preserve independent expected-byte fixtures in tests so tests do not simply reproduce the implementation.
- Keep protocol-specific behavior with its protocol; avoid a generic packet framework.

**Acceptance:** known packet fixtures, malformed packet tests, and fuzz targets pass; no behavior changes are hidden in code movement.

**Shared encoding implemented:** `internal/packetwire` owns fixed IPv4 headers,
TCP/UDP serialization and Internet/pseudoheader checksums. Socket bridges, ICMP
wrapping, fragmentation and health probes share these primitives. Allocation,
pooling, reservations, IP IDs, fragmentation policy and locks remain with callers.
Independent literal wire fixtures, dirty-buffer/size/zero-allocation tests and an
independent checksum fuzz oracle cover the boundary.

Two explicit corrections accompany extraction: health/legacy fragment builders
now encode computed-zero UDP checksums as `0xffff`; oversized private builders
reject before allocation instead of truncating lengths. Incoming omitted UDP
checksums remain accepted. No privilege or transport architecture changes.

**Encoding validation (2026-09-18):** Linux Go 1.23.12 unit and tagged integration
tests passed with the race detector, including encrypted TCP/UDP forwarding and
existing ownership/lifecycle regressions. Build, vet, module tidy/verification
(unchanged module files), and separate 10-second single-worker parser/encoder fuzz
campaigns passed (154,863 / 405,372 executions). The encoder fuzz smoke target is
also configured in CI; GitHub execution remains pending. The existing ACK
microbenchmark median was 692.9 ns/op, 34 B/op and 2 allocs/op; this is not encoder
throughput evidence. Gofmt and whitespace checks passed.

Across both integration/race runs plus final fuzz, build and vet, the largest
container peak was 794,804,224 bytes. All five bounded stages recorded zero
memory/OOM/PID-limit events and independently verified removal of owned
containers, networks, temporary workspaces and locks. Pause guards were restored.
Environment-specific scripts and raw evidence remain ignored/private. This is a
local change on `codex/architecture-hardening`; nothing is pushed.

- [x] Shared encoding and independent byte fixtures.
- [ ] Shared validated parsing: reconcile health-probe and socket acceptance/
  checksum policies explicitly before extracting a shared parser. Socket-local
  validated parsing already exists; the health probe still parses independently.

### PR 4.3 — Decompose TCP by responsibility

**Structural extraction sequence (2026-09-18):** tracked independently from F10
release/workload gates. Each boundary is a separate local commit; no upstream
push. Ownership and benchmark scope are recorded in
[pkg/socket/TCP_ARCHITECTURE.md](pkg/socket/TCP_ARCHITECTURE.md).

- [x] Connection establishment and pending-write flushing. Tagged integration/race passed; peak 815,554,560 bytes, zero resource-limit events and independently verified cleanup. Existing duplicate-dial, pending FIN, cancellation and admission regressions passed.
- [x] Registry/admission, lifecycle and expiry. Candidate publication now has an explicit state-lock contract; tagged integration/race passed, peak 801,849,344 bytes, zero resource-limit events and independent cleanup verification.
- [x] Incoming segment dispatch and reassembly. Validated borrowed segment views and locked payload/FIN processing are explicit; existing reassembly stays in `tcp_buffers.go`. Tagged integration/race passed, peak 829,521,920 bytes, zero resource-limit events and independent cleanup verification.
- [x] ACK/window handling and recovery. Locked ACK processing and delayed ACK scheduling live in `tcp_ack.go`; SACK/hole/RTO recovery lives in `tcp_recovery.go`, preserving state-before-transmit/SACK locking. Tagged integration/race passed, peak 799,698,944 bytes, zero resource-limit events and independent cleanup verification.
- [x] Diagnostics and snapshot formatting. TCP owns its extended metric snapshot and ACK/gating/RTO diagnostics; existing counter semantics, trace text and locking order are preserved. Tagged integration/race passed, peak 802,828,288 bytes, zero resource-limit events and independent cleanup verification.

**Final extraction validation:** all five tagged integration/race stages passed on Linux Go 1.23.12, including all unit tests, encrypted TCP/UDP forwarding, short-connection churn and existing lifecycle/ownership/sequence-wrap regressions. Final build, vet, module tidy/verification (unchanged module-file checksums), and 10-second single-worker fuzzing passed (157,931 executions). The ACK microbenchmark median changed from 654.7 to 679.5 ns/op (+3.79%), within the preselected 25% budget; 34 B/op and 2 allocs/op were unchanged. The largest container peak across the nine baseline/validation stages was 829,521,920 bytes. Every stage recorded zero memory/OOM/PID-limit events, independently verified zero owned container/network/workspace/lock residue, and restored the pause guards. Final build peak was 433,070,080 bytes, vet/benchmark 367,788,032 bytes, and fuzz 342,941,696 bytes. Gofmt and whitespace checks passed. Changes are separate local commits on `codex/architecture-hardening`; independent review remains pending and nothing was pushed. Environment-specific drivers and raw evidence remain ignored/private.

Full PR 4.3 performance acceptance remains separate: the bounded ACK benchmark
is only an initial latency/allocation gate, not forwarding throughput or dial/load
validation. PR 4.2 shared parsing and PR 4.4 dead-code cleanup remain separate.

Extract one boundary per PR, preserving protocol behavior:

1. Host connection establishment and pending-write flushing.
2. Flow admission, registry, expiry, and shutdown.
3. Incoming segment processing and reassembly.
4. Outbound segmentation, ACK/window handling, and retransmission scheduling.
5. Metric snapshots and diagnostic formatting.

- Retain congestion control through composition; introduce no inheritance or plugin registry.
- Define which lock or owner protects every mutable flow field, plus lock ordering. Avoid mixing unsynchronized field reads with registry locks that do not protect those fields.
- Compare throughput, allocation rate, latency, and memory against the baseline after consequential changes. Select regression budgets before evaluating results.

**Acceptance:** interfaces correspond to actual responsibilities, individual mechanisms can be tested without live Internet access, protocol behavior remains covered, and performance stays within the agreed budget.

### PR 4.4 — Remove verified dead paths and readability debt

- Remove unused private code and stale references to removed subsystems.
- Deprecate exported compatibility surfaces before removal where consumers may exist.
- Run formatting separately from behavioral refactoring; expand dense statements and replace historical comments with current invariants.
- Keep architectural decisions and lifecycle/ownership documentation adjacent to the owning packages.

**Acceptance:** dependencies form understandable boundaries; documentation describes active code; exported removals have explicit compatibility decisions.

**Principles:** 1–11, 17–19, 23, 29, 30.

## Phase 5 — Prove resilience and compatibility

**Priority: medium. Effort: medium–large. Existing unit/race checks continue throughout earlier phases.**

### PR 5.1 — Add missing protocol and lifecycle regression coverage

- Cover duplicate/out-of-order segments, sequence wraparound, loss/retransmission, zero windows, close races, queue saturation, dial failure, and flow expiry.
- Test pooled ownership with pooling enabled and disabled; logging must not alter correctness.
- Use local TCP/UDP fixtures and injectable clocks/dialers. Keep privileged tests explicitly separate from the ordinary suite.
- Run bounded fuzz smoke tests on PRs and longer fuzz campaigns on a schedule; retain discovered failures as regressions.

### PR 5.2 — Exercise the real executable and deployment

- Add an isolated Linux test that starts the production binary and a real WireGuard peer, forwards TCP/UDP to local services, and terminates under traffic.
- Verify optional overlay routing and optional ICMP separately.
- Add bounded load/fault scenarios for slow peers, unreachable destinations, exhausted flow budgets, failed capture storage, and shutdown during dialing.
- Define supported workload envelopes and measure recovery, memory, goroutine count, drop behavior, and throughput. Record limits rather than claiming universal performance.

### PR 5.3 — Protect supported contracts

- Maintain fixtures for metrics versions, environment aliases/defaults, and public packet/lifecycle behavior.
- Add a changelog and deprecation policy. Use release versions alongside commit tags when distributing stable releases.
- Pin build inputs sufficiently for repeatability, with a deliberate update process. Automate dependency review/scanning and image checks without claiming that a clean scan proves security.

**Acceptance:** all supported modes have documented, reproducible checks; fault tests demonstrate bounded failure/recovery; intentional compatibility breaks require a migration note and version decision.

**Principles:** 12–14, 19–24, 27–29.

## Phase 6 — Sustain Strong; earn Excellent with evidence

**Priority: ongoing, lowest immediate implementation impact.**

- Keep PRs focused and independently reviewed; use a short checklist covering contracts, concurrency, failure behavior, compatibility, and verification.
- Require release gates and immutable artifact identification. Periodically verify branch protection and publication permissions remain effective.
- Reassess this plan after significant architectural changes. Remove unnecessary abstractions and obsolete settings rather than accumulating compatibility scaffolding indefinitely.
- Use incidents, load results, and repeated release outcomes to choose further investment. Add tracing or more infrastructure only for demonstrated diagnostic needs.
- Record an owner for every ongoing check. Scheduled jobs are proposed work, not created by this plan.

**Excellent evidence:** repeated protected releases; no unexplained race/fuzz failures; demonstrated bounded shutdown and overload recovery; tested migrations; operational metrics that accurately explain observed failures. No numeric score substitutes for this evidence.

## Principle-by-principle completion map

| # | Principle | Main phase(s) | Strong completion criterion |
|---|---|---|---|
| 1 | Modularity | 4 | Components expose narrow contracts and can be understood/tested independently. |
| 2 | DRY | 2–4 | Defaults, config parsing, state parsing, and shared production packet logic have authoritative implementations. |
| 3 | KISS | 2, 4 | Active execution is clear; obsolete controls and unnecessary abstractions are removed. |
| 4 | YAGNI | 2, 4, 6 | Every retained feature has a supported consumer/use case; additions solve demonstrated needs. |
| 5 | Separation of Concerns | 2–4 | Startup/configuration, protocol mechanics, diagnostics, and deployment policy have distinct owners. |
| 6 | Single Responsibility | 4 | Components change for coherent reasons; TCP operations are separated by behavior rather than arbitrary file size. |
| 7 | Loose Coupling | 4 | Bridges use narrow collaborators instead of reaching through parent internals. |
| 8 | High Cohesion | 4 | Related flow/protocol behavior is owned together with its invariants. |
| 9 | Encapsulation | 3, 4 | Ownership and metrics snapshots hide mutable implementation state. |
| 10 | Composition over Inheritance | 4 | Existing composition remains simple; wrappers preserve contracts. |
| 11 | Dependency Inversion / Injection | 2, 4 | Environment/network/time dependencies are explicit at necessary seams. |
| 12 | Fail Fast | 1, 2 | Invalid configuration fails before resource startup; errors are actionable. |
| 13 | Defensive Programming | 1, 2, 5 | External boundaries and resource limits have meaningful adversarial tests. |
| 14 | Idempotency | 1, 3, 5 | Repeated shutdown/save operations have documented safe outcomes; forwarding preserves protocol semantics. |
| 15 | Least Privilege | 1, 2 | Default deployment is unprivileged; extra capabilities and sensitive access are explicit. |
| 16 | Secure by Default | 1, 2, 5 | Secrets remain private; resource defaults are finite and validated. |
| 17 | Explicit over Implicit | 2–4 | Dependencies, lifecycle, configuration, side effects, and ownership are explicit. |
| 18 | Immutable State | 1, 4 | Configuration is fixed after construction; mutable flow/buffer state has clear ownership and synchronization. |
| 19 | Testability | 4, 5 | Core mechanisms are deterministic and independently testable. |
| 20 | Automated Testing | 0, 1, 5 | Meaningful regressions, race checks, fuzzing, integration, and production-path tests gate appropriate changes. |
| 21 | Observability | 3, 5 | Metrics have correct units/counts, errors explain failures, and health signals reflect real checks. |
| 22 | Graceful Failure | 1, 2, 5 | Partial failures, saturation, and shutdown remain bounded and observable. |
| 23 | Backward Compatibility | 2–5 | Supported contracts have regression fixtures and changes have migration paths. |
| 24 | Versioned Interfaces | 3, 5 | Metrics/configuration/release contracts have deliberate version and deprecation policies. |
| 25 | Code Review | 0, 6 | Independent review is required and verified in repository settings. |
| 26 | Small Changes | All | Behavior fixes, formatting, and refactors are separated into reviewable, reversible changes. |
| 27 | CI/CD | 0, 5 | Publication requires passing checks on the same commit and artifacts are identifiable. |
| 28 | Infrastructure/Configuration as Code | 0, 2, 5 | Supported builds/deployments and required runtime settings are reproducible from versioned files. |
| 29 | Documentation Close to Code | 2–6 | Current contracts, assumptions, examples, and decisions live with their code. |
| 30 | Readability First | 4, 6 | Formatting, naming, function scope, and invariant documentation support straightforward review. |

## First implementation milestone

Complete Phase 0 and Phase 1 before beginning broad TCP refactoring. The milestone is reached when publishing is test-gated, sensitive diagnostics are repaired, lifecycle/health regressions pass, and invalid configuration cannot cause the identified panics. Then make resource controls effective before investing in structural cleanup.
