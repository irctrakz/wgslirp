# Architecture improvement plan

## Objective and evidence

Bring all 30 reviewed principles to **Strong**, with **Excellent** reserved for areas supported by sustained operational evidence. Prioritize preventable crashes, secret exposure, unsafe releases, and ineffective limits before refactoring.

Baseline: static review of commit `aded0ae`. Builds, tests, and race detection were not run because Go was unavailable on PATH. Findings below must be reproduced or verified against the implementation before fixes are considered complete. Repository settings such as required reviews and branch protection remain unverified.

This document is an implementation backlog, not a claim that the changes have been made.

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

Uncommitted work. Linux Go 1.23.12 verification passed: build, vet, unit tests, race tests, tagged integration tests with and without race detection, and 271,459 parser fuzz executions. Resource regressions cover fast-dial saturation, fallback/RST cancellation, hard failures, duplicate successful dials, overlapping reassembly, flush/ACK/teardown release, retransmission backpressure, shared TCP/UDP storage, and isolation of an existing flow during aggregate exhaustion. Implementing commit: pending local commit; nothing pushed.

- F01 implementation reserves before preliminary dialing and transfers the same reservation through asynchronous fallback. Dial contexts cancel on RST/flow removal and bridge shutdown; all exit paths release once. Saturation rejects before opening another socket.
- F02 implementation introduces a shared socket buffer budget covering retained TCP pending/reassembly/retransmission data, queue-entry allowances, asynchronous ICMP quotes and TCP/UDP reader buffers. Reassembly reserves before allocation and accounts unique bytes plus temporary merge storage; ACK, flush and teardown release ownership. Per-flow retransmission storage applies backpressure; global send-storage exhaustion resets only the affected flow.
- Finite defaults are 64 pending dials, 64 MiB shared storage, 64 KiB per-flow pending payload and 1 MiB retransmission payload. New zero-valued controls select these defaults; they do not request unlimited resources. F03 remains open for representative workload measurements and tuning.
- Typed configuration and additive metrics expose the budgets, peaks and refusal attempts. F05 remains open for consistent reason-specific admission metrics across all resource types.

**F02 remainder (explicitly deferred):** downstream WireGuard/processor queues and transient packet-synthesis copies do not yet participate in the shared reservation budget. Add ownership-aware byte accounting at those boundaries, test queue rejection/drain/close, and measure total-memory recovery under load. Kernel buffers and Go GC/allocator overhead are outside application-owned byte accounting and must be included in the F03 workload/RSS evidence. Do not claim F02's end-to-end acceptance criteria complete based only on socket-buffer reservation tests.

#### Next: resource budgets and configuration (PR 2.1/2.2)

- [ ] **F01 — Bound pending TCP dials.** Reserve capacity atomically **before the preliminary fast dial**, share the budget with asynchronous fallback, and release reservations on success, failure, duplicate-flow races, cancellation and shutdown. Define timeout, queue/rejection behavior and refusal signaling. **Acceptance:** concurrent SYN storms never exceed the configured dial budget, established flows keep working, and reservations return to zero after cancellation/shutdown.
  - Implementation and regression verification complete in the current uncommitted batch; record its commit when committed locally. The checkbox remains open until that commit is recorded.
- [ ] **F02 — Bound total buffering.** Inventory pending client data, out-of-order reassembly, retransmission queues and delivery queues; enforce per-flow and aggregate byte budgets before allocation/enqueue. Define ownership and release on ACK, flush, rejection, expiry and teardown, including retransmission and overlap handling. **Acceptance:** concurrent saturation cannot exceed accounted budgets; teardown releases all reservations; memory trends back toward baseline; one overloaded flow does not stop unrelated traffic.
  - Socket-owned budget and reservation regressions are implemented and verified above. Downstream queue accounting, transient synthesis accounting and total-memory/load evidence remain open as explicitly described in the F02 remainder.
- [ ] **F03 — Select measured finite defaults.** Measure representative connection counts, memory use and overload recovery, then choose defaults for flows, pending dials and buffers. Document any unlimited override and migration from today's zero/unlimited flow caps. **Acceptance:** reproducible load evidence supports the defaults and tests verify default and override behavior.
- [ ] **F04 — Finish typed configuration migration.** Move remaining packet/flow-time environment reads (dial timing, congestion control, socket buffers, window scaling and SACK) and other constructor tuning into validated configuration. Resolve JSON/YAML adapters, precedence and inactive controls as described in PR 2.1. **Acceptance:** each supported setting has effective-value coverage; environment changes after construction cannot alter existing components.
- [ ] **F05 — Make admission failures observable (also PR 3.1/3.2).** Distinguish active-flow, pending-dial, per-flow-buffer and aggregate-buffer refusals using bounded-cardinality counters and actionable errors. **Acceptance:** saturation fixtures prove exact counts and protocol-appropriate behavior, without counting one rejection multiple times.

#### Remaining deferred correctness and verification work

- [ ] **F06 — Finish lifecycle audits (PR 1.2/5.1).** Audit remaining mocks and callback ownership; address blocking or reentrant delivery callbacks and stale flow-identity removal in maintenance paths. **Acceptance:** targeted concurrent Start/Stop/Close, expiry/replacement and blocked-callback tests pass under race detection with documented shutdown bounds.
- [ ] **F07 — Complete TCP FIN recovery (PR 5.1/5.2).** Replace reliance on the current short FIN grace period with explicit, bounded close-state and retransmission behavior. **Acceptance:** lost/duplicate FIN and ACK, half-close and shutdown-under-traffic fixtures show no premature data loss or leaked workers.
- [ ] **F08 — Resolve remaining packet-validation scope (PR 1.4/5.1).** Define and test checksum-validation and IP-option policy. Record an explicit support decision for incoming fragment reassembly; retain tested rejection unless a supported use case justifies bounded reassembly. **Acceptance:** supported and rejected cases are documented and covered by regression/fuzz tests. Fragment reassembly is not implicitly promised by this item.
- [ ] **F09 — Finish metrics semantics and dependency separation (PR 3.1/3.2/4.1).** Complete the phase backlog for exact counters, reporter-owned state, stable snapshots/contracts and narrow bridge collaborators. **Acceptance:** deterministic metrics fixtures and independent component tests demonstrate the contracts, not merely file movement.
- [ ] **F10 — Verify external review/release controls (Phase 0/5/6).** Confirm branch protection and independent approvals, execute workflows and container release checks, verify dependency tidy checks, and add production-path/load coverage. **Acceptance:** record actual settings and run evidence; passing local tests alone does not close this item. Respect the current instruction not to push upstream.

### Rules for subsequent batches

**Remote testing paused after reported host-memory incident (2026-09-16).** The user reported overnight memory exhaustion requiring a physical restart. Post-restart inspection cannot establish the cause; no attribution is confirmed. Do not treat earlier passing tests or cleanup checks as proof that the harness could not have contributed. The local environment-specific runner now refuses to start; no additional remote workloads should run until the safety follow-up below is completed and resumption is explicitly agreed with the user.

- [ ] **F11 — Verify remote test containment before resuming (immediate priority).** Review the harness for orphaned work and concurrent-run accumulation. Add a single-run admission lock, an independent hard deadline inside the container, explicit memory/swap/PID/CPU limits, and cleanup on timeout/disconnection. Fail closed if the requested Docker/cgroup limits cannot be verified. Bound log/cache storage, check host headroom, and retain a compact run manifest and resource/exit evidence locally. **Acceptance:** first perform local/static review; then obtain explicit agreement for a small, bounded remote containment check that demonstrates timeout/termination, enforced limits and zero owned leftovers. Resume full suites only after that evidence is reviewed. Preserve unrelated server services; use only the dedicated test resources and `/tmp` workspace. The incident cause remains unknown unless supporting evidence becomes available.

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

### PR 4.3 — Decompose TCP by responsibility

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
