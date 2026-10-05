# Architectural reassessment — 2026-09-21

**Latest review (2026-09-30):** [HARDENING_REVIEW.md](HARDENING_REVIEW.md)
consolidates current progress and remaining work, and revises the earlier
KISS/DRY/readability judgment following closer inspection of TCP code paths.
The ratings below remain the historical assessment, with dated updates.

**IPv4 fragment update (2026-10-05):** observed deployment fragmentation now
justifies an opt-in bounded reassembler. It preserves default rejection and the
userspace forwarding model; ownership, quotas, expiry and diagnostics are
documented in [IPV4_FRAGMENT_REASSEMBLY.md](IPV4_FRAGMENT_REASSEMBLY.md).
Default enablement remains a separate evidence review. Historical YAGNI rationale
below describes the earlier unsupported scope, rather than the current opt-in.

**Implementation update (2026-09-22):** A1/F10e.2 is now accepted for its explicitly
revised finite low-rate natural-GC profile: three fresh ordinary and three fresh
race runs passed. See [ENCRYPTED_WORKLOADS.md](ENCRYPTED_WORKLOADS.md) for criteria,
measurements and retained failed tight-guard evidence. A2/A3 are next; larger
workloads and release-image validation remain open. The ratings and analysis
below describe the assessed source revision, not a new blanket rating upgrade.

**A3 default-policy update (2026-09-22):** default IPv6 sysctl writes are now
disabled; explicit `WG_DISABLE_IPV6=true` / `DeviceOptions.DisableIPv6=true`
preserves the documented legacy opt-in. Release-image and optional ICMP
deployment checks remain open. The snapshot findings below retain their original
revision context; the default-policy portion of A3 is implemented.

**A3 ICMP integration update (2026-09-30):** PR #4's ping-socket fallback is
integrated into library ICMP mode with bounded request correlation, shared
buffer accounting and joined shutdown. Ordinary and race integration tests
verified echo forwarding without raw-socket privileges; permission-related
skips were disabled for those checks. The executable still selects TCP/UDP-only
mode. Its optional ICMP activation policy, privileged raw ICMP validation and
the actual release-image check remain open; this does not close A2/A3 overall.

## Scope and conclusion

Assessed source: `1ef5ca73142150e64603e9304f5e803f2bded959` on
`codex/architecture-hardening`. This is a static reassessment of implementation,
test assertions, workflow configuration and recorded local validation. No tests,
remote workloads or GitHub actions were run for this assessment.

**The code has a strong architectural foundation. The next investment should be
memory/release validation and a few specific contract/default fixes, rather than
another broad TCP refactor.**

At the documented small IPv4 TCP/UDP workload scope: **21 principles are Strong
on inspected evidence, one is Strong by assumption, and eight are Partial.**
None is rated Excellent: the plan reserves that rating for sustained operational
and release evidence. These are qualitative judgments, not a percentage of
correctness, protocol completeness or production readiness.

Per the user's instruction, independent code review and verified branch
protections are **assumed satisfied**. They do not create backlog items or lower
ratings here. This does not retroactively verify repository settings or change
the historical evidence in the release record. Actual workflow execution,
release artifact behavior and workload acceptance remain separate questions.

## Rating definitions

- **Strong:** clear ownership/contracts, coherent implementation and meaningful
  recorded regression evidence for the supported scope; minor bounded debt can remain.
- **Partial:** a concrete implementation or material validation gap prevents the
  principle's completion criterion from being met across that scope.
- **Excellent:** Strong plus repeated operational, release and fault/load evidence,
  as defined in the architectural plan.

The ordinary unit/integration suite with race detection, build/module checks and
vet passed in the latest recorded batch. The explicit natural-GC encrypted soak
did not pass repeatably. Representative negative controls previously demonstrated
unit, race, integration-race, build and vet failure propagation. That establishes
the harness can reject those failures; it does not establish exhaustive test coverage.

## All 30 principles

Paths below identify inspectable evidence, including adjacent regression tests.
Remaining actions refer to the ordered backlog further down.

| # | Principle | Rating | Evidence and remaining limit |
|---|---|---|---|
| 1 | Modularity | Strong | `internal/packetwire`, typed configuration, transport bridges and reporter boundaries have distinct owners. TCP connection, registry, receive, ACK/recovery and diagnostics are separated by responsibility; see [TCP_ARCHITECTURE.md](TCP_ARCHITECTURE.md). |
| 2 | DRY | Strong | Shared parsing/encoding, `internal/envconfig`, WireGuard state parsing and common reservation/delivery helpers replace duplicated production logic. Independent test wire oracles are useful redundancy. Legacy config is explicitly separate and deprecated. |
| 3 | KISS | Strong | Inline forwarding, bounded queues and function collaborators avoid a generic packet framework. PR 4.4 removed verified unused helpers. Remaining protocol complexity corresponds to real TCP behavior. |
| 4 | YAGNI | Strong | Unsupported incoming fragments are deliberately rejected; no speculative reassembly service, scheduler framework or health endpoint was introduced. Retaining public compatibility adapters is justified by unknown external consumers. |
| 5 | Separation of Concerns | Strong | Startup composes components in `cmd/wgslirp/main.go`; wire mechanics, resource ownership, health policy and diagnostic formatting have distinct locations. Process-wide capture/pooling remain explicit single-instance policies. |
| 6 | Single Responsibility | Strong | TCP operations now have behavioral boundaries and documented lock ownership. A shared `tcpFlow` remains appropriate for one protocol state machine; file extraction alone is not the evidence. |
| 7 | Loose Coupling | Strong | Neutral `core.PacketWriter`/`PacketBufferReserver`, dial/delivery functions and reporter interfaces provide useful seams. Bridge parent references and the TUN's socket budget factory remain bounded internal coupling; A7 is optional cleanup. |
| 8 | High Cohesion | Strong | ACK/recovery, buffer accounting and registry identity each live with related state/invariants. Pure encoding has no socket, allocation-budget or lifecycle responsibilities. |
| 9 | Encapsulation | Partial | Private flow state and detached metric/config snapshots are good. Public `NewPacket`/`SimplePacket.Data` still change aliasing/copy behavior with global debug mode; tests explicitly preserve this. Finish the explicit packet API portion of PR 4.1 (A4). |
| 10 | Composition over Inheritance | Strong | Go interfaces, delivery functions, processors and congestion-control collaborators assemble behavior without class hierarchies or a plugin registry. |
| 11 | Dependency Inversion / Injection | Strong | Lookup functions, private dial/delivery collaborators, snapshot interfaces and explicit expiry time allow focused tests. Concrete host connection types remain where socket operations require them; a universal clock/network abstraction would not automatically improve this. |
| 12 | Fail Fast | Strong | Application environment snapshot and typed validation precede startup resources; malformed packet boundaries and reservations reject before retention. Explicit constructors return errors; legacy no-error adapters document bounded fallback. |
| 13 | Defensive Programming | Strong | `internal/packetwire/parse.go`, admission/accounting and health validation have malformed-input, saturation, cancellation and fuzz regressions. Deliberately unsupported IP options/fragments are documented rather than silently accepted. Broader protocol coverage remains A5. |
| 14 | Idempotency | Strong | Request/join shutdown, repeated reservation release, identity-checked flow removal and fixed capture/pooling policies have regressions. Packet release remains single-owner; this is not permission to release one packet concurrently. |
| 15 | Least Privilege | Partial | Core TCP/UDP uses ordinary host sockets and in-memory TUN; Dockerfile uses a non-root user. `DefaultDeviceOptions` still enables best-effort sysctl writes, library socket defaults select raw ICMP, and hardened release-image behavior is unverified (A2/A3). |
| 16 | Secure by Default | Partial | Finite application resource defaults, disabled capture, private capture/config files, strict parsing and sanitized config output are substantial improvements. Default sysctl mutation and deployment examples/build provenance need A2/A3; README also prints a private key in setup instructions. No known dependency vulnerability is asserted by this assessment. |
| 17 | Explicit over Implicit | Partial | Startup snapshots, lifecycle methods, callback ownership and metric units are explicit. Public debug-dependent packet semantics and default process sysctl side effects remain exceptions (A3/A4). |
| 18 | Immutable State where Practical | Strong | Constructors detach retained settings; capture/pooling are frozen; snapshots are copied. Mutable protocol buffers/state use documented owners and locks. Borrowed slices are read-only by contract, not enforced by Go's type system. A4 improves that public contract further. |
| 19 | Testability | Strong | Literal wire fixtures, injected failures, deterministic expiry, isolated metrics/state parsing and loopback peers allow useful tests without the public Internet. Process-global policies still constrain embedding/multiple instances but do not justify a new service framework. |
| 20 | Automated Testing | Strong | Unit, race, tagged integration, parser/encoder fuzzing, encrypted component forwarding, churn and performance fixtures exist with recorded runs; negative controls tested failure detection. Binary/image E2E and stable soak acceptance remain A1/A2/A5, so this is not an Excellent or complete-workload rating. |
| 21 | Observability | Strong | `OBSERVABILITY.md` specifies schema version, units, refusal ownership, unavailable state, detached snapshots and bounded repeated logs; contract tests check exact values. Startup probes have an explicit limited meaning. Add runtime memory diagnostics only as A1 demonstrates a need. |
| 22 | Graceful Failure | Partial | Saturation, capture failure, cancellation, half-close/FIN recovery and shutdown have meaningful coverage. Encrypted memory acceptance is unresolved; actual executable termination under traffic remains unverified (A1/A2). Arbitrary blocking callbacks/filesystems are explicitly outside unconditional shutdown bounds. |
| 23 | Backward Compatibility | Strong | Public adapters, error identities, metric keys and inactive settings are retained; stricter validation/default changes have migration notes and tests. This does not promise unchanged behavior for previously malformed inputs. Centralize future release policy in A6. |
| 24 | Versioned Interfaces | Partial | JSON metrics schema v1 and compatibility fixtures exist. A project-wide release/deprecation policy and changelog are still missing; image SHA tags alone are not a version policy (A6). |
| 25 | Code Review | Strong — assumed | Independent review and verified branch protections are satisfied assumptions supplied by the user. No external verification task is charged against this assessment. |
| 26 | Small Changes | Strong | Git history separates five TCP extractions, encoding, parsing, cleanup, performance evidence and encrypted workloads into local commits. The aggregate branch still needs the assumed independent review; no new review gap is inferred. |
| 27 | CI/CD | Partial | Reusable test workflow gates publication on the same revision with limited write permissions and timeouts. Published images are rebuilt without an image runtime gate; tested artifact identity/promotion and rollback evidence remain A2. Assumed branch protection does not supply those checks. |
| 28 | Infrastructure/Configuration as Code | Partial | Dockerfile, workflows, modules and typed runtime settings are versioned. Floating base-image/action tags, differing CI/image toolchain selection, absent hardened runtime verification and an undocumented update/promotion process prevent full reproducibility (A2/A3). Private machine-specific launchers correctly stay outside the repository. |
| 29 | Documentation Close to Code | Strong | Ownership, configuration, metrics, wire policy, resource limits and TCP boundaries are documented beside the repository and tests. This assessment exposes unfinished phase items that the checked F-register alone can obscure. Small README corrections remain A3/A7. |
| 30 | Readability First | Strong | `HandleOutbound` dispatch, named responsibilities, lock comments and extracted pure helpers make review substantially easier. Some stale comments and long coherent protocol routines remain; shorten only where comprehension improves (A7). |

## Remaining work, ordered by impact

### A1 — Resolve encrypted memory acceptance (F10e.2)

**Highest priority; investigation/validation, with a production fix only if warranted.**
The low-rate soak crossed its unchanged 64 MiB heap guard. In the final diagnostic,
one forced collection reduced heap from 68,034,344 to 51,327,360 bytes, against a
51,330,168-byte initialized baseline. This supports reclaimable growth in that
run, not a proven live leak or natural-GC recovery. A socket reservation budget
does not cap wireguard-go, the allocator, fixture peers or process RSS.

Collect bounded allocation/post-drain heap and RSS evidence, separate race/fixture
overhead from production behavior, and establish a predeclared criterion that
observes natural GC cycles relative to initialized live memory. Preserve failed
results. Do not silently raise guards, relax server limits or force GC in the soak.

**Done when:** repeated finite low-rate runs meet the declared natural-GC criterion,
payload and recovery checks pass, reservations drain, and containment/cleanup are
verified. Then widen load. See [ENCRYPTED_WORKLOADS.md](ENCRYPTED_WORKLOADS.md).

### A2 — Test and identify the actual release artifact (F10d / PR 5.2–5.3)

**High impact; implementation plus validation.** Current encrypted tests exercise
production components in process, not `main`, signal handling or the Dockerfile.
The publish job builds an image after Go tests without running that image.
CI selects Go 1.23.12 while the Dockerfile selects floating `golang:1.23-alpine`;
runtime base images and actions also use mutable tags.

Add a finite executable/image startup, invalid-config, encrypted TCP/UDP and
SIGTERM-under-traffic gate. Build once, test that artifact, and promote the same
digest; retain an immutable previous digest for a bounded rollback check. Pin
build inputs with a deliberate update/scanning policy; module verification is
not vulnerability scanning. Specify all runtime resource/security bounds in
versioned portable configuration. Keep machine-specific SSH launchers private.

**Done when:** the exact candidate image passes the runtime gate and its immutable
identity and rollback procedure are reproducible. Workflow/publication execution
can remain an explicitly pending authorized release step; upstream actions and
host image builds are not authorized by this assessment.

### A3 — Finish privilege defaults and deployment guidance (PR 2.3)

**High impact, relatively small implementation; coordinate with A2.** Make the
application's default stop attempting `/proc/sys/net/ipv6/...` writes. Preserve
any explicit legacy opt-in with a migration note or move namespace policy to
deployment configuration. Decide/document the library's raw-ICMP default
separately from the executable's explicit TCP mode.

Test/document non-root TCP/UDP with all capabilities dropped, no-new-privileges
and read-only root; allow only explicit writable paths. Clarify the actual raw
ICMP activation path: adding CAP_NET_RAW alone does not select it in the executable.
Correct README's blanket zero-privilege/ICMP wording and remove private-key echo
from setup guidance. Preserve all core userspace forwarding behavior.

**Done when:** default startup attempts no sysctl mutation, TCP/UDP passes the
hardened runtime fixture, and optional privilege-dependent behavior is accurately
documented and either verified or explicitly outside supported deployment scope.

### A4 — Finish explicit public packet ownership (PR 4.1 remainder)

**Medium impact; focused API change with compatibility.** Add economical explicit
borrowed/copied packet construction/access paths whose behavior is independent
of debug mode. Migrate maintained production callers; preserve/deprecate legacy
`NewPacket`/`Data` semantics deliberately. Keep single-owner pooled release and
read-only borrowed lifetime rules; do not introduce reference counting without
a real fan-out requirement.

**Done when:** mutation/aliasing, retention, rejection, fan-out and release fixtures
prove the explicit APIs have identical ownership semantics at both debug settings;
legacy compatibility remains tested and documented. Existing internal borrowed
access and budgeted synthesis already solve much of the production-path problem.

### A5 — Expand workload evidence after A1 (remaining F10e / PR 5.1)

**Medium impact, potentially substantial effort.** Sequence finite encrypted
churn/cap sizing, calibrated delay/loss/reordering and SACK/receiver-reneging
checks, then justified full-sequence and wall-clock expiry workloads. The default
64 TCP slots include TIME-WAIT: the documented roughly 16 host-first closes per
minute constraint matters more than another small ACK microbenchmark.

**Done when:** each claimed supported profile has explicit load/duration limits,
exact payload/failure/recovery assertions and resource evidence. Retain documented
unsupported IP fragmentation/options and wrap-reassembly policies unless a real
supported workload requires implementation changes. Do not run overnight tests.

### A6 — Centralize compatibility/release policy (PR 5.3)

**Medium-to-low effort.** Add a concise changelog and version/deprecation policy
covering Go APIs, environment defaults/aliases, metric schema and distribution
versions. State additive versus breaking changes, removal/migration rules and
how image digests map to releases. Reuse existing contract fixtures.

**Done when:** the next release can identify intentional behavior changes and
migration steps without reconstructing the chronological architecture log.

### A7 — Optional dependency/readability cleanup (PR 4.1 / PR 4.4)

**Lowest impact; no broad redesign needed for Strong.** If it simplifies ownership,
relocate/inject the TUN fallback budget factory so its interface-only use no longer
imports `socket`; preserve finite fallback and shared accounting. Review residual
bridge-parent metric access only where it obstructs tests. Remove remaining stale
FlowManager/simple-mode comments and fix documentation claims in small edits.
Do not split state into independently locked services or remove public compatibility
APIs just to improve a score.

## What this assessment does not reopen

F01–F09 implementation, F11/F12 containment, shared parsing/encoding, the five
TCP structural extractions, verified dead-code cleanup and the bounded loopback
performance gate retain their recorded scope. No evidence here requires replacing
the userspace TCP/UDP design or adding kernel privileges. A1 is the immediate next
deliverable; A2/A3 are the largest remaining release/default changes.

The current roadmap is [ARCHITECTURE_PLAN.md](ARCHITECTURE_PLAN.md). Historical
external-review statements in [RELEASE_VALIDATION.md](RELEASE_VALIDATION.md) remain
historical evidence; the user's review/protection assumption applies to this
assessment only. Excellent should be earned through repeated measured results,
not speculative abstractions or a blanket upgrade of all ratings.
