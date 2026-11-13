# Jellyfin plugin implementation plan

Created: 2026-10-29

W1 was approved at `459f6f1`. W2 was approved at `8b10bbd`.
W3 was approved at `539d884` and recorded in `623f6ff`.
W4 was approved at `553f165` and pushed with approval commit `2155c9e`.
W5 is ready for review on `codex/jellyfin-integration`.

## Architecture and scope

Build two coordinated projects with a versioned binary protocol between them:

- **wgslirp repository:** retain the Go networking core and deliver a standalone
  helper executable, protocol, destination policy, peer operations and binary releases.
- **Jellyfin plugin repository:** deliver the C# management plugin, dashboard,
  durable settings, helper supervision and plugin packages. Repository name and
  location are still to be selected.

The Go executable is the permanent networking implementation. There will be no
C# networking rewrite, shared-library binding, copied Go source or Git submodule
in the plugin repository. The plugin will bundle explicitly pinned binaries;
users will not need Go installed or a separate wgslirp installation.

Linux is the first validated platform, not the final architectural boundary.
The initial purpose is remote access to configured Jellyfin endpoints using
ordinary WireGuard clients and a narrow route to a virtual service address.
NAT traversal, relay services, automatic client integration and per-peer IP
attribution inside Jellyfin are outside the initial scope.

| Concern | Owner |
| --- | --- |
| WireGuard, packets, forwarding and resource limits | wgslirp |
| Destination mapping and enforcement | wgslirp |
| Live peer operations and connection cleanup | wgslirp |
| Helper protocol, portable status and executable releases | wgslirp |
| Persistent settings, peer records and dashboard | Jellyfin plugin |
| Executable selection, supervision and recovery | Jellyfin plugin |
| Client provisioning UI and configuration downloads | Jellyfin plugin |
| Playback acceptance and plugin distribution | Jellyfin plugin |

All package paths and interfaces proposed below are design proposals. Existing
source links identify starting points, not completed integration surfaces.

## Repository 1: wgslirp

Complete these work packages in order, with the early integration overlap
described in the delivery checkpoints below.

### W1 — Define the helper contract and compatibility rules

- [x] Add a protocol specification, machine-readable message definitions,
  example exchanges and reusable compatibility fixtures.
- [x] Use newline-delimited JSON over stdin/stdout, with stderr reserved for logs.
- [x] Define protocol version negotiation, capability reporting, request IDs,
  maximum message size, bounded request queues, timeouts and structured errors.
- [x] Serialize mutations and include process-instance and configuration-revision
  identifiers so clients can recognize stale responses.
- [x] Specify the initial operations.

  | Operation | Purpose |
  | --- | --- |
  | Handshake | Report binary version, protocol versions, platform and capabilities |
  | Validate configuration | Check settings without opening network resources |
  | Start | Start one runtime using explicit configuration |
  | Status | Return state, configuration revision and sanitized statistics |
  | Add/remove peer | Change peer access without restarting unrelated peers |
  | Stop | Shut down, report completion and exit |

- [x] Mark server keys, listener settings, destination mappings, MTU and resource
  budgets as restart-required in protocol version one. Support live peer changes.
- [x] Define readiness as configuration applied and WireGuard listener operational;
  do not equate it with external reachability.
- [x] Define reconciliation after a mutation timeout: the outcome is uncertain
  until status is checked; the caller must not blindly repeat the operation.
- [x] Verify fixtures for successful exchanges, incompatible versions, malformed
  and oversized input, unknown operations, duplicate requests and reconciliation.

**Complete when:** the contract and fixtures are sufficient for independent Go
and C# implementations and all listed protocol behaviors are specified.

Review the [protocol specification](HELPER_PROTOCOL.md),
[message schema](../protocol/v1/message.schema.json) and
[shared compatibility fixtures](../protocol/v1/README.md).

W1 review follow-up:

- [x] Define cancellation, publication and teardown for EOF and fatal pipe or
  queue errors. Add held-start, held-revocation and queue-overflow transcripts.
- [x] Define error precedence separately for the generic envelope and the
  operation payload. Cover inputs that fail multiple checks.
- [x] Check the complete applied peer set on every status response and handle
  repeated handshake requests after negotiation.
- [x] Require a fixed startup failure reason for an occupied address, denied
  permission or other failure. Cover accepted and rejected error shapes.

Verification on 2026-11-12 passed the Draft 2020-12 schema, 19 frame cases,
19 message shapes and 18 session transcripts. In-memory negative checks rejected
an omitted untouched peer, an incorrect error for an invalid envelope, a
success response after EOF and a success response after queue overflow. These
checks exercise the contract and fixture checker. Cancellation and resource
cleanup in a running Go helper remain for later work.

The protocol baseline delivery checkpoint stays open until W1 is accepted in review.

Second W1 review follow-up

- [x] Specify interrupted stdout writes, diagnostic delivery failure and
  shutdown timeout precedence. Cover overflow with no delivered diagnostic,
  overflow followed by a cleanup timeout, and EOF during a partial response.
- [x] Track assigned and reserved addresses across live peer changes. Check
  virtual service address conflicts at validation, startup and live addition.
- [x] Check the bound port and server public key in every running status
  response against the successful startup response.

The revised verification passed the Draft 2020-12 schema, 19 frame cases,
19 message shapes and 23 session transcripts. In-memory probes accepted
overflow without a diagnostic and rejected a lower-priority diagnostic after
a cleanup timeout, output after an interrupted frame, reuse of a revoked
address, both configuration and live-add service address conflicts, and
changes to the bound port or server key. Runtime behavior remains to be
verified against the future helper.

Third W1 review follow-up

- [x] Check requested, default and ephemeral port behavior at startup. Verify
  the reported public key against the fixture's known private/public key pair.
- [x] Reject duplicate guest IP and port mappings, even when their host targets
  differ. Cover peers whose key matches the server key at validation, startup
  and live addition.
- [x] Distinguish clean EOF from unfinished frames. Specify immediate
  oversized-frame rejection and cover the CRLF boundary.

The updated verifier passed the Draft 2020-12 schema, 24 frame cases, 19 message
shapes and 30 session transcripts. Eight in-memory probes confirmed rejection
of incorrect fixed and default ports, an unrelated public key repeated in
startup and status, duplicate mappings accepted by validation or startup,
and a peer matching the server key accepted by validation, startup or live
addition. The protocol baseline still awaits review before W2.

Fourth W1 review follow-up

- [x] Require a reconciliation decision before further requests after a peer
  mutation timeout. Cover a status timeout while the mutation is still pending
  and require closing stdin and reaping before replacing the helper.
- [x] Check the remaining configuration rules for invalid IPv4 ranges,
  duplicate peer addresses and keys, and all-zero keys. Cover validation,
  startup and live peer addition where applicable.

Verification passed the Draft 2020-12 schema, 24 frame cases, 19 message shapes
and 44 session transcripts. Eight in-memory probes rejected retry without a
reconciliation decision, replacement before reaping, another status after
failed reconciliation, and false success replies for the four configuration
examples and an all-zero live peer key. The protocol baseline remains open
for review.

Fifth W1 review follow-up

- [x] Reconcile a late mutation reply against the helper's reported revision.
  Record whether the request applied and whether status satisfies the desired
  peer state separately. Cover stale revision and already absent peer cases.
- [x] Require `peer_not_found` for an absent peer and reject it for an active
  peer. Restrict `peer_limit` and `peer_conflict` to additions.

Verification passed the Draft 2020-12 schema, 24 frame cases, 19 message shapes
and 47 session transcripts. Six in-memory probes rejected impossible removal
errors, success for removal of an absent peer, an incorrect status revision
and an incorrect desired-state decision. W1 awaits review before W2.

Sixth W1 review follow-up

- [x] Cover terminal session errors and stdout failure while reconciliation
  status is queued. Require the old helper to be reaped before replacement.
- [x] Limit `peer_update_failed` to peer addition and removal in the schema.
  Cover both accepted operations and rejection on `status`.

Verification passed the Draft 2020-12 schema, 24 frame cases, 22 message shapes
and 49 session transcripts. Four negative probes rejected replacement before
reaping after either terminal failure, reconciliation replacement without a
pending reconciliation, and `peer_update_failed` on an idle `status` request.
The protocol baseline remains open for review.

Seventh W1 review follow-up

- [x] Cover abrupt helper exit during reconciliation and forced termination
  after closing stdin and waiting the shutdown grace period. Require confirmed
  exit and reaping before replacement in both paths.
- [x] Cover non-peer control deadlines with a startup timeout followed by
  clean exit on EOF and reaping. Reject further requests after that timeout.

Verification passed the Draft 2020-12 schema, 24 frame cases, 22 message shapes
and 52 session transcripts. Seven negative probes rejected replacement before
reaping in all three new paths, forced termination without stdin closure or
the grace period, reaping without confirmed exit, and further requests after a
startup timeout. W1 awaits review before W2.

Eighth W1 review follow-up

- [x] Track controller stdin closure separately from helper request admission.
  Allow one closure after a terminal diagnostic or stdout failure. Exercise
  both paths through exit and reaping, including forced termination after the
  shutdown grace period.

Verification passed the Draft 2020-12 schema, 24 frame cases, 22 message shapes
and 54 session transcripts. Twelve negative probes across the two failure
paths rejected duplicate stdin closure, a clean exit status after failure,
new requests after admission closed, skipping stdin closure or the grace
period before forced termination, and replacement before reaping. W1 awaits
review before W2.

Ninth W1 review follow-up

- [x] Require explicit controller stdin closure and reaping before replacement.
  Cover closure after observed exit for terminal diagnostics, stdout failure
  and abrupt helper exit.

Verification passed the Draft 2020-12 schema, 24 frame cases, 22 message shapes
and 54 session transcripts. Nine negative probes rejected missing closure,
missing reaping and duplicate closure across the three failure paths. Three
positive probes accepted closure after reaping and before replacement. W1
awaits review before W2.

### W2 — Extract a reusable application lifecycle

Starting point: [cmd/wgslirp/main.go](../cmd/wgslirp/main.go).

- [x] Move networking assembly and cleanup into `internal/application`.
- [x] Keep environment parsing and terminal signal handling in the existing CLI.
- [x] Add a thin `cmd/wgslirp-helper` scaffold that accepts typed configuration
  at its runtime boundary. W6 connects the wire protocol.
- [x] Make both entry points use the same runtime construction and shutdown logic.
- [x] Use explicit, validated runtime configuration independent of the helper
  environment.
- [x] Keep one runtime per helper process. Replace the process for restart-required
  changes rather than adding a multi-instance runtime framework.
- [x] Respect existing single-use lifecycle and process-wide pooling/capture
  contracts documented in [runtime lifecycle](CONTRACTS.md#lifecycle-and-concurrency)
  and [configuration and compatibility](CONTRACTS.md#configuration-and-compatibility).
- [x] Preserve the standalone CLI's existing configuration contract and defaults.
- [x] Verify existing standalone behavior, startup-failure cleanup, cancellation
  and repeated shutdown.

**Complete when:** both entry points share runtime ownership without duplicating
the networking lifecycle or changing the standalone CLI's supported behavior.

The runtime validates typed settings before claiming process-wide resources.
It cancels observers and starts socket shutdown before joining WireGuard.
It waits for observers and socket cleanup before releasing capture. Startup
checks cancellation between acquisition steps. The
standalone command retains its existing health and metrics observers.
The helper scaffold exits with an error until W6 provides the protocol controller
and restricted configuration.

Windows amd64 verification used Go 1.23.12. Build, vet, the full unit suite
and the encrypted standalone binary test passed. The binary test exercised
forwarding with fragment reassembly enabled and disabled. Lifecycle subprocess
tests checked typed configuration despite conflicting environment settings,
failed bind cleanup, cancellation during startup and after readiness, and
concurrent close. The lifecycle suite passed ten consecutive runs. Linux
amd64 and ARM64 cross-builds and focused Linux amd64 vet passed. Native Linux
runtime and race validation were unavailable in the initial Windows-only run.

W2 review follow-up

- [x] Close socket admission and cancel pending host dials before waiting
  for WireGuard receive workers. Join socket cleanup before returning.
- [x] Reject unsupported typed socket protocols before opening capture or
  claiming the runtime slot. The regression starts successfully after
  the invalid attempt in the same process.
- [x] Exercise actual Linux SIGTERM on the built standalone binary and
  include the regression in the Linux integration workflow.

The Windows amd64 full unit suite, vet and encrypted standalone binary test
passed, including forwarding with fragment reassembly enabled and disabled.
Linux amd64 integration vet and the Linux ARM64 cross-build passed.

The application and standalone CLI test suites passed as an unprivileged
user in a network-isolated Linux amd64 VM (Alpine kernel 6.12.51). The
standalone binary exited zero on SIGTERM and released its UDP listener.
The encrypted shutdown regression observed a pending host dial before
closing the runtime and verified that shutdown cleared the dial reservation.
The same regression failed at the expected shutdown deadline with the old
runtime supplied through a temporary Go compiler overlay.

The Linux run used the standalone binary directly. The Docker release-image
acceptance job and race-enabled tests were not run for this follow-up.
W2 was approved at `8b10bbd`.

Second W2 review follow-up

- [x] Run the Linux encrypted pending-dial regression in a fresh subprocess
  per test invocation so repeats exercise the process-wide runtime guard.
- [x] Validate exact protocol names at the typed application boundary.
  Preserve the empty default and direct socket library behavior. Verify
  malformed TCP names fail before capture or the runtime slot is claimed.

The first repeated Linux run exposed an intermittent false-ready UDP bind
failure and a SIGTERM race at startup. StartDevice now configures WireGuard
before its single explicit Up call. The standalone command treats startup
cancellation as clean when cleanup succeeds.

The final isolated Linux amd64 VM run passed ten repetitions of the lifecycle
suite, encrypted pending-dial regression and protocol validation. The
standalone SIGTERM test passed five consecutive runs. Linux integration vet,
Linux ARM64 cross-build, Windows unit tests, vet and encrypted forwarding
checks passed. W2 was approved at `8b10bbd`.
The approval checkpoint `a6a57d0` was pushed to GitHub before W3 began.

### W3 — Provide portable status and protocol-safe logging

Starting points: [pkg/logging/logging.go](../pkg/logging/logging.go),
[cmd/wgslirp/metrics_reporter.go](../cmd/wgslirp/metrics_reporter.go) and
[pkg/wireguard/state.go](../pkg/wireguard/state.go).

- [x] Redirect standard Go, wgslirp and WireGuard dependency logging to stderr
  before starting the helper runtime. Preserve standalone logging destinations.
- [x] Reserve stdout exclusively for protocol messages, including error and debug paths.
- [x] Separate portable status from Linux-specific resource collectors.
- [x] Define structured status for runtime state, uptime, effective listener port,
  peer public keys/endpoints/handshakes/transfers, active flows, refusals, buffer
  pressure and a sanitized error for uncertain applied state. The version 1
  response envelope carries the configuration revision.
- [x] Return sanitized peer state without raw WireGuard UAPI output or private keys.
- [x] Use the version 1 counter direction and reset rules. Preserve known zero
  values and return null for unavailable telemetry.
- [x] Collect a fresh snapshot on demand without a background metrics publisher.
- [x] Bound each protocol write to one frame and five seconds. The serial
  controller owns output and a failed write retires the stream.
- [x] Verify protocol-only stdout, secret omission, slow and disconnected
  readers, and pipe closure after interrupted output.

The stdout subprocess tests start the shared runtime in debug mode and exercise
a UDP bind failure. W6 will wire the status snapshot and bounded writer into the
command loop, attach the revision, and verify runtime shutdown and process exit
when the real controller's stdout stalls or disconnects.

The final isolated Linux amd64 run passed three repetitions each of the
runtime lifecycle suite, encrypted pending-dial shutdown, direct standalone
SIGTERM, helper logging, status and output checks. Windows unit tests and vet,
the encrypted TCP/UDP forwarding regression, 100 repetitions of the output
suite, Linux integration vet and Linux ARM64 cross-builds of both binaries
passed. The compatibility verifier passed 24 frame cases, 22 message shapes
and 54 session transcripts. The Docker acceptance and race-enabled suites
were outside this verification run.

W3 review follow-up

- [x] Make inherited Unix stdout interruptible. The helper takes ownership of
  a pollable, nonblocking stdout descriptor. Cancelling or timing out a write
  closes the stream and waits for that write to stop before returning.
- [x] Ignore SIGPIPE in the Unix helper before starting diagnostics. Broken
  stdout returns a write error, and a closed stderr reader leaves the helper
  running so it can finish its work and clean up.
- [x] Read portable TCP metrics from the registry count, shared buffer budget
  and admission counters without taking per-flow locks. Verify both the
  collector and `Runtime.Status` while a real host write is stalled.

In the isolated Linux amd64 VM, the inherited-pipe tests passed three runs
each for partial-write cancellation, the five-second timeout, closed stdout
and closed stderr. The parent drained the cancelled and timed-out pipes while
the child remained alive and observed EOF with no terminating LF. The
runtime status regression passed three runs and the socket metrics regression
passed ten. The encrypted pending-dial test also verified a live peer's
endpoint, handshake timestamp and nonzero transfer counters. Direct
standalone SIGTERM passed three runs.

Windows unit tests, vet, encrypted TCP/UDP forwarding and 100 repetitions
of the output unit tests passed. Linux integration vet, Linux and macOS
ARM64 cross-builds of both binaries, and the compatibility verifier passed.
Native inherited-pipe pressure was verified on Linux. W6 owns the full
controller and runtime teardown test after output failure. W3 awaits review.

Second W3 review follow-up

- [x] Preserve success when the entire response, including LF, was written
  before cancellation can interrupt it. Join the writer and check its result
  before reporting a cancellation as an interrupted frame.
- [x] Route all three helper loggers through one best-effort stderr worker.
  Limit the queue to 32 records of at most 4 KiB each and allow up to 100 ms
  to drain on exit. Drop diagnostics under pressure so a full stderr pipe
  cannot block runtime startup, packet workers or cleanup.

The frame-boundary regression passed 100 Windows output-suite repetitions
and three Linux runs. With a full, unread Linux stderr pipe, the subprocess
started the runtime, wrote a response, closed the runtime and confirmed
cleanup on stdout in all three runs. The Linux subprocess suite also passed
three runs each for broken stdout and stderr, partial-frame cancellation,
the five-second stdout timeout, stalled host-write status and standalone
SIGTERM. The lower-level socket metrics regression passed ten runs.

Windows tests and vet, encrypted TCP/UDP forwarding, Linux integration vet,
Linux and macOS ARM64 cross-builds of both binaries, and all 100 protocol
compatibility cases passed. W3 awaits review before W4.

Third W3 review follow-up

- [x] Interrupt an inherited Unix stdout write with a temporary write
  deadline. Preserve stdout when cancellation occurs before any bytes or
  after the terminating LF, so a terminal diagnostic can still be sent.
  Retire stdout on a partial frame, an I/O failure or a five-second stall.
- [x] Verify a subsequent diagnostic after pre-cancellation, zero-byte
  cancellation during a write and cancellation after LF. The Linux child
  also cancels a write with stdout prefilled and sends its diagnostic after
  the parent drains the pipe.

All six Linux inherited-pipe cases and all three frame-boundary cases
passed three runs each in the isolated amd64 VM. Linux integration vet,
runtime lifecycle, stalled-host status and standalone SIGTERM checks
passed. Windows tests and vet passed, including 100 output-suite repeats,
and the helper cross-built for macOS ARM64. Windows output-unit coverage
uses test writers. In-flight cancellation on inherited Windows pipes
remains part of native acceptance. W3 awaits review before W4.

Fourth W3 review follow-up

- [x] Wait for the production stdout write to encounter `EAGAIN` on a full
  Linux subprocess pipe before sending cancellation. Keep the pipe full
  until the write returns, then drain it and verify stdout contains exactly
  the original fill bytes followed by the complete `queue_full` diagnostic.

The synchronized regression and the other five Linux inherited-pipe cases
passed three runs each in the isolated amd64 VM. Linux integration vet,
frame-boundary tests, runtime lifecycle, stalled-host status and standalone
SIGTERM also passed. W3 was approved at `539d884`.

**Complete when:** portable status is usable by the C# wrapper and control-channel
backpressure cannot cause unbounded buffering or block packet callbacks.

### W4 — Add generic restricted destination mapping

Starting points: [pkg/socket/socket.go](../pkg/socket/socket.go),
[pkg/socket/tcp_connect.go](../pkg/socket/tcp_connect.go),
[pkg/socket/udp_bridge.go](../pkg/socket/udp_bridge.go) and
[pkg/wireguard/wg_tun_wg.go](../pkg/wireguard/wg_tun_wg.go).

- [x] Add an explicit restricted-forwarding mode independent of Jellyfin terminology.
- [x] Support mappings such as:

  ```text
  Guest destination: TCP 10.77.0.1:8096
  Host destination:  TCP 127.0.0.1:8096
  Default action:    deny
  ```

- [x] Preserve guest-visible addresses in synthesized replies while dialing the
  mapped host destination.
- [x] Enforce policy for initial connections, existing-flow handling and
  reassembled packets.
- [x] Disable peer-to-peer overlay routing in the restricted profile so it cannot
  provide a policy bypass.
- [x] Require unique, non-overlapping client IPv4 `/32` addresses in this profile
  and reserve the virtual service address separately.
- [x] Keep WireGuard source-address ownership separate from destination authorization.
- [x] Permit only explicitly mapped TCP services in the initial Jellyfin profile;
  reject other guest traffic unless explicitly supported.
- [x] Leave the standalone router's existing unrestricted behavior available.
- [x] Verify allowed mappings, rejected addresses/ports/protocols, fragment handling,
  reply endpoint preservation and unrestricted-mode regression coverage.

The typed application configuration opts in through an immutable destination
policy. The TCP bridge checks the guest tuple before looking up or changing
flow state, including after reassembly. Only the host dial uses the mapped
tuple. Restricted configuration rejects overlay routing, capture, ICMP echo
and non-passive or conflicting peer assignments. The socket drops non-TCP
traffic and suppresses fragment-expiry replies in restricted mode. W6 will
translate validated protocol requests into this configuration.

Encrypted tests exercised a loopback host listener at a different port from
the virtual service. They verified fragmented SYN and data, guest-visible
reply endpoints, and rejection of a direct host address, an unmapped port,
UDP, and a forged data segment addressed to an unmapped port.

Restricted and unrestricted encrypted forwarding passed five runs each in
the isolated Linux amd64 VM and ten each on Windows. Linux runtime tests
also passed three runs each for mapped and unrestricted pending-dial
cancellation, standalone SIGTERM and helper pipes. Windows unit tests and
vet, Linux integration vet, Linux and macOS ARM64 cross-builds of both
binaries, and all 100 protocol compatibility cases passed. W4 awaits
review before W5.

W4 review follow-up

- [x] Reject unmapped destination IPs before reserving IPv4 reassembly
  storage. Test first and later fragments against a one-datagram budget,
  verify zero current and peak usage for denied traffic, and verify that
  a mapped fragment can still reserve and release the budget.
- [x] Test the restricted application runtime with two encrypted peers.
  Verify that a direct packet to the second peer and a mapped SYN with
  that peer's forged source address cannot reach the peer or open a
  host flow. Verify legitimate mapped payloads from both peers.

The fragment-budget regression passed ten Linux runs and the encrypted
two-peer regression passed three in the isolated amd64 VM. Linux
integration vet, mapped and unrestricted pending-dial shutdown,
standalone SIGTERM and helper pipe checks passed. Windows unit tests
and vet passed, including ten runs each of restricted and unrestricted
encrypted forwarding. Both binaries cross-built for Linux and macOS
ARM64, and all 100 protocol compatibility cases passed. W4 awaits review.

Second W4 review follow-up

- [x] Check the destination port as soon as the first TCP fragment arrives.
  An unmapped port cannot create a reservation, and it releases any
  provisional reservation for that datagram. Later fragments can reserve
  provisional space because they carry no TCP ports.
- [x] Wait for the destination-policy rejection and WireGuard source-address
  rejection in the encrypted two-peer test. Verify that both peers can
  still reach the mapped service and only the expected host flows opened.

Both fragment arrival orders passed ten Linux runs and 100 Windows
repetitions. The encrypted isolation test passed three Linux runs per VM
run. Linux integration vet, lifecycle, SIGTERM and helper pipe checks
passed, as did Windows tests and vet and Linux and macOS ARM64 cross-builds.
Restricted and unrestricted encrypted forwarding passed five runs each on
Linux and ten each on Windows. W4 awaits review before W5.

Third W4 review follow-up

- [x] Retain denied fragment keys for the 60-second reassembly lifetime so
  subsequent fragments cannot recreate the reservation. An admitted first
  fragment can reuse the IP ID and starts with fresh reassembly state.
- [x] Cap denial tracking at 128 keys. If the table fills, temporarily
  refuse new assemblies that arrive without their first fragment. Mapped
  first fragments and existing assemblies can still proceed.
- [x] Verify both arrival orders, zero reservation after subsequent denied
  fragments, IP ID reuse, table saturation and expiry.

All restricted fragment regressions passed ten Linux runs and 100 Windows
repetitions. Linux integration vet, encrypted two-peer isolation, runtime
lifecycle, standalone SIGTERM and helper pipes passed. Windows unit tests,
integration vet, ten runs each of restricted and unrestricted encrypted
forwarding, and both Linux ARM64 cross-builds passed. W4 awaits review.

Fourth W4 review follow-up

- [x] Keep denial tracking through completion of a mapped datagram that
  reuses the IP ID. Verify that a delayed fragment still cannot reopen the
  denied assembly or reserve buffer space after mapped completion.
- [x] Track up to 128 denied keys per source, across the 128 sources the
  restricted runtime admits. Only the saturated source temporarily loses
  new out-of-order assemblies. Verify that another source can reserve and
  continue a mapped assembly with the same IP ID while saturation is active.

The fragment regressions passed ten Linux runs and 100 Windows repetitions.
Linux encrypted two-peer isolation, lifecycle, standalone SIGTERM, helper
pipes and integration vet passed. Windows unit tests, integration vet and
ten runs each of encrypted restricted and unrestricted forwarding passed.
Both binaries cross-built for Linux ARM64. W4 awaits review before W5.

Fifth W4 review follow-up

- [x] Reclaim expired denial keys and source entries before triggering
  overflow. Test a new denial at expiry before the maintenance sweep,
  verifying that its later fragments stay denied and an unrelated
  out-of-order fragment can still reserve space.

Both pre-sweep capacity cases passed ten Linux runs and 100 Windows
repetitions. Linux integration vet, encrypted peer isolation, runtime
lifecycle, standalone SIGTERM and helper pipes passed. Windows unit tests,
integration vet and ten runs each of restricted and unrestricted encrypted
forwarding passed. W4 was approved at `553f165`.

**Complete when:** a WireGuard client can reach a mapped service, and alternate
destinations or forwarding paths cannot escape the configured policy.

### W5 — Add live peer management and complete revocation

Starting points: [pkg/wireguard/device_common.go](../pkg/wireguard/device_common.go),
[pkg/wireguard/device_wg.go](../pkg/wireguard/device_wg.go) and the TCP/UDP flow
registries in `pkg/socket`.

- [x] Add peer-management APIs without unnecessarily breaking existing consumers
  and mocks of the device handle.
- [x] Validate public keys and address ownership before applying peer configuration.
- [x] Associate admitted work with the peer's validated, uniquely assigned source address.
- [x] On revocation, close admission, remove the WireGuard peer, cancel pending
  dials, close owned TCP/UDP flows and release associated buffers and incomplete
  fragment state.
- [x] Recheck admission when asynchronous dials complete so revoked work cannot
  publish a new host connection.
- [x] Return successful revocation only after the peer's cleanup completes;
  document that previously delivered bytes cannot be retracted.
- [x] Do not automatically recycle revoked client addresses in the initial profile.
- [x] Define failure and reconciliation behavior for partially applied WireGuard
  updates. Do not assume the underlying update operation is transactional.
- [x] Stop forwarding if an uncertain update means access policy cannot be
  established safely.
- [x] Verify add/revoke during streaming and pending dials, reconnection rejection,
  resource cleanup and continued service for unrelated peers.

The optional WireGuard peer API preserves the base device interface. The
restricted runtime tracks assignments for the life of the process and opens
socket admission only after confirming the applied peer set. Revocation
closes source admission, cancels pending dials, verifies the WireGuard
removal, joins peer work and discards fragment state and queued TUN replies.
Restricted forwarding admits only TCP. Bytes already delivered cannot be
retracted. If a failed removal leaves the prior policy intact, admission
reopens after cleanup. Existing connections may have been interrupted.
Uncertain applied state closes the runtime. W6 supplies protocol dispatch,
revision checks and process-exit handling.

In the Linux amd64 VM, encrypted live add and revocation during an active
stream, revocation during both pending-dial phases, fragment and reservation
cleanup, and injected UAPI failure reconciliation passed three runs each.
Linux integration vet, runtime lifecycle, direct SIGTERM and inherited
helper pipes passed. Windows unit tests and integration vet, ten runs each
of encrypted restricted and unrestricted forwarding, Linux and macOS ARM64
cross-builds of both binaries, and all 100 protocol fixtures passed.
Race-enabled tests and Docker acceptance were outside this run.

W5 review follow-up

- [x] Close peer-owned host sockets before WireGuard removal waits for the
  peer's workers. Connection publication and revocation share the source
  lock, and socket closure does not wait for a blocked flow lock.
- [x] Inject failed removals with prior, desired and partial applied state.
  Verify closed admission during the update, cleanup of fragment state,
  reopening only with the prior policy verified, and shutdown on uncertainty.
- [x] Restart the revoked encrypted client and observe the server reject
  its fresh WireGuard handshake before checking that no host flow opened.

The stalled-host, failed-removal and encrypted reconnect regressions passed
three runs each in the isolated Linux amd64 VM. Linux pending-dial,
lifecycle, standalone SIGTERM, inherited-pipe checks and integration vet
also passed. Windows unit tests and integration vet, ten runs each of
encrypted restricted and unrestricted forwarding, Linux and macOS ARM64
cross-builds, and all 100 protocol fixtures passed. W5 awaits review.

**Complete when:** revocation removes both tunnel access and associated host work
without restarting other peers or silently leaving uncertain access state.

### W6 — Implement the helper executable and process contract

Dependencies: W1–W5. An early subset can support the vertical slice before live
peer management is complete; do not advertise unsupported capabilities.

- [ ] Connect the runtime, protocol, status, policy and peer operations into the helper.
- [ ] Negotiate compatibility before accepting private configuration.
- [ ] Start once, process requests and exit after shutdown.
- [ ] Define behavior for stdin EOF, broken stdout, startup failure and shutdown timeout.
- [ ] Initiate shutdown on parent disappearance without requiring a Unix signal.
- [ ] Add a bounded final termination path for permanently stuck shutdown.
- [ ] Expose executable version information without configuration.
- [ ] Report capabilities so callers do not infer features from version strings.
- [ ] Verify the real executable through pipes, including abrupt parent termination,
  startup cancellation, unread output, malformed input and repeated stop requests.

**Complete when:** the helper is independently operable through its published
contract and has verified process-lifecycle behavior.

### W7 — Publish versioned binaries and acceptance evidence

- [ ] Add binary releases alongside the existing container workflows.
- [ ] Publish archives, checksums and metadata recording source revision, protocol
  compatibility and supported capabilities.
- [ ] Begin Windows/macOS cross-compilation checks during Linux development.
- [ ] Keep platform collectors and OS-specific support in dedicated files/packages.
- [ ] Distinguish buildable targets from natively validated, supported targets.
- [ ] Retain existing networking validation gates and add encrypted tests for
  destination mapping, live peer changes and helper lifecycle.
- [ ] Validate Linux x64 first and Linux ARM64 before completing the Linux release.
- [ ] Add native acceptance for every OS/architecture advertised in the final release.

| Stage | Build coverage | Native acceptance |
| --- | --- | --- |
| First integration | Linux x64 plus early Windows/macOS compile checks | Linux x64 |
| Linux release | Linux x64/ARM64 | Both Linux architectures |
| Cross-platform release | Agreed Linux, Windows and macOS matrix | Every advertised target |

**Complete when:** downstream projects can download pinned artifacts and operate
the helper without importing Go source or building locally.

## Repository 2: Jellyfin plugin

### J1 — Create the plugin skeleton and protocol client

Dependency: W1. This work can proceed while the Go runtime work is underway.

- [ ] Select one initial Jellyfin server version and pin compatible framework and
  package versions.
- [ ] Separate the protocol client and supervisor from dashboard/controller code.
- [ ] Implement the shared protocol fixtures in C#, including request correlation,
  bounded reads, cancellation and compatibility failures.
- [ ] Reject incompatible helpers before sending secrets or starting forwarding.

**Complete when:** the C# client passes shared fixtures independently of a running
Jellyfin instance and enforces the agreed compatibility boundary.

### J2 — Implement helper discovery and supervision

Dependency: W6 for real integration.

- [ ] Select the binary by operating system and process architecture.
- [ ] Launch directly, without a shell, using redirected stdin/stdout/stderr.
- [ ] Handle readiness, clean shutdown, process reaping, bounded restart backoff
  and duplicate-start prevention.
- [ ] Keep Jellyfin operational when the helper fails and expose a useful plugin error.
- [ ] Put executable permissions, forced termination and process ownership behind
  small platform adapters; avoid Unix-signal dependencies in shared lifecycle code.
- [ ] Manage owned processes by retained handles, never executable-name searches.
- [ ] Provide an internal helper-path override for development; use pinned bundled
  binaries in packaged installations.
- [ ] Verify start/stop/crash/restart, Jellyfin shutdown and failed-launch behavior.

**Complete when:** the wrapper reliably owns one helper without duplicate or
orphaned processes in the tested lifecycle scenarios.

### J3 — Implement persistent desired state and reconciliation

- [ ] Persist server settings, peer records and assigned addresses in the plugin.
  Keep active networking state in Go.
- [ ] Separate ordinary settings, secrets and transient status.
- [ ] Use private Linux directories/files and equivalent permission handling in
  later platform adapters.
- [ ] Send complete desired configuration to a fresh helper on startup.
- [ ] Persist peer-mutation intent and track completion explicitly. Report
  revocation success only after helper acknowledgement.
- [ ] Reconcile interrupted operations using durable desired state and reported
  runtime state; do not assume a transaction spans both processes.
- [ ] Verify interruption before and after mutation boundaries cannot silently
  resurrect revoked peers or mark unapplied settings active.

**Complete when:** restart and crash recovery preserve desired access policy and
accurately distinguish pending, applied and failed changes.

### J4 — Implement endpoint settings and client provisioning

- [ ] Configure public WireGuard endpoint, virtual Jellyfin endpoint and actual
  host destination as distinct values, including container deployments.
- [ ] Support peer public-key import first.
- [ ] Add generated client configurations with narrow service routes, MTU and
  optional keepalive. Keep WireGuard key operations in Go rather than adding a
  second cryptographic implementation in C#.
- [ ] Return generated client private keys through explicit provisioning and avoid
  retaining them by default. Define configuration re-download behavior accordingly.
- [ ] Verify ordinary WireGuard clients can import the configuration and reach
  Jellyfin without tunneling unrelated Internet traffic.

| Address | Meaning |
| --- | --- |
| Public WireGuard endpoint | Where the client sends encrypted UDP |
| Virtual Jellyfin endpoint | The address opened through WireGuard |
| Host destination | Where the helper actually connects |

**Complete when:** an administrator can provision a client that reaches the
intended Jellyfin service using the documented address and routing model.

### J5 — Add the dashboard and administrator API

- [ ] Add enable/disable, endpoint settings, peers, provisioning, revocation,
  connection status and diagnostics.
- [ ] Enforce administrator authorization in server endpoints, not only the UI.
- [ ] Omit secrets from normal configuration responses.
- [ ] Distinguish saved settings from applied settings.
- [ ] Explain interruptions for restart-required changes and apply them through
  an explicit operation.
- [ ] Present actionable errors for occupied ports, unsupported architectures,
  incompatible helpers, permissions and unreachable targets.
- [ ] Verify non-administrators cannot manage peers or retrieve provisioning
  material and that pending/failed operations are accurately displayed.

**Complete when:** administrators can operate the plugin without inspecting raw
protocol messages, and the UI accurately represents applied state.

### J6 — Package the plugin with pinned helpers

Dependencies: W7 and the selected Jellyfin compatibility baseline.

- [ ] Maintain a dependency manifest recording wgslirp release, protocol range,
  artifact names and checksums.
- [ ] Download and verify exact artifacts in the plugin release pipeline, then
  bundle them so users need neither Go nor a separate wgslirp installation.
- [ ] Keep persistent state outside versioned executable directories.
- [ ] Stop the old helper before launching a replacement during upgrades.
- [ ] Preserve server identity and peer records across upgrades and compatible rollbacks.
- [ ] Bundle supported platform binaries in the plugin package unless measured
  package size justifies another distribution approach.
- [ ] Verify clean installation, upgrade and compatible rollback.

**Complete when:** packaged installation and upgrade work with pinned helpers
without losing keys or peer records.

### J7 — Validate actual Jellyfin behavior on Linux

- [ ] Test native Linux and a selected Jellyfin container deployment.
- [ ] Validate direct play, transcoding, seeking, long streams, concurrent peers,
  network interruption, helper recovery and revocation during playback.
- [ ] Determine how Jellyfin classifies helper-originated connections and verify
  remote-access and bitrate restrictions.
- [ ] Test WebSockets, redirects, base URLs and advertised addresses.
- [ ] Measure resource contention while Jellyfin transcodes.
- [ ] Document UDP port publication and executable-storage requirements for containers.
- [ ] Record supported behavior and measured limits on Linux x64 and ARM64.

Socket bridging hides the original client IP. Resolve the connection-classification
behavior during the early vertical slice; per-peer IP attribution is a separate
requirement and must not be promised implicitly. A plugin cannot publish an
unpublished container UDP port or add NAT traversal by itself.

**Complete when:** both Linux architectures pass actual plugin/playback acceptance,
with connection-classification and deployment limitations documented.

### J8 — Complete the cross-platform deliverable

- [ ] Confirm the final OS/architecture support matrix. Initial candidates are
  Linux x64/ARM64, Windows x64 and macOS ARM64/x64.
- [ ] Add platform executable selection, permissions, termination and packaging
  using the same protocol and supervision model.
- [ ] Address signing or execution-policy requirements in distribution where applicable.
- [ ] Validate native startup, parent disappearance, clean/forced shutdown,
  upgrade replacement, forwarding and actual playback on every advertised target.
- [ ] Publish platform-specific acceptance evidence and deployment instructions.

**Complete when:** every advertised platform passes native acceptance. Producing
a cross-compiled binary alone does not complete platform support.

## Coordinated delivery checkpoints

| Checkpoint | Required work | Result |
| --- | --- | --- |
| Protocol baseline | W1 | Both repositories can develop against one contract |
| Vertical slice | W2–W4, minimum W6, J1–J2 | C# launches Go; a client streams through a mapped endpoint |
| Managed access | W5–W6, J3–J5 | Durable provisioning and effective live revocation |
| Linux release | W7, J6–J7 | Installable, validated Linux x64/ARM64 plugin |
| Final platform release | Expanded W7 and J8 | Validated binary implementation across the agreed OS matrix |

- [x] Protocol baseline accepted at `459f6f1`, with shared fixtures available
  to both repositories.
- [ ] Vertical slice accepted, including an early decision on Jellyfin connection classification.
- [ ] Managed access accepted, including crash reconciliation and live revocation.
- [ ] Linux release accepted on x64 and ARM64.
- [ ] Cross-platform release accepted on every advertised target.

Make the vertical slice the first integration milestone, before dashboard polish.
It tests real Jellyfin playback and the treatment of bridged connections early.

The stages are intended as bounded AI-assisted implementation and review work
packages, not estimates based on human development schedules. The main
uncertainties are connection classification, deployment packaging and measured
playback behavior. Record evidence alongside completed items rather than treating
generated code or successful compilation as proof of acceptance.
