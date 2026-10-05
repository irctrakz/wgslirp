# Independent-peer mixed workload

## Predeclared acceptance — 2026-10-04

The deployment preference is mixed short requests, bulk transfers and UDP.
This first gate introduces an independent guest TCP implementation through the
`tun/netstack` adapter in the already pinned WireGuard module. Its pinned gVisor
dependency is test-only; the executable continues using this repository's TCP
bridge and ordinary userspace sockets. Neither peer requires kernel TUN,
root, sysctl writes or capabilities.

`TestEncryptedMixed` is opt-in (`integration,mixed,linux`). Two real WireGuard
devices encrypt traffic between gVisor and the production bridge. Host TCP/UDP
services bind the disposable container's own non-loopback IPv4 address. No
external service or private SSH server is involved.

All clients start together:

- Four short-request workers: 32 fresh connections each, 1 KiB exact echo per
  request, with 100 ms pacing between requests.
- Two bulk connections: 4 MiB exact echo each, concurrent upload and download.
- One UDP client: 512 exact 1 KiB round trips, paced by 20 ms, with a 2-second
  per-round deadline. There are no application retries hiding loss.

Acceptance requires all 130 TCP handshakes within 5 seconds each, all exact
payloads, guest write-half-close followed by host EOF, and completion within
45 seconds. Log handshake p50/p95/max and bridge buffer peak. After stop, require
zero TCP/UDP flows, pending dial reservations, retained buffer bytes and TCP
delivery refusals. Join fixture workers and require process goroutines to return
within four of their initial count within five seconds after device cleanup.

Ordinary and race runs are sequential. Existing container limits stay unchanged:
1 CPU, 2 GiB RAM, no additional swap, 128 PIDs, read-only root, dropped
capabilities, 768 MiB work tmpfs and 64 MiB temporary tmpfs. The Go test has a
120-second timeout; the container has a 600-second deadline and an independent
outer watchdog. Resource-limit events or OOM fail acceptance. Always remove and
verify absence of the exact owned container and toolchain image. Published
development images retain the existing explicit retention contract.

This measures baseline encrypted interoperability and bounded mixed progress.
It is not a sustained saturation, deployment latency or adverse-WAN claim.
The existing deterministic packet fixtures remain useful for precise loss,
sequence-wrap and recovery assertions.

## Reviewable follow-ups

1. Apply calibrated bidirectional delay, jitter, loss and reordering to this
   independent peer; retain exact payload, progress and cleanup assertions.
2. Add slow readers, cancelled dials, refused destinations and shutdown during
   active mixed traffic. Assert the intended refusal/recovery metrics.
3. Increase simultaneous connections and run duration in explicit finite steps;
   measure admission pressure, TIME-WAIT occupancy, UDP latency, application RSS
   and natural-GC behavior. Declare thresholds before each run, preserve failures,
   and stop on any containment/cleanup failure.

## Validation status

### Congestion-control state cleanup — 2026-10-04

At `474cf7f`, [run 37252560572](https://github.com/irctrakz/wgslirp/actions/runs/37252560572)
passed this unchanged profile in both modes: 130 host accepts, zero empty accepts,
all exact payload/half-close checks and final reservation/worker cleanup. Race
mode exercised 36 async handoffs. Both modes recorded zero memory/PID-limit
events or OOM and verified container/tmpfs/image cleanup. The same run passed
standard checks, sustained-loss, WAN, full TIME-WAIT capacity, actual-image
validation and same-digest promotion. These observations establish acceptance;
they do not establish a performance improvement from removing redundant state.

### Single-dial handoff — 2026-10-04

At `6a2b78b`, [run 37246793917](https://github.com/irctrakz/wgslirp/actions/runs/37246793917)
passed the standard build/vet, unit/integration race and fuzz checks, plus both
mixed modes with the predeclared zero-empty-connection requirement.

| Measurement | Ordinary | Race |
| --- | ---: | ---: |
| Traffic elapsed | 10.518 s | 13.733 s |
| Host accepts / empty accepts | 130 / 0 | 130 / 0 |
| Async handoffs | 0 | 46 |
| Handshake p50 | 0.656 ms | 15.512 ms |
| Handshake p95 | 5.492 ms | 96.372 ms |
| Handshake maximum | 7.720 ms | 132.668 ms |
| Bridge buffer peak | 580,363 bytes | 470,015 bytes |
| Cgroup peak, including compilation/cache | 564,604,928 bytes | 927,158,272 bytes |

All exact payload, half-close, reservation and worker checks passed. Both modes
recorded zero memory/PID-limit events or OOM and verified container/tmpfs/image
cleanup. The race result exercises actual async handoffs without extra empty
host sockets. These are separate runner observations, not a controlled latency
comparison or a speedup claim. The same run passed both modes of sustained-loss,
WAN and capacity/TIME-WAIT checks, then actual-image validation and promotion.
All workload resource-event and cleanup checks passed. The image ran as UID 100,
forwarded encrypted TCP/UDP, and handled SIGTERM under traffic in 85.696406 ms.
CI promoted the same tested digest; see [RELEASE_IMAGE_TEST.md](RELEASE_IMAGE_TEST.md)
for its immutable identity. No owned runtime containers, networks, builder,
cache volume or local image remained after cleanup.

**Single-dial handoff acceptance, declared before its run:** retain all existing
traffic, latency, resource and cleanup criteria, and additionally require zero
empty host accepts (exactly 130 host payload connections). Keep the 260-accept
fixture safety ceiling for failure diagnostics. Async-dial metrics now count
handoffs of the original attempt, not replacement host dials. Earlier results
below describe the cancellation/redial implementation and remain historical.

Initial [run 37241906300](https://github.com/irctrakz/wgslirp/actions/runs/37241906300)
at `4a2b2b2` passed ordinary mode in 10.53 seconds (handshake p95 7.701 ms,
maximum 13.031 ms), but race mode timed out on short worker 0, request 24.
All later gates and image promotion were skipped. Cgroup peaks were 556,068,864
and 944,988,160 bytes respectively; both recorded zero memory/PID events or OOM
and verified container/tmpfs/toolchain-image cleanup.

Investigation found that the fixture's exact 130 host accepts were not a valid
oracle: a cancelled fast dial may already have been accepted by the host before
the asynchronous fallback creates its replacement. The responder now serves
until all clients finish, with a hard 260-accept ceiling, six concurrent handlers
and the same deadline. It logs total and empty accepts to test this explanation.
The 130 completed guest requests, exact bytes and all resource/time criteria are
unchanged.

### Corrected mixed gate accepted

Both modes passed at `740d0cd` in
[run 37242371491](https://github.com/irctrakz/wgslirp/actions/runs/37242371491).

| Measurement | Ordinary | Race |
| --- | ---: | ---: |
| Traffic elapsed | 10.588 s | 11.863 s |
| Completed TCP handshakes | 130 | 130 |
| Handshake p50 | 0.217 ms | 1.546 ms |
| Handshake p95 | 8.810 ms | 82.002 ms |
| Handshake maximum | 72.085 ms | 104.799 ms |
| Host accepts / empty accepts | 134 / 4 | 145 / 15 |
| Async fallback dials | 4 | 15 |
| Bridge buffer peak | 466,795 bytes | 416,155 bytes |
| Cgroup peak, including compilation/cache | 597,889,024 bytes | 887,861,248 bytes |

Both completed every exact payload and half-close/EOF check, zero final flow,
dial and buffer reservations, and worker cleanup. Memory/PID events and OOM
were zero; container, tmpfs and toolchain-image removal were verified. The extra
empty accepts matching fallback dials support the corrected fixture diagnosis.
This is one accepted pair, not a latency distribution across deployment runs.

Standard build/vet, unit/integration race, fuzz and configuration checks also
passed. The same run passed both modes of sustained-loss, calibrated WAN and
capacity/TIME-WAIT gates, then actual-image validation and same-digest promotion.
All workload containers reported zero memory/PID-limit events and verified
cleanup. The image ran as UID 100 with dropped capabilities, forwarded encrypted
TCP/UDP and exited on SIGTERM under traffic in 101.71672 ms.

Tested/promoted artifact:
`ghcr.io/irctrakz/wgslirp@sha256:b47b92492cbd09db701e41e77d5180ff33428fab31786b7ad29464066d72c4b8`.
Development tag:
`dev-740d0cdb8e8de58b7251ae72286957e901e2f9e5-37242371491-1`.
Image cleanup verified no owned runtime containers, networks, builder, cache
volume or local image remained. Published candidate/development artifacts remain
in GHCR intentionally. Neither main/master nor `latest` was updated.
