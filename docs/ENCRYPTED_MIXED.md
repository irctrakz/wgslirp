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
unchanged. Pending corrected ordinary/race execution; no combined acceptance yet.
