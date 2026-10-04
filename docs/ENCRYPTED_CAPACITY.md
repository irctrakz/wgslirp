# Bounded encrypted churn and default-capacity profile

## Acceptance declared before execution — 2026-10-03

This profile exercises real wireguard-go encryption, the production userspace TCP
bridge and ordinary loopback host sockets. No kernel TUN, raw sockets or added
capabilities are used. It does not introduce WAN impairment, change production
TIME-WAIT/idle timers, force GC or claim production throughput capacity.

Run one fresh ordinary process and one fresh race process, sequentially, on
GitHub-hosted Linux runners. The private server remains unused. Each container
has 1 CPU, 2 GiB RAM/no swap, 128 PIDs, read-only root, no capabilities, bounded
768 MiB work and 64 MiB temporary filesystems, and bounded logs. Module download
and compilation occur inside those bounds, with Go build scratch space explicitly
under `/work/build`. Cleanup removes the container, its tmpfs and the downloaded
toolchain image; evidence is retained for 14 days. Published GHCR application
images are retained separately. The container has a 600-second
deadline, the test 420 seconds and workload checks a six-minute ceiling.

Workload and pass criteria:

1. Eight warmups followed by **256 measured TCP connections** through one
   encrypted link. Each connection exchanges an exact 1 KiB payload in both
   directions, then guest RST releases its slot. Use distinct guest ports.
2. Measure guest SYN injection to decrypted SYN-ACK arrival using a monotonic
   clock. Report first/cold observation separately; report warm p50/p95/p99/max.
   Require warm p95 <=250 ms and max <=1 second; individual I/O deadlines are
   three seconds. These generous loopback liveness ceilings are declared in
   advance, not a comparative performance-improvement target. Sampled percentiles
   are not statistically established production latency guarantees.
3. Admit **64 simultaneous connections**, using the unchanged default flow cap.
   Exchange exact payloads on every connection. The 65th attempt must receive
   RST/ACK and increment the flow-limit counter without increasing flow count.
   An existing connection must still exchange exact payloads after refusal.
4. Close all 64 connections host-first, complete guest FIN/ACK and host EOF,
   and verify the slots remain occupied. Another attempted connection must be
   refused. Wait through the **actual four-minute TIME-WAIT interval**, including
   the normal two-minute idle-reaper boundary. Do not inject expiry or reset
   these flows to recover capacity. All slots must expire within five seconds
   of the last flow's four-minute deadline, then a new connection must succeed.
5. Final created/closed totals must both be 329, with exactly two capacity
   refusals, zero flows, zero pending-dial reservations, zero socket buffer
   reservations and zero downstream delivery refusals. Device cleanup must
   return goroutines to the pre-link count plus at most four within five seconds.
6. Sample after each connection and during the TIME-WAIT wait: heap <=192 MiB,
   RSS <=384 MiB, goroutines <=512. These are new capacity-profile ceilings,
   including race instrumentation; they do not revise the earlier A1 profile.
   Keep GOMAXPROCS=1 and GOMEMLIMIT=512MiB. Record sampled heap/RSS peaks separately
   from cgroup peak (which includes build/cache/tmpfs). Require zero cgroup
   memory/PID-limit events, no OOM kill, exit zero and verified container removal.

At most 330 KiB of application payload is exchanged in each direction: 329
successful connections plus one progress check on an already admitted flow.
The 256 timed warm handshakes substantially improve sample count over the earlier
eight-handshakes-per-sample baseline, but the encrypted workload is different:
do not compare those percentiles as an apples-to-apples regression measurement.

## CI and interpretation

The dedicated `capacity` build tag keeps the multi-minute profile out of ordinary
unit/integration invocations. `.github/workflows/capacity.yml` runs ordinary and
race variants with max parallelism one, retains 14-day evidence, and stops on a
failure. Development image validation/promotion depends on successful completion
of both variants. The unchanged stable/master publication path is outside this
development gate.

```sh
go test -v -tags=integration,capacity -run='^TestEncryptedChurnCapacity$' -timeout=420s -count=1 -parallel=1 ./pkg/wireguard
go test -v -race -tags=integration,capacity -run='^TestEncryptedChurnCapacity$' -timeout=420s -count=1 -parallel=1 ./pkg/wireguard
```

RST churn measures rapid establishment/release; it must not be described as
graceful-close throughput. The separate host-first batch demonstrates that
TIME-WAIT consumes the same finite slots, making roughly 16 host-first closes
per minute the default 64-slot/four-minute steady-state ceiling without headroom.
No capacity default is raised by this work. Calibrated WAN delay/loss/reordering,
encrypted RTO recovery, receiver reneging and larger sustained profiles remain
separate follow-ups. Existing UDP/image coverage does not turn this TCP churn
profile into a UDP capacity measurement.

## Results

Run [37149852601](https://github.com/irctrakz/wgslirp/actions/runs/37149852601)
failed during compilation, before the capacity workload: Go used the 64 MiB
`/tmp` for build scratch space and exhausted it. Cgroup peak was 324,509,696 bytes,
with zero memory/PID-limit events and no OOM kill. Container/tmpfs cleanup was
verified; the toolchain image was left for disposable-runner teardown. Race and
application-image publication did not run. The harness now places build scratch
space in the existing 768 MiB `/work` and explicitly removes its toolchain image.
Resource and workload acceptance ceilings are unchanged.

### Accepted ordinary and race profile — 2026-10-03

[Run 37165341911](https://github.com/irctrakz/wgslirp/actions/runs/37165341911),
source `fc0a4ba`, passed both fresh-process variants sequentially. The workload
and resource ceilings above were unchanged after correcting build scratch space.

| Measurement | Ordinary | Race |
| --- | ---: | ---: |
| Warm samples | 256 | 256 |
| Cold SYN-ACK (µs) | 4,060 | 52,293 |
| Warm p50 / p95 / p99 / max (µs) | 68 / 81 / 105 / 192 | 542 / 646 / 1,062 / 8,169 |
| TIME-WAIT through recovery (ms) | 240,073 | 240,141 |
| Sampled heap peak (bytes) | 63,478,160 | 94,905,440 |
| Sampled RSS peak (bytes) | 37,511,168 | 337,002,496 |
| Cgroup peak including compilation/tmpfs (bytes) | 344,289,280 | 585,740,288 |
| Socket buffer peak (bytes) | 201,168 | 201,168 |
| Workload elapsed (ms) | 240,457 | 241,152 |

Both verified 64 simultaneous flows, two signaled/accounted refusals, progress
on an admitted flow after refusal, actual four-minute TIME-WAIT retention and
successful admission after expiry. Both finished with 329 created/closed flows,
zero active flows, pending dials and reserved socket buffers, no downstream
delivery refusals, and worker cleanup within the declared allowance. The two
`flow limit reached` log entries per run are the expected negative controls.
There were no race reports, OOM kills or cgroup memory/PID-limit events.

Both artifacts verify removal of the container, tmpfs and downloaded toolchain
image. No dedicated network or persistent volume was created. This is one
ordinary/race pair, not a statistical production-capacity guarantee. Calibrated
WAN and recovery workloads remain outstanding as described above.
