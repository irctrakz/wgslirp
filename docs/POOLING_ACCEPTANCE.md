# Packet pooling default: paired evidence

## Decision rule (before measurement)

Keep the current default off until ordinary encrypted traffic demonstrates a useful,
repeatable benefit without a material CPU, latency, memory or admission regression.
Fewer allocations alone are insufficient. A consistent regression above 10% in
paired CPU, bulk completion time or handshake p95 needs explanation before enabling
the default. Three pairs are exploratory evidence, not a statistical guarantee.
Any payload, race, ownership, reservation recovery or resource-gate failure blocks
default promotion. Actual release-image validation remains necessary for a default
change; this study makes no default change and publishes no image.

## Method

The existing Docker workflow has an explicit `pooling-study` dispatch input on
`codex/architecture-hardening`. It selects the reusable pooling workflow and skips
the image publication chain. The private SSH server remains unused.

One runner, source checkout, toolchain and bounded container run three paired
comparisons in off/on, on/off, off/on order. Each policy/workload uses a fresh test
process; the process-wide startup policy is never changed live. Ordinary and race
binaries are built once. Race runs check correctness separately from performance.

- Mixed independent encrypted guest: 128 short TCP requests, two 4 MiB TCP echo
  transfers and 512 UDP round trips. Record handshake p50/p95/max, individual bulk
  completion times and shared buffer peak. UDP pacing dominates whole-workload
  elapsed time, so that time is not a throughput benchmark.
- Encrypted WAN: calibrated 20/60 ms relay delay, consecutive drops, reordering
  and SACK reneging. Existing exact-payload/recovery/cleanup assertions remain.
- Both: process CPU, allocated bytes/objects, GC cycles/pause, sampled heap/RSS
  peaks and final memory. These include the independent guest and fixture, exclude
  compilation, and do not isolate the production router's RSS or CPU. Sampling
  every 20 ms can miss short peaks. No forced GC is introduced.
- Isolated packet allocation: 40, 1,380, 8,192 and 20,000 byte buffers with live
  reservation/release; allocation counts and time per operation. This measures
  storage ownership overhead, not checksum/encoding or encrypted throughput.
- Intentional saturation: retain ACK-sized and MTU-sized packets under the same
  64 KiB downstream budget. Check exact admitted count, one refusal, zero live
  reservations after release and successful readmission. This exposes pool-class
  rounding's capacity cost; these refusals are not workload failures.

Containment: one CPU, 2 GiB RAM, no additional swap, 128 PIDs, dropped capabilities,
read-only root, non-root user, bounded tmpfs and logs, 900-second container deadline.
The limit includes compilation/tmpfs and differs from the 256 MiB deployment limit.
Memory/PID events must remain zero. Cleanup removes the owned container/tmpfs and
toolchain image, verifies absence, and retains evidence artifacts for 14 days.
No owned network or persistent volume is created.

Pooling only affects selected packet synthesis buffers. It does not disable
WireGuard/gVisor pools or the bounded IPv4 reassembly object cache. UDP reply
datagram/fragment builders currently use exact-sized storage rather than this pool.
Idle packet pool retention is bounded at 960 KiB; retained pooled packets charge
the full class capacity plus the existing 128-byte entry allowance.

## Results

Pending the first bounded paired run. The default remains off.
