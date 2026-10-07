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

**Decision: retain default off; keep `POOLING=1` as an explicit option.** Pooling
reduces some allocations and sampled memory, but the independent encrypted mixed
profile shows no repeatable bulk speedup and uses more CPU in all three pairs.
The larger-buffer microbenchmark benefit does not carry through to encrypted
traffic sufficiently to justify changing the general deployment default.
This is a policy decision from bounded evidence, not proof that pooling is slower
for every workload or that the opt-in setting is unsafe.

The first attempt passed in [run 37689880492](https://github.com/irctrakz/wgslirp/actions/runs/37689880492)
at source `43863889d2fb781a00955bc6f3a1cedeabcfa11b`, using Go 1.23.12 linux/amd64
and toolchain digest `sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db`.
The [ordinary samples](POOLING_SAMPLES.csv) preserve the individual measurements
beyond artifact retention. The CI artifact also contains all ordinary/race logs,
baseline checks, saturation controls, inspected limits and cleanup records.

### Encrypted traffic

The off/on columns are medians of the three samples. Change is the median of
the three *paired* percentage changes, so it can differ from the ratio of the
displayed medians. Negative changes mean a lower value, not necessarily a benefit
for every metric. MiB means 1,048,576 bytes.

| Mixed profile metric | Off | On | Paired change |
| --- | ---: | ---: | ---: |
| Process CPU | 482.7 ms | 505.1 ms | +4.64% |
| Allocated bytes | 214.0 MiB | 205.2 MiB | -4.09% |
| Allocated objects | 307,743 | 300,497 | -2.35% |
| GC cycles | 8 | 7 | -12.50% |
| GC pause total | 0.120 ms | 0.092 ms | -23.51% |
| Sampled peak heap | 150.6 MiB | 141.4 MiB | -6.11% |
| Sampled peak RSS | 137.5 MiB | 133.4 MiB | -4.45% |
| Handshake p95 | 7.495 ms | 6.746 ms | -6.15% |
| Mean of the two bulk completion times per run | 260.3 ms | 260.6 ms | +0.72% |
| Shared live buffer peak | 525,311 B | 534,159 B | +0.72% |

With two observations per run, the mean and median bulk completion time coincide.
Mixed CPU changed +4.64%, +1.41%, +7.07%; bulk completion changed +1.53%, +0.72%,
-1.00%. These samples establish an allocation/memory tradeoff, not a throughput
improvement. Handshake p50 was noisy (paired changes +37%, +104%, -46%); its
off/on sample medians were both 455 microseconds. Do not infer a latency guarantee.

Final mixed heap also depended on GC phase: off samples were 79.7, 81.9, 151.6 MiB;
on samples were 141.0, 141.4, 139.3 MiB. With fewer collections, lower cumulative
allocation and peak heap need not mean lower heap at the instant of shutdown.
These final measurements are not a leak test; the fixtures separately verify
closed workers, zero active flows and returned reservations.

| WAN profile metric | Off | On | Paired change |
| --- | ---: | ---: | ---: |
| Process CPU | 430.8 ms | 397.6 ms | -7.50% |
| Allocated bytes | 100.744 MiB | 100.713 MiB | -0.03% |
| Allocated objects | 41,253 | 41,207 | -0.13% |
| GC cycles | 5 | 5 | 0% |
| Sampled peak heap | 99.32 MiB | 99.31 MiB | -0.01% |
| Sampled peak RSS | 49.65 MiB | 47.70 MiB | -3.93% |
| Total duration | 12.249 s | 12.245 s | 0.00% |

WAN CPU changed -7.50%, +5.21%, -9.48%, so the benefit was inconsistent. This
small recovery profile has little pooled packet volume and is dominated by delay
and fixture setup. Both modes delivered exact payloads, recovered the deliberate
drops/reordering/reneging, and retained calibrated UDP RTTs near 41/121 ms.
All mixed/WAN admission refusal counters were zero in all ordinary samples.
Retransmit waits were recorded separately; they were also zero in these samples.

### Isolated allocation and retained capacity

| Packet bytes | Off median ns/op | On median ns/op | Off/on B allocated per op | Off/on allocations per op |
| --- | ---: | ---: | ---: | ---: |
| 40 | 187.8 | 212.5 | 152 / 104 | 5 / 4 |
| 1,380 | 290.2 | 226.8 | 1,512 / 104 | 5 / 4 |
| 8,192 | 935.1 | 320.2 | 8,296 / 104 | 5 / 4 |
| 20,000 | 1,489 | 1,540 | 20,584 / 20,584 | 5 / 5 |

Pooling's bounded-channel reuse is a plausible source of the extra small-buffer
cost; this is an inference, not a CPU-profile attribution. ACK-sized storage was
about 13% slower despite one fewer allocation. MTU-sized and 8 KiB storage was
about 22% and 66% faster in isolation. Buffers above 16 KiB remain uncached;
the 20 KiB control showed no allocation savings.

| Retained packet bytes | Accepted off / on in 64 KiB | Storage capacity charged off / on |
| --- | ---: | ---: |
| 40 | 390 / 30 | 40 / 2,048 B |
| 1,380 | 43 / 30 | 1,380 / 2,048 B |

Both modes refused exactly one intentionally excess packet, returned every
reservation and successfully admitted another after release, including under
race instrumentation. This is a deliberately small retention budget, not the
default 64 MiB budget or a prediction of deployment flow capacity. Real queues
have independent entry limits; no encrypted workload refusal was observed here.

### Acceptance and cleanup

- Build and vet passed; unit/race and integration/race suites passed.
- Twelve ordinary encrypted processes and four race encrypted processes passed.
- Six ordinary allocation/capacity processes and two race capacity controls passed.
- Inspected limits matched the declared bounds; the container exited 0 with
  `OOMKilled=false`. Cgroup memory peak was 1,064,267,776 bytes, including compilation,
  cache and tmpfs, and every memory/PID event was zero. Container runtime was 361 s.
- Cleanup verified removal of the owned container/tmpfs and toolchain image;
  no owned network or persistent volume was created. The private server was unused.
- No pooling default, routing behavior or resource limit changed. No release
  image was published by this evidence workflow, and main was untouched.

## Optional future reconsideration

Before revisiting the default, profile a demonstrated deployment bottleneck or
evaluate a separately reviewed policy that avoids pooling tiny control packets.
Any such implementation needs fresh paired evidence, reservation/ownership/race
controls and actual release-image acceptance at deployment resource limits. These
are possible follow-ups, not outstanding prerequisites for retaining default off.
