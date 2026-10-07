# Selective packet pooling

Historical comparison of source `7fcaa40`. The subsequent
[full-pooling default decision](POOLING_DEFAULT_ACCEPTANCE.md) removes this
candidate's cutoff. Measurements below retain their original policy and source;
the retired `selective` dispatch profile is available only at that revision.

## Implementation and predeclared comparison

With `POOLING=true`, packet synthesis pools buffers from **512 through 16,384
bytes**. Smaller packets use exact-sized storage, including IPv4 TCP ACK/SYN/FIN
headers (at most 80 bytes with all options). Buffers above the cache's largest
class also remain exact-sized. This is a size policy, not protocol flag parsing;
small data packets can also bypass the cache. The 512-byte cutoff is an initial
candidate, not a claim of an optimal threshold for every deployment.

Allocation and reservation use the same frozen-policy eligibility predicate.
Live eligible packets charge their full pool class; others charge exact capacity,
plus the existing queue-entry allowance. Release captures the decision made at
allocation, returns eligible buffers only after ownership ends, and releases the
reservation exactly once. A first tiny allocation still freezes startup policy.
The four bounded classes and 960 KiB idle ceiling remain unchanged.

No additional environment variable or public configuration field is introduced.
`POOLING` still defaults off. Legacy `WrapPacket`, `PktPut` and `PktShouldPut`
continue their documented ownership/capacity behavior for caller-provided buffers.
UDP reply builders and IPv4 reassembly storage keep their existing allocation
policies. TCP negotiation, segmentation and userspace routing are unchanged.

### Comparison

Dispatch the existing Docker workflow on `codex/architecture-hardening` with
`pooling-study=true`, `pooling-profile=selective`. Use the same sustained mixed
fixture as [the previous comparison](POOLING_SUSTAINED_ACCEPTANCE.md): two 256 MiB
echo streams per direction, concurrent short TCP and UDP clients, exact-byte
verification and returned-reservation/worker checks.

Six groups compare three policies on the same runner/container:

1. Disabled: current source with `POOLING=false`.
2. Full pooling: a disposable source copy with only `poolutil.go` and
   `packet_storage.go` restored from `90e4df7d42fca7973f027e4024b56cfb4f90c4a2`.
   The current fixture and toolchain stay identical; the unused cutoff constant
   has no effect on this baseline. Record the restored files' hashes.
3. Selective: current source with `POOLING=true`.

All six order permutations occur once, balancing position/order. Each policy
uses a fresh process. Compare verified bulk throughput and short/UDP tail latency
first, accepting additional memory for repeatable performance gains. Allocations,
CPU profiles, GC, heap/RSS and admission counts support the assessment.

Isolated benchmarks include 40, 80, 128, 256, 511, 512, 1,024, 1,380, 8,192 and
20,000 byte buffers, 200 ms per case in this profile. This exposes the threshold
and small/control costs. Candidate off/selective queue-saturation controls check
exact charge, refusal and recovery; the full baseline runs benchmarks without
candidate-specific capacity assertions. Run all three policies under race for
encrypted correctness, excluding those smaller-payload runs from performance.

Keep the existing one-CPU, 2 GiB/no-additional-swap, 128-PID, non-root, dropped-cap,
read-only-root, bounded tmpfs/logs and 900-second deadline gates. Build/vet,
unit/race, integration/race, legacy encrypted mixed acceptance and corruption/
truncation/trailing-byte verifier controls remain required. Retain adverse results
and verify container/tmpfs/toolchain-image cleanup. The private server remains
unused; no image publishing or main-branch change occurs in the comparison.

## Results (2026-10-07)

[CI run 37697847115](https://github.com/irctrakz/wgslirp/actions/runs/37697847115)
passed on source `7fcaa405323547889ac505e3a0154db758166614`, first attempt.
All 18 ordinary processes verified 512 MiB in each direction while short TCP and
UDP traffic overlapped bulk traffic. All three policies passed separate race
workloads, baseline checks and legacy encrypted acceptance. Candidate capacity
controls verified reservation, one intentional refusal, release and readmission.
The full baseline's restored file hashes matched the pinned source.

The table reports medians of six within-group percentage changes, not percentage
changes between overall medians. Negative latency/CPU/allocation changes are
better; positive throughput changes are better. Every adverse sample is retained
in [ordinary samples](SELECTIVE_POOLING_SAMPLES.csv).

| Measurement | Selective vs disabled | Selective vs full pooling |
| --- | ---: | ---: |
| Verified bulk throughput per direction | +0.24% | -0.68% |
| Short TCP completion p95 | -0.86% | +3.32% |
| Short TCP completion p99 | -1.44% | +1.65% |
| UDP round-trip p95 | -0.27% | +2.43% |
| UDP round-trip p99 | -3.72% | +0.10% |
| CPU time | -0.22% | +0.73% |
| Allocated bytes | -10.94% | -0.07% |
| Allocation count | -2.71% | +0.06% |
| GC cycles | -9.39% | -1.82% |
| Sampled heap peak | +0.55% | -4.38% |
| Sampled RSS peak | +1.50% | -3.62% |

Selective throughput exceeded disabled in four of six groups. Full pooling
exceeded selective in all six groups; short TCP p95 was lower with full pooling
in five. These small differences on one runner do not establish deployment-wide
superiority, but the result does **not** support claiming that skipping tiny
packets improves sustained throughput over full pooling. Memory is not a veto:
the performance-first assessment retains this adverse comparison explicitly.

### Isolated packet storage

Median timings below come from six fresh processes per policy, with identical
fixtures. [All 180 allocation samples](SELECTIVE_POOLING_ALLOCATION_SAMPLES.csv)
include intermediate sizes and the 511/512-byte boundary.

| Buffer bytes | Disabled ns/op | Full ns/op | Selective ns/op |
| --- | ---: | ---: | ---: |
| 40 | 186.60 | 206.85 | 190.95 |
| 80 | 189.15 | 211.10 | 192.95 |
| 511 | 229.00 | 217.65 | 234.10 |
| 512 | 229.70 | 217.80 | 224.30 |
| 1,024 | 273.30 | 223.35 | 223.55 |
| 1,380 | 290.95 | 225.60 | 223.60 |
| 8,192 | 935.40 | 316.85 | 314.00 |
| 20,000 | 1,501.00 | 1,535.00 | 1,533.00 |

Selective storage is about 7.7% faster than full pooling for 40-byte packets and
8.6% faster for 80-byte packets. Larger eligible storage keeps its substantial
isolated benefit over disabled pooling. That isolated control-packet benefit
does not translate into a demonstrated mixed-workload win. At 511 bytes, full
pooling is already faster; the cutoff remains a conservative initial policy,
not an experimentally optimal crossover.

Under the fixed 64 KiB live budget, selective storage admits 390 40-byte packets,
315 80-byte packets and 102 511-byte packets; 512/1,380-byte packets admit 30,
charging their 2 KiB class plus queue allowance. Release returns the entire
reservation and allows immediate readmission. This accounting benefit is distinct
from measured throughput.

### Resource and deployment boundary

The container completed in 677 seconds within its existing 900-second deadline,
with a 1,127,743,488-byte cgroup memory peak including compilation and tmpfs,
exit zero, no OOM kill and zero memory/PID limit events. Cleanup verified removal of the
owned container/tmpfs and toolchain image; no owned network or volume was created.
The private server was unused and main was untouched.

The requested selective implementation is available with `POOLING=true`;
`POOLING=false` remains the global default. This run validates source and bounded
fixtures, and does not publish a release image. A later global default change
still requires a separate performance decision and actual release-image acceptance.
