# IPv4 reassembly allocation churn

Status: implemented and accepted through the full bounded Linux pipeline,
actual-image validation and same-digest development promotion. Unpaced acceptance
and default enablement remain separate work.

## Measured problem and selected change

Previously every admitted assembly allocated a 65,535-byte wire buffer, even
when a complete datagram fit within an ordinary MTU. The isolated benchmark
excludes fixture construction and WireGuard/gVisor; it measures reassembly,
completion/release, missing-range expiry and global quota saturation.

The assembly now contains a 2,048-byte inline buffer. A validated range extending
beyond it causes at most one promotion to the original full-size buffer. Existing
inline bytes are copied once, and completion dispatches the active tier without
a completion copy. Large or high-offset fragments still require full storage.
There is no buffer pool, retained cache or incremental growth policy.

Range offsets use `uint16`, sufficient for the validated maximum payload offset
and end (65,515). Compact ranges leave room for inline storage within the
existing metadata allowance. On amd64 the assembly object is 2,912 bytes;
a regression check reserves at least 512 bytes of the 4,096-byte allowance for
map metadata. The existing fixed 69,631-byte reservation covers the object and
full buffer simultaneously, including promotion. Go allocator overhead, garbage
awaiting GC and process RSS remain distinct from logical ownership accounting.

Admission, aggregate and fragment budgets, 32 global/eight source/128 range
quotas, expiry deadlines and diagnostics are unchanged. Reservation occurs
before allocating either tier and remains live through synchronous dispatch or
timeout feedback. Rejection, expiry and joined shutdown retain the same release
paths; the dispatch release remains idempotent. Borrowed input is never retained.
All routing remains in userspace with unchanged privilege requirements.

## Native before/after evidence

Go 1.23.12, windows/amd64, `GOMAXPROCS=2`, 100 ms per benchmark, three repetitions.
Baseline production source: `abe3b56`; both versions use the same benchmark
fixtures. Baseline quota measurements used a disposable source copy, removed
after execution. These are allocation comparisons, not Linux production
throughput or encrypted/RSS acceptance.

| Work per operation | Before bytes / allocations | After bytes / allocations |
| --- | --- | --- |
| Complete 128-byte payload, ordered or reordered/duplicate | 68,784 / 4 | 3,120 / 3 |
| Complete 1,360-byte payload, ordered or reordered/duplicate | 68,784 / 4 | 3,120 / 3 |
| Complete 8,192-byte or maximum payload | 68,784 / 4 | 68,656 / 4 |
| Missing first/final range followed by expiry, MTU-sized offsets | 68,744 / 3 | 3,080 / 2 |
| Admit 32 small assemblies, refuse the 33rd, expire all | approximately 2,200,080 / 70 | approximately 98,824 / 38 |
| Admit 32 high-offset assemblies, refuse the 33rd, expire all | approximately 2,200,080 / 70 | approximately 2,195,982 / 70 |

Small/MTU completion allocates about 95.5% fewer bytes. Allocation object count
drops by one; large datagrams still allocate a full buffer. Large-datagram timing
overlaps the baseline range in these short local samples; no throughput gain is
claimed. At saturation, logical assembly storage is 93,184 bytes for inline-only
assemblies or 2,190,304 bytes when all are promoted, excluding maps/allocator
overhead. Both retain the same conservative 2,228,192-byte reservation. Expiry
and completion restore live slots and reservations to zero. Isolated measurements
use Go's standard benchmark harness, which performs GC between samples; they
are not RSS-recovery evidence. The encrypted acceptance workload forbids forced GC.

Reproduce isolated measurements:

```sh
go test ./pkg/socket -run '^$' -bench '^BenchmarkIPv4Fragments$' \
  -benchmem -benchtime=100ms -count=3 -timeout=60s
```

## Regression and acceptance gates

Native focused fragment tests pass, including exact inline/promotion boundaries,
ordered and tail-first maximum datagrams, borrowed-input reuse, duplicate ranges
across promotion, dispatch ownership through cache close, repeated release,
promoted-storage conflict rejection and expiry. Linux/amd64 cross-build and vet
pass. A ten-second native reassembly fuzz check passed 520,549 executions with
two workers. The broader Windows socket suite encountered the empty-UDP forwarding
timeout; it is not recorded as a passing full suite. Native executable build is
unsupported by existing Linux-only resource syscalls.

The fragment CI jobs additionally retain three ordinary/race isolated benchmark
samples in `reassembly-allocations.txt` inside the existing bounded container and
14-day evidence artifact. Existing encrypted workload volumes, packet loss,
memory/RSS, resource-event, deadline and cleanup gates remain unchanged.

### Bounded encrypted fragment result

[Run 37382676625](https://github.com/irctrakz/wgslirp/actions/runs/37382676625)
tests production/fixture commit `b8233254a16471aa1073b7500cdcf26c22ed3e77`.
Both fragment modes passed; Linux isolated benchmarks reproduced 3,120 bytes /
three allocations for small/MTU completion and 68,656 bytes / four allocations
for large/maximal completion in all three samples, including race mode.

| Observation, bytes unless noted | Ordinary | Race |
| --- | --- | --- |
| Sampled peak heap | 145,602,680 | 136,315,568 |
| Initial RSS | 9,355,264 | 32,014,336 |
| Peak RSS | 137,969,664 | 478,756,864 |
| Final idle heap | 59,393,056 | 69,632,224 |
| Final idle RSS | 102,375,424 | 475,410,432 |
| Cumulative allocated bytes | 353,034,856 | 1,953,777,216 |
| Allocation objects | 702,912 | 5,047,907 |
| Natural / forced GC cycles | 10 / 0 | 36 / 0 |
| Cgroup peak including compilation and benchmarks | 440,037,376 | 821,796,864 |

The prior accepted finite-rate run allocated 788,133,832 ordinary and
2,384,902,136 race bytes cumulatively. Traffic volumes and acceptance gates are
unchanged, but TCP recovery/fragment counts, scheduling, runner CPUs and natural
GC vary. These observations support the isolated allocation saving; they do not
attribute every heap/RSS change to inline storage or establish unpaced capacity.
Neither mode returned RSS to its cold baseline during the three-second idle
window. Race final idle heap was higher than in the previous run despite lower
sampled peaks; no full memory-return claim or forced scavenging is made.

Both modes completed 128 short requests, 8 MiB bulk in each direction, 512 UDP
round trips, two deliberate fragment losses, 48 large datagrams and 66 natural
expiries. Source/global refusals remained 2/4, live/source peaks 32/8 and duplicates
55. Ordinary TCP/UDP continued for 243/243/243 rounds across the expiry cycles;
race completed 240/242/241. Final reservations were zero and worker teardown
passed. Both containers exited zero without OOM; all cgroup memory/PID events
were zero. Artifacts confirm the unchanged limits and successful owned container,
tmpfs and toolchain-image removal/absence checks.

### Full pipeline and tested artifact

The same run completed successfully: all 13 applicable jobs passed (two jobs for
other branch/event policies were skipped). Baseline build/vet/unit-race,
integration-race and all three ten-second fuzz stages passed, followed by all ten
ordinary/race fragment, mixed, sustained, WAN and churn/capacity workload jobs.
Every workload artifact passed exit, enforced-limit, zero memory/OOM/PID-event
and owned-cleanup review. The largest workload cgroup peak, including compilation,
was 883,105,792 bytes in mixed race mode. Capacity recovered after real 240-second
TIME-WAIT in both modes; sustained and WAN retained their existing loss profiles.

The actual linux/amd64 release image passed default-disabled and explicit enabled
reassembly as UID 100, with one CPU, 256 MiB/no swap, 128 PIDs, a read-only root,
all capabilities dropped and no-new-privileges. Default mode verified eight
encrypted TCP/UDP rounds and the existing aggregated fragment-rejection log
contract. Enabled mode retained eight flood assemblies with the unchanged
557,048-byte reservation, expired all eight and restored admission while completing
230 ordinary TCP/UDP rounds during saturation. Reported cgroup memory peaks were
28,893,184 / 50,896,896 bytes; SIGTERM exited zero in 60 / 58 ms. Both modes had
zero memory/PID events and no OOM. Cleanup verified no owned runtime containers,
networks, builder, cache volume or local candidate image remained.

Tested and promoted artifact:

`ghcr.io/irctrakz/wgslirp@sha256:046e35cc1170638419b8652b69458fbd2e08ddf0a01fe49ab2edf502f7ddb6ec`

Development tag:

`ghcr.io/irctrakz/wgslirp:dev-b8233254a16471aa1073b7500cdcf26c22ed3e77-37382676625-1`

Source and fixture both match `b8233254a16471aa1073b7500cdcf26c22ed3e77`.
Promotion's recorded manifest digest matches the tested digest exactly; no rebuild
occurred. Workload artifacts are retained for 14 days and image/promotion evidence
for seven days; the written measurements above preserve the acceptance summary.
GHCR artifacts are deliberately retained. The private server was not used; no
main/master or latest publication occurred.

- [x] Establish isolated before/after allocation evidence.
- [x] Implement a bounded storage change preserving ownership and quota policy.
- [x] Pass focused regression tests and Linux cross-build/vet.
- [x] Pass full Linux build/vet/unit-race/integration-race/fuzz checks.
- [x] Pass all bounded ordinary/race encrypted workloads, reviewing allocation,
  heap/RSS, recovery, zero resource events and owned cleanup evidence.
- [x] Validate the actual release image and promote the same tested digest.

See the [remaining acceptance sequence](ENCRYPTED_FRAGMENTS.md#remaining-work-allocation-churn-and-unpaced-acceptance).
This change does not establish unpaced acceptance or authorize default enablement.

## Released-object reuse during default-policy validation

The later default-policy run hit the unchanged unpaced heap gate; see
[failure evidence](UNPACED_FRAGMENT_ACCEPTANCE.md#default-policy-validation-failure-and-bounded-reuse).
The reassembler now reuses small assembly objects only after dispatch/expiry
release. An explicit cache under the existing mutex holds at most 32 objects;
cached plus live objects remain bounded by the admission limit. Its maximum idle
object storage on amd64 is 93,184 bytes, plus the fixed pointer array and allocator
overhead. Idle objects have no live buffer reservation; this bounded metadata
retention is separate from reserved packet bytes. Full-size promoted payloads
are dropped on release, never cached, and close clears the idle cache.

Native Windows/amd64 isolated benchmarks (`-benchtime=100ms`, no forced GC)
measure small/MTU completion at 48 B / 2 allocations versus 3,120 B / 3 previously;
large/maximum completion at 65,584 B / 3 versus 68,656 B / 4; and expiry at
8 B / 1 versus 3,080 B / 2. Quota-saturation inline cycles report about 527 B /
6 allocations amortized, retaining the same 93,184 owned assembly bytes per
cycle. These isolate churn savings; they do not prove full-workload peak reduction.
Regression checks retain dispatch output until release, reset reused state,
discard promoted payloads and verify an old idempotent release callback cannot
release a new owner of the same object. Native socket checks, Linux cross-build
and tagged vet passed; bounded Linux CI and actual-image validation remain pending.
