# IPv4 reassembly allocation churn

Status: implementation and native measurements complete; full bounded Linux
pipeline and actual-image acceptance pending. Unpaced acceptance and default
enablement remain separate work.

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
and completion restore live slots and reservations to zero; no forced GC is used.

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

- [x] Establish isolated before/after allocation evidence.
- [x] Implement a bounded storage change preserving ownership and quota policy.
- [x] Pass focused regression tests and Linux cross-build/vet.
- [ ] Pass full Linux build/vet/unit-race/integration-race/fuzz checks.
- [ ] Pass all bounded ordinary/race encrypted workloads, reviewing allocation,
  heap/RSS, recovery, zero resource events and owned cleanup evidence.
- [ ] Validate the actual release image and promote the same tested digest.

See the [remaining acceptance sequence](ENCRYPTED_FRAGMENTS.md#remaining-work-allocation-churn-and-unpaced-acceptance).
This change does not establish unpaced acceptance or authorize default enablement.
