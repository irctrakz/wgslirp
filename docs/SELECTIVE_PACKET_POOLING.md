# Selective packet pooling

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

Results pending. A later global default change still requires a separate policy
decision and actual release-image acceptance.
