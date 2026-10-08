# Full packet pooling by default

## Decision (2026-10-07)

Enable the existing bounded packet cache by default for every supported packet
size, including ACK/control packets. Remove the selective 512-byte cutoff.
`POOLING=false` remains the explicit escape hatch; legacy `POOL_WRAP` remains
false because enabling it changes caller-provided buffer ownership.

This decision prioritizes throughput and latency, accepting additional memory
for even marginal repeatable gains. The [sustained comparisons](POOLING_SUSTAINED_ACCEPTANCE.md)
showed a modest full-pooling throughput tendency across twelve pairs. In the
[three-policy comparison](SELECTIVE_PACKET_POOLING.md), full pooling beat
selective throughput in all six groups; selective paired median throughput was
0.68% lower, and short TCP p95 was 3.32% higher. These are bounded fixture results,
not a universal performance guarantee. Removing the cutoff also removes an
allocation-policy branch and the retired three-policy comparison machinery.

## Contracts

- The environment adapter and unconfigured library fallback both enable pooling.
  Explicit `PoolConfig{Enabled: false}` and `POOLING=false` still disable it.
- Supported synthesized packets through 16 KiB charge the actual 2/4/8/16 KiB
  class, plus the existing queue allowance, before allocation. Tiny packets
  therefore consume more live budget than exact-sized storage; limits stay fixed.
- Larger buffers remain exact-sized. UDP reply and IPv4 reassembly storage retain
  their existing policies; this change does not pool every allocation in the process.
- Allocation and reservation share frozen-policy eligibility. Release captures
  that decision and returns the reservation once after packet ownership ends.
- Four classes of 32 entries retain at most 960 KiB idle process-wide. Excess
  returns are discarded, and reused packet bytes are cleared before synthesis.
- The cache does not change TCP negotiation, segmentation, locking, lifecycle,
  userspace routing or required kernel privileges.

## Acceptance

Required checks: Linux build/vet, unit/race, integration/race, fuzz controls and
the existing bounded encrypted fragment/unpaced/mixed/sustained/WAN/capacity
workloads. Keep all existing quotas, deadlines, resource and cleanup gates.

The actual release image must forward verified encrypted TCP/UDP and handle
SIGTERM during traffic under a non-root user, dropped capabilities, no-new-privileges,
read-only root, one CPU, 256 MiB memory/no swap and 128 PIDs. Two fresh containers
test unset pooling/reassembly defaults and explicit `POOLING=false` /
`IPV4_REASSEMBLY=false`. Both must report effective `POOL_WRAP=false`.
Read effective pooling from the image's allowlisted startup summary; do not
persist private environment values. Promotion requires the same immutable digest
that passed runtime checks, without rebuilding.

## Accepted evidence

[Run 37705426326](https://github.com/irctrakz/wgslirp/actions/runs/37705426326)
passed all 19 jobs at source `4c865c1608307d011f04b579e9ee71dfaec89e1b`:
Linux build/vet, unit/race, integration/race, bounded fuzz checks, sixteen
encrypted workload samples, actual-image validation and same-digest promotion.
[Resource samples](POOLING_DEFAULT_RESOURCE_SAMPLES.csv) retain all sixteen
workload checks. Every container exited successfully, with no OOM or memory/PID
limit events. The largest workload cgroup peak was 1,035,051,008 bytes, including
compilation and tmpfs, below the unchanged 2 GiB workload limit.

| Actual-image mode | Effective pooling | Effective wrapping | Memory peak after eight verified rounds | SIGTERM completion |
| --- | --- | --- | ---: | ---: |
| Defaults unset | true | false | 55,439,360 B | 83 ms |
| Explicit opt-outs | false | false | 25,042,944 B | 81 ms |

Both actual-image containers passed encrypted TCP/UDP, applicable fragment
checks and shutdown under traffic within the declared non-root, capability,
filesystem and 256 MiB resource restrictions. These memory observations are
fixture checkpoints, not a sustained production sizing guarantee.

Tested and promoted immutable image:
`ghcr.io/irctrakz/wgslirp@sha256:d9c5bf50a3a377bbb536f7b5601b43559f210dd8307c73eb14709ad669064891`.
Development tag:
`dev-4c865c1608307d011f04b579e9ee71dfaec89e1b-37705426326-1`.
The build manifest, runtime image reference and promotion manifest identify
the same digest; promotion did not rebuild it or retag `latest`.

Cleanup evidence verifies removal of all owned workload containers, tmpfs and
toolchain images, plus release runtime containers, network, builder/cache volume
and image. Work and publishing stayed on `codex/architecture-hardening`; main
and the private SSH server remained untouched. This establishes bounded acceptance,
not unlimited capacity or a universal performance gain.

The initial run `37701806315` was stopped before image validation after static
review found that the new startup-policy assertion ran after the long expiry
workload, when bounded log rotation could remove its evidence. The assertion moved
immediately after the first verified traffic rounds, without changing production
code, log limits or acceptance requirements. Completed baseline and encrypted
checks remain useful evidence, but this stopped run does not qualify promotion.
