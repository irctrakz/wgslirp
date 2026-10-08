# Resource budget measurements

## Current default policy (2026-10-07)

The executable and `socket.DefaultConfig()` now default to **256 TCP / 512 UDP
registered flows**, following deployment reports of admission refusal with the
previous 64/256 defaults. `WG_TUN_QUEUE_CAP` remains 1024. The 64 MiB shared buffer
budget, 64 pending dials and per-flow storage limits are unchanged; increased
flow admission does not increase those independent budgets. UDP reader storage
alone is approximately 32 MiB at 512 flows. TCP TIME-WAIT remains four minutes
and counts toward the TCP cap. Without extensions or other active flows, 256
slots correspond to approximately 64 host-first closes/minute at steady state.

The default-capacity TCP churn regression now exercises two 256-flow batches
(512 connections), including refusal at TIME-WAIT capacity and simulated expiry
recovery. The measurements below retain their original 64/256 fixture sizes;
they are historical evidence, not measured memory sizing for the new defaults.

## Historical scope and reproduction

`TestMixedTrafficMemoryRecovery` exercises real loopback TCP/UDP echo peers through `SocketInterface.WritePacket`, the production bridges and `SocketPacketProcessor`. A bounded guest sink replaces the guest network stack. The fixture uses no forced GC, scavenging, runtime memory-limit changes or background workload after completion.

Run in a resource-contained Linux environment:

```sh
go test -tags=integration -run '^TestMixedTrafficMemoryRecovery$' -v -count=1 -timeout=90s ./pkg/socket
```

The recorded environment uses Go 1.23.12, one CPU, 2 GiB memory with no swap, 128 PIDs, bounded tmpfs caches and a ten-minute outer container deadline. Test-owned listeners, accepted sockets and workers are closed/joined on both success and failure. Every remote stage also verifies removal of its dedicated container, network, `/tmp` workspace and admission lock. Machine-specific drivers and raw manifests are not repository artifacts.

## Workload and acceptance checks

- Small profile: 8 TCP and 32 UDP peers.
- Capacity profile: 64 TCP and 256 UDP peers, then repeated on a new interface.
- Pooled profile: the same capacity with buffer pooling enabled.
- Each peer performs 66 verified 1 KiB echo exchanges: one warmup, four rounds of 16 concurrent exchanges, and one after deliberate budget exhaustion.
- TCP peers run concurrently; at most 16 UDP requests are in flight against the shared echo socket. This bounds the fixture's burst size while retaining all 256 UDP flows. Initial unpaced testing lost a UDP response at the shared loopback peer; that run is not used as memory/default evidence.
- Extra TCP/UDP peers must receive `ErrFlowLimit` at the configured flow caps. Deliberate shared-budget exhaustion must refuse synthesis, and every admitted peer must work again after capacity is released.
- Live/peak reservations must stay within the configured budget. Shutdown must leave zero reservations and no registered flows.
- Samples cover each traffic round and four post-shutdown observations from zero to three seconds. Heap, RSS, goroutine-stack storage, heap pages and natural GC counts are logged. RSS is observed, not asserted to return to its initial value within three seconds.

The fixture includes allocations and sockets used by the echo peers and guest simulator. Its RSS is not an isolated router RSS measurement. It excludes encrypted WireGuard transport, WAN loss/latency, long-idle expiry and long-duration soak behavior. F10 separately covers bounded encrypted loopback round trips and an accepted finite low-rate natural-GC profile with ciphertext loss/reordering; see [ENCRYPTED_WORKLOADS.md](ENCRYPTED_WORKLOADS.md). Larger encrypted/WAN and long-duration evidence remain open in [RELEASE_VALIDATION.md](RELEASE_VALIDATION.md). Existing focused tests cover per-flow backpressure, pending-dial admission, queue rejection and ownership release.

## Default selection

At this measurement checkpoint, the application and `socket.DefaultConfig()` selected **64 TCP / 256 UDP active flows**. These counts matched the tested capacity profile rather than extrapolating to unlimited admission. They were conservative starting limits, not a universal performance optimum. See the current policy above for the subsequent increase.

The **64 MiB shared buffer budget** is retained: preliminary unpooled capacity runs peaked around **18.1 MiB** in normal traffic, leaving more than three times that observed storage available for larger bursts, retransmission and queue overlap. UDP reader storage alone consumes roughly 16 MiB at 256 flows. The deliberate overload step fills the shared budget; its peak must be distinguished from normal traffic samples.

The existing **64 pending dials**, **64 KiB pending payload per TCP flow**, **1 MiB retransmission payload per TCP flow**, and **960 KiB global idle pool ceiling** remain unchanged. Focused saturation tests establish their enforcement. This workload supports retaining the aggregate headroom; it does not establish optimal per-flow windows or dial latency under slow remote hosts. Per-flow maxima cannot all be filled simultaneously: the aggregate budget remains the final admission boundary.

Unset flow-cap settings previously admitted unlimited flows. Explicit `MAX_TCP_FLOWS=0` and `MAX_UDP_FLOWS=0` retain that compatibility option; positive values override the measured defaults. Explicit zero fields in hand-built Go configs remain unlimited. Buffer/dial zero values continue selecting finite defaults. Environment parsing tests cover unset, explicit unlimited and explicit finite configurations.

## Natural memory recovery

Final normal-traffic samples on 2026-09-18:

| Profile | Peak accounted bytes before overload | Maximum sampled traffic RSS (KiB) | RSS at 3 seconds idle (KiB) | Natural GC cycles | Reservations after teardown |
| --- | ---: | ---: | ---: | ---: | ---: |
| 8 TCP / 32 UDP | 2,366,336 | 14,452 | 13,396 | 8 | 0 |
| 64 TCP / 256 UDP | 18,976,656 | 57,316 | 54,284 | 14 | 0 |
| Capacity repeated | 19,012,016 | 64,448 | 57,988 | 11 | 0 |
| Capacity with pooling | 19,038,464 | 66,888 | 62,852 | 11 | 0 |

All profiles passed flow-cap rejection, post-exhaustion payload recovery and empty flow-registry checks. The suite's container peak, including compilation and dependency caches, was 430,587,904 bytes (410.64 MiB), with zero memory/PID-limit events. Container/network/workspace/lock cleanup was independently verified. Race-instrumented measurements are checked separately for correctness and are not used for these memory/default figures.

The initial successful unpooled capacity run recorded normal reservation peaks of 18,955,776 bytes; the repeat reached 18,998,184 bytes. Both returned to zero after teardown. During the first capacity run, sampled RSS reached 60,484 KiB and declined to 46,460 KiB after three seconds idle. The repeat reached 62,728 KiB and ended near 62,304 KiB. No forced collection was used; respectively 14 and 11 natural GC cycles occurred during the profiles.

This demonstrates reservation recovery and bounded storage under the measured traffic, but not immediate RSS return to a cold baseline. Go may retain heap pages and stacks after application ownership ends. Operational memory limits must allow for that caching and for kernel socket memory; do not equate `socket_buffer_bytes == 0` with zero process memory.

## Validation

Build, vet, the complete tagged integration suite (including unit/default-migration regressions) and tagged integration-race passed on 2026-09-18. Integration-race completed in 74.79 seconds including compilation; peak cgroup memory was 845,574,144 bytes (806.40 MiB). The 2 GiB/no-swap, one-CPU, 128-PID limits were unchanged. Every stage recorded zero memory/PID-limit events, independent zero-owned-residue checks and restored pause guards. No test process was left running. The workload evidence is for the documented finite profiles, not a production RSS guarantee.

## Close-state capacity caveat (F07)

TCP TIME-WAIT records now retain a flow slot for four minutes after an active or
simultaneous close, with bounded extension for duplicate FINs. Their host socket
is closed and acknowledged payload reservations are released, but they count
against `MaxTCPFlows` and registry-based active/closed metrics until expiry.
The profiles above keep connections open across exchanges. F10 adds
`TestTCPDefaultCapacityChurnAndTimeWaitRecovery`: two batches of 64 real loopback
TCP connections receive exact short responses, complete host-first close, release
payload storage and close host sockets. Each batch fills the default cap with
TIME-WAIT records, refuses a new connection, and admits the next batch after
explicitly advancing the expiry clock. All reservations release at shutdown.
This is bounded capacity/recovery evidence, not a four-minute wall-clock soak.

**Historical default-sizing decision:** retain the finite 64-flow default for the measured
small deployment profile, with an explicit churn constraint. Without duplicate
FIN extensions, 64 / 240 seconds is about **0.267 host-first closes per second
(16 per minute)** at steady state with no other active flows. Bursts can consume
all 64 slots immediately. A starting sizing estimate is active connections plus
peak sustained host-first closes/second times 240 seconds, plus burst/extension
headroom. Validate the resulting cap and memory budget for the deployment;
raising it is not a measured universal recommendation. Guest-first passive close
does not take this TIME-WAIT path. See [LIFECYCLE.md](LIFECYCLE.md) and
[RELEASE_VALIDATION.md](RELEASE_VALIDATION.md) for remaining workload limits.
