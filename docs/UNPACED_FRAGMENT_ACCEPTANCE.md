# Unpaced encrypted IPv4 fragment acceptance

Status: repeated unpaced acceptance and full pipeline passed. Default enablement
is implemented; its separate full pipeline and actual-image checks are pending.
The original unpaced heap breach and diagnostic timeout remain recorded in
[encrypted fragment evidence](ENCRYPTED_FRAGMENTS.md). The executable and
`DefaultConfig` now enable bounded reassembly; explicit false and zero-value
library configuration preserve rejection.

## Declared profile and gates

`TestEncryptedFragmentsUnpaced` shares the entire existing fragment fixture with
`TestEncryptedFragments`; its original-packet read delay is zero instead of one
millisecond. It adds no replacement pacing, GC tuning, buffer pool or production
change. Finite traffic is unchanged: 128 short requests, two bulk connections
with 8 MiB in each direction, 512 UDP round trips, duplicate/reordered fragment
bursts and two deliberately lost ranges. Large datagrams at MTUs 1200/1380,
late duplicates, 66 natural expiries, competing sources and two quota cycles
remain part of every run. Host byte checks and independent guest TCP recovery
remain the delivery oracle.

Before execution, the repetition count is fixed at **three fresh ordinary
containers and three fresh race containers**. The reusable workflow adds a
repetition matrix with `max-parallel: 1` and fail-fast enabled. Each container has
its own name, empty tmpfs/cache, deadline, resource readback and cleanup artifact;
no container or runtime memory is reused between samples. The accepted finite-rate
profile runs first and remains a separate regression gate.

The unchanged limits are:

- Ordinary sampled heap/RSS: 192/384 MiB; race: 256/768 MiB.
- At most 512 goroutines, zero forced GC, joined workers and final reservations zero.
- Mixed traffic deadline 45 seconds and all 130 TCP handshakes at most five seconds.
- Go test deadline 300 seconds; container deadline 600 seconds.
- One CPU, 2 GiB RAM/no swap, 128 PIDs, read-only root, all capabilities dropped,
  no-new-privileges, 768 MiB work tmpfs and 64 MiB temporary tmpfs, bounded logs.
- Zero memory/OOM/PID-limit events, exit zero, exact quota/refusal/expiry counters,
  normal TCP/UDP progress during saturation and verified owned resource removal.

Logs preserve mixed elapsed time, handshake p50/p95/max, socket budget peak,
host connection count and asynchronous dial starts. Additional mixed-phase
allocation bytes/objects and natural/forced GC accompany whole-test allocation,
heap/RSS, idle recovery and quota counters. On a resource breach, the existing
bounded allocation profile is diagnostic evidence, not a passing measurement.
Successful acceptance is unprofiled; no limit is relaxed to turn failure into a pass.

## Sequence

The first unpaced ordinary attempt (run
[37401457360](https://github.com/irctrakz/wgslirp/actions/runs/37401457360),
source `e37f132`) failed at the unchanged 45-second mixed-traffic deadline.
TCP refused 653 out-of-order storage requests; IPv4 fragment admission refused
none. Container OOM was false, memory/PID events were zero, and owned-resource
cleanup passed. The remaining five samples were cancelled; this is not acceptance.

Investigation found missing receiver-side SACK feedback for retained TCP bytes.
ACKs now report at most four retained ranges, most recently received first, only
with peer permission. Refused ranges never enter the feedback; cumulative ACKs,
storage reservations and lock ownership are unchanged. Focused regressions cover
refusal, duplicates, delayed ACKs, negotiation and wrap, and the regression fails
against the previous code in a disposable source copy. This follows
[RFC 2018](https://www.rfc-editor.org/rfc/rfc2018.html#section-4).
The repeated unpaced workload remains the acceptance gate; no deadline, pacing,
memory limit or storage quota has been relaxed.

The SACK-only follow-up at `0f427bb` passed baseline and finite-rate ordinary/race
checks in [run 37560249997](https://github.com/irctrakz/wgslirp/actions/runs/37560249997).
Its first unpaced sample failed at UDP round 3's two-second deadline; cleanup
waited until the shared 45-second deadline. TCP reported 807 reassembly refusals,
IPv4 fragment quotas reported none, memory/PID events were zero, and cleanup
passed. It does not establish unpaced acceptance.

The next change bounds advertised TCP receive space by the existing out-of-order
storage cap, consistently across ACK/data/retransmission/FIN paths. It negotiates
window scaling only when offered (including scale zero), clamps peer scales to
14, keeps SYN windows unscaled and avoids retracting the right edge as future
bytes are retained. Small caps reduce the scale to keep the window nonzero.
Packet reservations and checksums are finalized once before ownership transfer.
Focused wire tests pass; a disposable negative control restoring the old 8 MiB
advertisement fails against the expected 128 KiB receive window. See
[RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2).
The fixture now also records an earlier sampled resource breach if traffic fails,
so a subsequent deadline cannot hide the sampler's first error.

- [x] Implement the separate zero-delay profile and repeated bounded CI gate.
- [x] Require all three ordinary and three race samples to pass; retain failure
  evidence and investigate any failure before continuing.
- [x] Pass the remaining full pipeline and actual-image validation/promotion for
  that commit before marking unpaced acceptance complete.
- [x] Make a separate default-policy commit enabling `DefaultConfig` and normal
  executable startup, preserving explicit `IPV4_REASSEMBLY=false` and zero-value
  library configuration behavior.
- [ ] Validate normal default-enabled image startup with no environment override
  and the explicitly disabled image, then pass all unchanged pipeline gates and
  promote that exact tested artifact.

## Receive-recovery acceptance measurements

[Run 37561741720](https://github.com/irctrakz/wgslirp/actions/runs/37561741720)
tests source/fixture `324d2ee7dc4f0f9a1f7e44c52910cbbf572e3b06` without changing
the declared traffic, deadlines or resource limits. All six samples and all 19
applicable pipeline jobs passed; the table retains each sample.
Byte columns are exact reported bytes, not simultaneous peaks or cold-baseline
memory guarantees. Cgroup peaks include compilation and tmpfs caches.

| Mode/sample | Mixed ms | Handshake p95/max µs | Heap peak | RSS peak/final | Total allocation bytes/objects | Natural GC | Cgroup peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ordinary 1 | 10471 | 4886 / 5810 | 161559008 | 157425664 / 151236608 | 374856888 / 670474 | 10 | 519192576 |
| Ordinary 2 | 10583 | 9577 / 12190 | 180386208 | 204029952 / 146112512 | 390834496 / 670590 | 9 | 566816768 |
| Ordinary 3 | 10425 | 5060 / 7462 | 190015264 | 201928704 / 143327232 | 391323600 / 669864 | 9 | 564617216 |
| Race 1 | 15922 | 135897 / 194837 | 192832392 | 640626688 / 292888576 | 1849464472 / 4527065 | 30 | 1040236544 |
| Race 2 | 13155 | 65042 / 79934 | 188634384 | 640151552 / 342589440 | 1846606064 / 4537441 | 32 | 1053614080 |
| Race 3 | 15788 | 119471 / 152315 | 186072392 | 631230464 / 297758720 | 1847613288 / 4493562 | 30 | 1048559616 |

Completed samples have exact traffic checks, zero forced GC, 66 expiries, source
and global refusal counts 2/4, live/source peaks 32/8, 55 duplicates and zero final
reservations. Resource readback, zero memory/PID events and owned cleanup are
independently checked from their artifacts. All six fresh samples passed on their
first attempts at this commit. Mixed, sustained, WAN and capacity ordinary/race
checks also passed, including real four-minute TIME-WAIT retention and recovery.

The actual image passed both the old default-rejection and explicitly enabled
fragment modes as UID 100, with all capabilities dropped, read-only root, 1 CPU,
256 MiB/no swap and 128 PIDs. SIGTERM exit zero took 72/78 ms. Enabled mode retained
eight assemblies / 557,048 reserved bytes, continued 222 ordinary rounds during
real expiry, released reservations and restored fragmented admission. All
memory/PID events were zero and owned runtime containers, networks, builder,
cache volume and local image were removed. The tested and promoted digest was:

`ghcr.io/irctrakz/wgslirp@sha256:e9b6cd3df48e1976828f7c76a5ba78c87ad1ab947a0b6e65387018d599e610aa`

Promotion retained that manifest without rebuilding under
`dev-324d2ee7dc4f0f9a1f7e44c52910cbbf572e3b06-37561741720-1`.
This closes unpaced acceptance for the receive-recovery commit. The separate
default-policy commit must repeat all gates and test an absent setting plus
explicit false on its own actual image before promotion.

## Default-policy scope

### Default-policy validation failure and bounded reuse

[Run 37566970665](https://github.com/irctrakz/wgslirp/actions/runs/37566970665)
at `259cc5f389d43fcb015e2310e06117f2b62be16f` passed baseline and both finite-rate
checks, then failed the first unpaced ordinary sample's unchanged 192 MiB heap
gate: 209,461,408 heap bytes, 192,806,912 RSS bytes. Mixed traffic completed in
10,502 ms with 130 accepted connections, no empty connections and no admission
refusals. The remaining repetitions were cancelled; no image was promoted.
Cgroup peak was 559,501,312 bytes, all memory/PID events were zero and owned
cleanup passed. This failure remains evidence rather than being retried away.

The sampled heap profile attributes most reported storage to upstream WireGuard
message buffers, but its 56.88 MiB in-use total lags the failing runtime sample;
it cannot establish the full live/garbage breakdown at that instant. Failure
diagnostics now retain allocation totals, natural GC count and next GC target.
Reassembly's independently measured per-datagram allocation churn is reduced by
reusing released small assembly objects in a cache bounded by the existing
32-datagram limit. No packet or expiry owner relinquishes storage before release;
large promoted payloads are never cached. The unchanged full pipeline must pass
again before default-policy acceptance or promotion is marked complete.

[Run 37568200098](https://github.com/irctrakz/wgslirp/actions/runs/37568200098)
at `05dbf322782be2168259acbfe9cf7e81d82eeac0` passed baseline and finite-rate
ordinary/race checks but still failed the unpaced heap gate when starting the
separate datagram fixture: heap 209,897,528, RSS 188,973,056, next-GC target
228,385,320 bytes, seven natural GC cycles and zero forced GC. Mixed traffic
completed in 10,474 ms with all 130 connections and no admission refusals.
The profile's reported in-use storage was dominated by WireGuard message buffers
(78.19 MiB, 86.6%). Resource events were zero and owned cleanup passed; remaining
jobs were cancelled and no image was promoted. Reduced reassembly churn alone
did not establish the required peak bound.

The fragmenting guest fixture now returns the ready ranges of one original
packet as a batch, using WireGuard's existing read-buffer contract. It never
waits for another original packet, adds no delay, preserves emitted fragment
order/duplicates/losses and copies each frame into WireGuard-owned buffers.
Previously it emitted each ready range as a separate one-packet read, increasing
queue/container overhead. A regression checks partial batches and ownership.
All traffic, per-original pacing settings, loss injection, memory/resource gates,
GC policy and deadlines remain unchanged. Acceptance still requires six fresh
unpaced samples, the full workload chain and actual-image validation/promotion.

Default enablement does not increase byte/datagram/source/range quotas, extend
expiry, add privileges or enable kernel routing. The source quota is an IP quota,
not authenticated-peer fairness: four sources can occupy all 32 assembly slots.
Existing assemblies and ordinary unfragmented packets continue independently of
new-slot admission. Source/global/storage/aggregate refusal counters and expiry
recovery remain the deployment signals; do not treat them as packet loss on the
physical uplink or raise caps without sizing the aggregate budget.

The policy decision retains an explicit disable switch for deployments that
prefer fragment rejection. It does not promise reliable UDP delivery when a
fragment is genuinely lost, unbounded traffic capacity, or RSS return to a cold
baseline. Private-server testing remains paused. Only the development branch is
published; main/master and latest remain untouched.
