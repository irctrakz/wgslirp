# Unpaced encrypted IPv4 fragment acceptance

Status: profile implemented; repeated acceptance and default-policy change pending.
The original unpaced heap breach and diagnostic timeout remain recorded in
[encrypted fragment evidence](ENCRYPTED_FRAGMENTS.md). Default reassembly remains
disabled until this acceptance sequence passes.

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
- [ ] Require all three ordinary and three race samples to pass; retain failure
  evidence and investigate any failure before continuing.
- [ ] Pass the remaining full pipeline and actual-image validation/promotion for
  that commit before marking unpaced acceptance complete.
- [ ] Make a separate default-policy commit enabling `DefaultConfig` and normal
  executable startup, preserving explicit `IPV4_REASSEMBLY=false` and zero-value
  library configuration behavior.
- [ ] Validate normal default-enabled image startup with no environment override
  and the explicitly disabled image, then pass all unchanged pipeline gates and
  promote that exact tested artifact.

## Default-policy scope

Default enablement does not increase byte/datagram/source/range quotas, extend
expiry, add privileges or enable kernel routing. The source quota is an IP quota,
not authenticated-peer fairness: four sources can occupy all 32 assembly slots.
Existing assemblies and ordinary unfragmented packets continue independently of
new-slot admission. Source/global/storage/aggregate refusal counters and expiry
recovery remain the deployment signals; do not treat them as packet loss on the
physical uplink or raise caps without sizing the aggregate budget.

The policy decision will retain an explicit disable switch for deployments that
prefer fragment rejection. It does not promise reliable UDP delivery when a
fragment is genuinely lost, unbounded traffic capacity, or RSS return to a cold
baseline. Private-server testing remains paused. Only the development branch is
published; main/master and latest remain untouched.
