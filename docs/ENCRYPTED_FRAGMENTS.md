# Bounded encrypted fragment evidence

Status: finite-rate ordinary/race fragment profile and full pipeline accepted.
Default enablement remains separate and is still disabled.

## Profile and preselected gates

`TestEncryptedFragments` uses tags `integration,mixed,fragments,linux`. CI runs
fresh ordinary and race containers sequentially, using the existing 1 CPU,
2 GiB/no-swap, 128-PID, read-only, dropped-capability, bounded tmpfs/log and
600-second container deadline. Go's test deadline is 300 seconds. Container
memory/PID events must remain zero; owned container/image removal and absence
checks remain mandatory. The private SSH server is unused.

- Independent gVisor guest TCP stack: 128 short requests, two bulk connections
  checking 8 MiB in each direction, and 512 UDP round trips concurrently. A
  test-only guest TUN splits large TCP packets into at most 1200-byte IP fragments,
  duplicates the initial range, reverses subsequent ranges and deliberately
  drops one range from each of two packets. TCP must recover through its own
  retransmission behavior; exact host/guest payload checks remain unchanged.
  The guest reader pauses one millisecond between original IP packets, bounding
  its uplink at 1000 original packets/s (about 11 Mbit/s at MTU 1380); each packet's
  reordered/duplicate fragment burst remains intact. This finite-rate profile
  does not establish acceptance of an unpaced in-memory producer.
- Raw guest datagrams cross actual WireGuard encryption/decryption and production
  reassembly. Check 48 UDP datagrams of 8192, 16384 and 65507 payload bytes, using
  legal aligned fragments at MTUs 1200 and 1380. Host checks the entire payload;
  a small digest reply verifies the encrypted return path. This deliberately
  avoids requiring a second fragment reassembler as the test oracle.
- A late noninitial fragment replay after completion starts a bounded incomplete
  assembly; an exact repeat cannot extend its fixed lifetime. A separate UDP
  range is lost: no partial datagram may reach the host. Both assemblies must
  expire naturally, and the lost datagram must work when retried afterward.
- Two global-quota cycles: four sources retain eight incomplete datagrams each.
  A ninth for an already-full source increments only `source_limit`; a fresh
  source increments only `global_limit`. Completing one existing assembly must
  release its slot and admit the previously refused source. Its allocation cannot
  evict existing assemblies. All remaining 32 assemblies must expire each cycle.
- Ordinary encrypted TCP and UDP must progress while partial assemblies occupy
  the global quota, and after every expiry cycle. All fragment reservations and
  aggregate reservations must return to zero on joined teardown. Worker counts
  must return within four of the initial baseline within five seconds.

Sample heap/RSS every 100 ms during mixed traffic and on every ordinary round
during expiry. Ordinary bounds: 192 MiB sampled heap, 384 MiB sampled RSS; race
bounds: 256 MiB heap, 768 MiB RSS. Both permit at most 512 goroutines. Report
allocation bytes/objects and natural GC cycles, with RSS at each expiry recovery
and three idle observations after teardown. Initial, peak and final RSS are
reported. No forced GC, scavenging or runtime-limit changes are allowed.
Reservation recovery is asserted; RSS returning to its cold baseline is observed,
not assumed. Limits are fixed before acceptance and are distinct from the
actual release image's existing 256 MiB runtime validation profile.

## Fairness scope and counters

Sources are distinct allowed IPv4 addresses behind one encrypted peer; this tests
IP-source fairness, not authenticated-peer fairness or isolation. Quotas admit in
arrival order: a source can occupy at most eight of 32 live slots, while four
sources can collectively deny further fragmented admission until a slot is freed.
Unfragmented traffic and fragments of already-admitted assemblies bypass *new*
fragment-slot admission. Byte and aggregate budget checks still apply.

The fixed diagnostic map adds `source_limit`, `global_limit`, `storage_limit`,
`aggregate_limit`, `live_peak` and `source_peak`. Exactly one new-admission
reason is counted per refused attempt, in source/global/storage/aggregate order.
`rejected` still includes all fragment failures. Successful or rejected assembly
completion releases ownership after transport dispatch; timeout feedback runs
outside the cache lock. No addresses or dynamic labels appear in production metrics.

Expected quota totals on the datagram interface: `live_peak=32`, `source_peak=8`,
`source_limit=2`, `global_limit=4`, and `expired=66`. Other mixed-interface partial
assemblies are released by joined shutdown and do not count as timeout expiry.

## Acceptance and default-policy decision

The unpaced mixed profile failed the 192 MiB sampled heap gate in
[run 37375012908](https://github.com/irctrakz/wgslirp/actions/runs/37375012908).
The no-forced-GC breach profile in
[run 37375909341](https://github.com/irctrakz/wgslirp/actions/runs/37375909341)
attributed approximately 91 MiB (84% of sampled live space) to upstream
WireGuard message buffers, versus 5.8 MiB to reassembly. Reassembly accounted for
82 MiB (43%) of cumulative sampled allocation, so its allocation churn remains
a separate optimization candidate; a profile is not proof of a leak. The
diagnostic run also hit the unchanged mixed-traffic deadline. Profile sampling
can lag recent allocations and perturbs execution; it is diagnostic evidence,
not an acceptance run. Both failures had zero cgroup limit/OOM events and passed
owned cleanup. The finite-rate candidate retains all original byte/loss/quota,
memory/RSS, deadline and cleanup checks without changing production storage or
forcing GC.

### Finite-rate profile results

Both fragment modes passed in
[run 37376714607](https://github.com/irctrakz/wgslirp/actions/runs/37376714607)
on source `b99620bcfbc8f233fea23080fb909f23cc0b704c`:

| Measurement | Ordinary | Race |
| --- | ---: | ---: |
| Sampled peak heap, bytes | 159,381,208 | 143,494,848 |
| Sampled peak RSS, bytes | 144,629,760 | 538,411,008 |
| Final idle heap, bytes | 73,221,280 | 56,189,896 |
| Final idle RSS, bytes | 144,629,760 | 501,710,848 |
| Cumulative allocated bytes | 788,133,832 | 2,384,902,136 |
| Natural / forced GC cycles | 16 / 0 | 42 / 0 |
| Cgroup peak including compilation, bytes | 505,090,048 | 921,776,128 |

Both passed the original exact-byte mixed traffic, two fragment losses, 48 large
datagrams, 66 real expiries, late-duplicate recovery and two global quota cycles.
The observed peaks were 32 live assemblies and eight per source; source/global
refusals were exactly 2/4. Ordinary TCP/UDP progressed for 243 rounds per expiry
cycle in ordinary mode and 240/241/241 in race mode. All reservations returned to
zero, worker teardown passed, all cgroup memory/PID-limit events were zero, and
owned container/tmpfs/toolchain-image removal and absence checks passed.

Cumulative allocations are traffic volume, not simultaneously retained bytes.
Neither mode returned RSS to its cold baseline during the three-second idle
window; retained runtime/race memory is recorded without forced GC. These are
bounded observations, not a production capacity or leak-free proof.

The same run completed successfully: baseline build/vet/unit-race/integration-race
and fuzz checks, all ten ordinary/race workloads, actual-image validation and
tested-digest promotion passed (13 applicable jobs; two branch-inapplicable jobs
skipped). Every workload had zero cgroup memory/OOM/PID-limit events and passed
owned cleanup. The tested and promoted linux/amd64 artifact is:

`ghcr.io/irctrakz/wgslirp@sha256:a91d7784f99ce65e4ec957ef9f3b50341ade0992c95f34365544efe5975e4c5b`

Development tag:
`dev-b99620bcfbc8f233fea23080fb909f23cc0b704c-37376714607-1`.
The normal non-root image passed default rejection and explicit enabled
reassembly, with all capabilities dropped, one CPU, 256 MiB/no swap, 128 PIDs,
read-only root and bounded tmpfs/logs. Enabled mode retained eight assemblies
from a forty-ID flood, completed 222 ordinary TCP/UDP rounds during expiry,
expired all eight and restored fragment admission. Its observed cgroup memory
peak was 56,954,880 bytes; SIGTERM exited zero in 71 ms (default mode: 75 ms).
All runtime resource events were zero. Owned runtime containers/networks,
builder/cache volume and local tested image were removed; GHCR artifacts are
deliberately retained. Promotion preserved the tested digest, without rebuilding.

### Remaining work: allocation churn and unpaced acceptance

Implement these as separate reviewable changes, in the order below. The accepted
finite-rate profile remains a regression gate; neither item changes the default
policy or establishes unlimited forwarding capacity.

#### 1. Reassembly allocation churn

Implementation, isolated before/after measurements and remaining pipeline gates
are recorded in [reassembly allocation churn](REASSEMBLY_ALLOCATION_CHURN.md).

- [x] Establish an isolated reassembly allocation baseline, separate from
  WireGuard/gVisor allocations. Cover small fragmented packets, MTU-sized
  fragments and maximum datagrams, including completion, reordered ranges,
  exact duplicates, missing ranges, late duplicates, expiry and quota saturation.
  Record bytes and allocation objects per completed datagram, retained bytes
  during incomplete assemblies, and recovery after expiry and shutdown.
- [x] Use that evidence to select the smallest worthwhile storage change.
  Compare the same workload, runtime and measurement method before and after;
  report allocation savings and any throughput or retained-memory tradeoff.
  Do not infer a leak from cumulative allocations or optimize solely from a
  sampled heap profile.
- [x] Preserve reserve-before-retain, the aggregate/sub-budget boundaries,
  global/source/range quotas, and the charge held through synchronous dispatch.
  Completion, rejection, expiry and joined shutdown must release ownership
  exactly once. Any retained pool/cache or transient old/new storage must have
  explicit bounded accounting; moving allocations outside accounting is not a
  reduction in memory use.
- [ ] Verify unchanged checksum, overlap, ECN, duplicate and expiry behavior,
  exact-byte delivery, quota counters and recovery. Run focused regression,
  race and fuzz checks followed by the unchanged full bounded pipeline and
  actual-image validation/promotion for the tested commit. Accept the change
  only with demonstrated allocation improvement, no resource-gate regression,
  zero final reservations and verified worker/resource cleanup.

#### 2. Unpaced encrypted acceptance

- [ ] Declare a separate opt-in CI profile that removes the artificial
  one-millisecond pause per original packet. Unpaced still means finite traffic
  volumes and connection counts inside bounded containers, not an unlimited
  producer. Preserve the original short/bulk/UDP volumes, exact-byte checks,
  duplicate/reordering bursts and two deliberate fragment losses.
- [ ] Retain the current acceptance limits: ordinary heap/RSS 192/384 MiB,
  race heap/RSS 256/768 MiB, the 45-second mixed-traffic deadline, 300-second Go
  test deadline and 600-second container deadline. Keep one CPU, 2 GiB/no swap,
  128 PIDs, bounded tmpfs/logs and all cleanup/resource-event gates. Do not pass
  by shrinking traffic, adding pacing, removing loss, forcing GC or relaxing
  limits. A different capacity envelope requires a separately declared decision
  and does not resolve the original failed profile.
- [ ] Measure reassembly and WireGuard buffer/queue behavior together with
  allocation rate, sampled heap/RSS, natural GC, throughput, handshake latency
  and post-load recovery. Use profiled runs for diagnosis and unprofiled runs
  for acceptance; sampled allocation profiles can lag GC and instrumentation
  can affect timing. Retain the original heap breach and diagnostic timeout
  evidence alongside any new result.
- [ ] Predeclare a repetition count before running acceptance (proposed: three
  fresh ordinary containers and three fresh race containers). Require every
  run to meet unchanged gates without timeout, data mismatch, OOM/PID events or
  cleanup failures, with final reservations zero and workers joined. Follow
  with the full pipeline and actual-image validation, promoting the same tested
  digest before marking unpaced acceptance complete.

Private-server testing remains paused. These follow-ups retain arrival-order
admission: the per-source IP quota is not authenticated-peer fairness, and four
sources can occupy all 32 assembly slots. Default-policy review must explicitly
consider that limitation and retain the `IPV4_REASSEMBLY=false` escape hatch.

Native focused reassembly tests and Linux cross-vet including the new fixture
passed. The baseline build, vet, unit/race, integration/race and fuzz stage passed
in [run 37369562429](https://github.com/irctrakz/wgslirp/actions/runs/37369562429).
The new ordinary/race workload jobs remained queued without an assigned runner;
that run was cancelled before workload execution to validate the later RSS
checkpoint commit instead. It does **not** establish encrypted acceptance.
The default remains false while the separate default-policy review remains
open; finite-rate acceptance does not resolve the unpaced failure above. No
private-server workload was launched.

The runtime, allocation/RSS, counter and owned-cleanup evidence above accepts the
declared finite-rate profile. The arrival-order fairness limit and unpaced
failure remain explicit. A separate default-policy commit must preserve
`IPV4_REASSEMBLY=false`, verify the normal default-enabled image startup path and
the explicit disabled image path, and pass the unchanged full pipeline. There is
no claim of production capacity, authenticated-peer scheduling fairness or
successful UDP delivery when an actual fragment is lost.
