# Finite encrypted WAN/soak fixture

**Current status (2026-09-22):** the separately defined A1 natural-GC acceptance
profile passed three fresh-process ordinary runs and three fresh-process race
runs. The original tighter 64 MiB/30-second profile and its failures remain below
as historical evidence; that old criterion was not made to pass. Higher-rate,
larger and long-duration acceptance remain outside this result.

## A1 natural-GC acceptance profile (criteria declared before execution)

The original `TestEncryptedWANSoak` retains its 64 MiB/30-second guard and its
failure history. A separate `TestEncryptedWANMemoryAcceptance` evaluates whether
the initialized encrypted link can collect naturally while traffic stays bounded.
This is an explicit change of acceptance criterion, not a production memory fix.

The extended diagnostic measured initialized heap 51,266,392 bytes and a later
`NextGC` target of 103,126,544 bytes. Sampled allocation stacks chiefly identify
wireguard-go message-buffer pools. One live-link collection returned heap to
51,365,512 bytes. Five seconds after device cleanup, RSS still measured about
178 MB; a subsequent diagnostic collection left about 42.8 MB heap. These
measurements distinguish reclaimable allocation, pool retention and RSS; they
do not establish immediate RSS recovery or identify every retained object.
Profiles retain only eight sampled allocation stacks (function names and raw
sampled bytes, not scaled totals or packet/key contents). Visibility may lag GC.

Predeclared acceptance for the new finite profile:

- Same one TCP/one UDP link, payloads, one-second pause, delay/reorder/drop policy;
  at most 90 seconds of traffic and 96 rounds (480 KiB application payload per
  direction maximum). At least 64 completed rounds; test deadline 120 seconds.
- Initialized heap at most 64 MiB; sampled heap at most 128 MiB and process RSS
  at most 256 MiB throughout completed-round and five-second post-cleanup samples.
  The heap ceiling permits the observed roughly 98 MiB GC target plus bounded
  headroom. The RSS ceiling includes both devices, peers and race instrumentation;
  it is a test-process envelope, not a per-instance production memory guarantee.
- Observe at least one additional natural GC; at each observed GC transition,
  sampled heap must be within 8 MiB of initialization. Complete at least eight
  additional rounds after the first observed collection. Sampling is not exact
  live-heap measurement and does not detect arbitrary between-sample spikes.
- No increase in forced-GC count; no runtime GC/memory-limit changes. Keep the
  existing harness `GOMAXPROCS=1`, `GOMEMLIMIT=512MiB`, 1 CPU, 2 GiB/no swap,
  128 PIDs, bounded tmpfs and 600-second outer deadline.
- Existing exact payload, actual loss/reordering, duplicate ACK, zero relay
  overflow and reservation checks remain. Shutdown must leave zero socket flows
  and reservations. After child cleanup joins devices/relay/peers, sample for five
  seconds; goroutines must return to the pre-link count plus at most four.
- Require three separate fresh-process non-race runs and three fresh-process race
  runs before accepting the profile. A run without an observed GC fails for
  insufficient evidence. Do not use `-count=3` in one process as fresh-process evidence.

```sh
go test -v -tags=integration,soak -run='^TestEncryptedWANMemoryAcceptance$' -timeout=120s -count=1 -parallel=1 ./pkg/wireguard
go test -v -race -tags=integration,soak -run='^TestEncryptedWANMemoryAcceptance$' -timeout=120s -count=1 -parallel=1 ./pkg/wireguard
```

The diagnostic still has explicit collections and remains separate from acceptance.
Larger/higher-rate and long-duration workloads remain F10e follow-ups even if this
finite baseline passes. No server limit was increased.

### A1 repeat results (2026-09-21/22)

All runs used the same Go 1.23.12 contained environment and profile, each in a
fresh process/container. Values below are bytes; peaks are sampled process values,
not container peaks or exact instantaneous maxima.

| Mode/run | Rounds | Natural GCs after initialization | First observed GC round | Heap peak | RSS peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ordinary 1 | 87 | 1 | 60 | 64,132,936 | 21,991,424 |
| Ordinary 2 | 87 | 1 | 61 | 64,262,320 | 22,315,008 |
| Ordinary 3 | 87 | 1 | 60 | 64,074,496 | 21,893,120 |
| Race 1 | 86 | 1 | 49 | 90,054,736 | 258,781,184 |
| Race 2 | 86 | 2 | 11 | 91,545,376 | 255,025,152 |
| Race 3 | 86 | 2 | 10 | 93,590,336 | 260,255,744 |

Initialized heap was 51.25–51.32 MB. Samples immediately following observed
natural collections were 51.60–52.25 MB, comfortably within the declared 8 MiB
growth allowance. Every run verified 11 ciphertext drops, 96–97 reordered
deliveries, duplicate ACK recovery, exact TCP/UDP payloads, zero relay overflow
and zero final flows/reservations. RTO count was zero; recovery exercised the
duplicate-ACK path. After device/relay/peer cleanup, the final goroutine sample
was two. No forced GC occurred in any acceptance run.

Race instrumentation materially changes this fixture's measured footprint:
peak RSS was about 243–248 MiB with race detection versus about 21 MiB without.
The race profile has limited RSS headroom below its 256 MiB ceiling. HeapAlloc
and RSS measure different things and should not be equated; these totals include
both WireGuard devices and fixture peers. No per-production-instance estimate
or universal capacity claim follows from them.

**Decision:** F10e.2's repeatable finite low-rate baseline is accepted under the
explicitly revised natural-GC criterion. No production memory fix, GC tuning,
server-limit increase or claim of immediate RSS reclamation is warranted by these
results. The old 64 MiB guard was below the initialized link's later collection
target and is not the current acceptance gate. Its opt-in test remains unchanged
and can still fail; select the named acceptance test rather than running every
`soak`-tagged experiment indiscriminately. Larger profiles must predeclare their
own bounds and cannot inherit this pass.

The additional diagnostic and all six acceptance stages recorded zero memory/
OOM/PID-limit events and independently verified no owned container, network,
workspace or lock residue. Acceptance-stage container peaks were 325,951,488–
500,924,416 bytes, including build/cache/tmpfs overhead. Pause guards were restored
after each stage; execution helpers and raw evidence remain private and ignored.

### A1 final regression validation (2026-09-22)

The full ordinary unit/tagged integration suite passed with the race detector
(excluding opt-in `soak` experiments), followed by build/module tidy/verification
with unchanged module files and vet including `integration,soak` code. Container
peaks were 819,204,096, 437,231,616 and 376,377,344 bytes respectively. Formatting
and diff whitespace checks passed. No parser/encoder changes required a new fuzz
campaign; the existing parser/encoder regressions ran in the ordinary suite.

Across all ten A1 stages (one diagnostic, six acceptance repeats and three final
checks), there were zero memory/OOM/PID-limit events and independently verified
zero owned remote residue. The largest container peak was 819,204,096 bytes.
Remote pause guards are restored. Production code/defaults and server limits
are unchanged; implementation and documentation are committed locally only.

## Original tight-guard profile and historical findings

`TestEncryptedWANSoak` is an initial low-rate workload, not a throughput or
long-duration stability claim. It uses two real wireguard-go devices, in-memory
TUNs, the production socket bridges and real loopback TCP/UDP peers. No kernel
TUN, raw socket, netem, root or network-administration privilege is required.
The shared encrypted fixture aligns socket and WireGuard MTUs at 1380.

## Finite profile

- One persistent TCP connection and one UDP flow; 30-second traffic window,
  maximum 32 rounds, one-second pause between rounds, at least 16 completed rounds.
- Each round checks a 1 KiB UDP echo, 1 KiB TCP request and 4 KiB TCP reply exactly.
  Application traffic is at most 160 KiB in either direction (excluding headers,
  retransmissions and handshake); total test timeout is 90 seconds.
- A single userspace relay owns at most 64 ciphertext datagrams, each below 2048
  bytes. It adds a nominal 2 ms delay in both directions and delays every third
  server transport datagram by 20 ms to induce reordering. Actual scheduling delay
  is measured indirectly through completion; this is not calibrated WAN emulation.
- Every eighth round arms a single drop of a server transport datagram larger
  than 1000 bytes during the TCP reply. UDP completes before the drop is armed.
  The guest uses bounded reassembly (at most eight pieces within the 4 KiB reply)
  and cumulative ACKs. It does not advertise SACK, renege or complete a full
  sequence-number cycle. Reordering and actual drops must both occur.
- Five-second socket/reply deadlines, zero relay queue overflow, heap below
  64 MiB and no more than 256 goroutines after each round. Reservation usage must
  remain within the configured budget and reach zero at socket shutdown.
- Relay, devices, TUNs, host sockets and workers are closed/joined by cleanup.
  The external harness independently enforces 1 CPU, 2 GiB/no swap, 128 PIDs,
  bounded tmpfs and a 600-second container deadline, then checks zero owned residue.

Run the soak alone in a fresh process. The separate tag keeps ordinary CI finite:

```sh
go test -v -race -tags=integration,soak -run='^TestEncryptedWANSoak$' -timeout=90s -count=1 -parallel=1 ./pkg/wireguard
```

## Guard findings and unresolved higher-rate memory

The initial 250 ms / maximum-128-round profile did not pass. A combined run hit
the heap/worker guard, then an instrumented combined run showed 97,718,880 bytes
of heap before soak traffic and only 56 goroutines. Running the soak alone started
at 51,285,528 bytes and hit 67,741,696 bytes at round 36 after 10.71 seconds.
The 64 MiB guard correctly stopped it; no container memory/OOM/PID-limit event
occurred and every failed stage verified cleanup. The first run also exposed an
MTU mismatch in the test setup, which was corrected.

The profile was reduced to one round per second and 32 rounds; the heap guard
and all containment limits were retained. That run also failed: 67,529,256 bytes
at round 24 after 24.33 seconds, starting from 51,310,256 bytes. The 30-second
soak therefore remains an unsatisfied opt-in gate, not completed coverage. The soak uses no forced GC or runtime memory-limit change. A separate
`TestEncryptedWANMemoryDiagnostic` stops at the same guard (or the finite
workload endpoint) and performs one explicit GC to measure retained heap, then
shuts down. Its success only means
the diagnostic completed; it cannot turn a failed soak into a pass. Follow-up must distinguish live retention from allocator/pool behavior
with bounded post-drain heap/RSS sampling and allocation profiles before increasing
traffic or duration. Preserve the failed evidence; do not call this a leak or
claim natural recovery without measuring it.

## Remaining F10e coverage

Higher-rate and larger encrypted profiles, long-duration steady-state/idle/close
expiry, mixed high churn, calibrated WAN loss/latency distributions, SACK/receiver
reneging and full-sequence transfers remain open. Actual release-image execution
and external review/enforcement remain F10d. Environment-specific launchers and
raw manifests stay private and ignored; no upstream action is needed.

Run the diagnostic separately in a fresh process:

```sh
go test -v -race -tags=integration,soak -run='^TestEncryptedWANMemoryDiagnostic$' -timeout=90s -count=1 -parallel=1 ./pkg/wireguard
```

The opt-in soak is deliberately still capable of failing at the documented guard;
do not add `soak` indiscriminately to ordinary CI or claim every test passed.

## Observed diagnostic results (2026-09-19)

A diagnostic run completed 29 rounds in 30.50 seconds without explicit GC,
recording four dropped ciphertext datagrams, 32 reordered deliveries, no relay
overflow, heap peak 66,376,032 bytes and zero final reservations. This was close
to the guard and did not erase earlier failures.

The final diagnostic reached the same guard at round 29: heap before collection
68,034,344 bytes, after one diagnostic GC 51,327,360 bytes, initial heap
51,330,168 bytes. GC count changed from five to six; goroutines stayed at 57.
It observed four drops, 32 reorder events and zero RTO events (recovery used
duplicate ACKs). Active reader reservations were 70,015 bytes before shutdown;
shutdown verified zero flows and reservations. The diagnostic completed under
race detection and stopped traffic when the guard fired.

This shows that nearly all the sampled increase was reclaimable in this run,
not evidence of a retained-payload leak. It does not establish natural heap/RSS
recovery or a long-run bound. A defensible next profile should account for the
roughly 49 MiB initialized live heap and allow observation of natural GC cycles;
any revised application-level threshold must be explicit before testing, while
retaining the existing container limits. No threshold was raised in this work.

One diagnostic refactor had a variable-scope compilation error, corrected before
the final diagnostic. Failed/diagnostic manifests remain private and preserved;
none is represented as a successful soak.

## Final regression validation (2026-09-21)

The ordinary full unit/tagged integration suite passed with race detection
(excluding the explicit `soak` tag); peak cgroup memory was 810,287,104 bytes.
Build and module tidy/verification passed with unchanged module files (peak
567,410,688 bytes). Vet including `integration,soak` code passed (peak
370,487,296 bytes). Gofmt and whitespace checks passed.

All ten bounded stages, including the four heap-guard failures and the corrected
compilation failure, recorded zero memory/OOM/PID-limit events and independently
verified removal of owned containers, networks, temporary workspaces and locks.
Pause guards were restored. Environment-specific drivers and raw evidence remain
private/ignored. The opt-in natural-GC soak is still not a repeatably passing gate;
its failures and next memory investigation remain F10e. This commit adds test
infrastructure and evidence, not a production memory fix or completed soak claim.
