# Bounded sustained encrypted traffic and ingress loss

## Acceptance declared before execution — 2026-10-04

One persistent TCP connection and one UDP flow traverse two real wireguard-go
devices, the production userspace socket bridges and ordinary loopback sockets.
No kernel TUN, raw sockets, netem, extra privileges or private server are used.
This profile increases byte volume and sustained activity; it is not a saturation,
high-concurrency, Internet throughput or multi-hour soak claim.

Three consecutive phases share the connection and process: **baseline**, **seeded
8% loss**, and **two-packet bursts**. Each completes 128 rounds, each round sending
8 KiB TCP uplink in eight stop-and-wait segments, 32 KiB TCP downlink through the
unchanged 4 KiB advertised guest window, and a 1 KiB UDP echo. Each round is paced
to at least 400 ms; each phase must take 50–90 seconds. Totals: 3 MiB TCP uplink,
12 MiB TCP downlink and 384 KiB UDP each way = **15.75 MiB** application data.

### Loss model and its limits

A test-only writer classifies actual pure TCP ACKs and TCP payload packets at
**decrypted server ingress**, then silently discards selected packets. Every
attempt, including a discarded attempt, crosses actual WireGuard encryption.
The writer preserves the socket's shared reservation interface and synchronous
borrowed-packet ownership. There is no ciphertext-size classifier. This models
loss at the bridge input; earlier WAN tests separately cover ciphertext loss and
delay. The sustained profile adds no artificial latency, downlink loss or UDP loss.

- Baseline drops nothing.
- Seeded loss uses independent xorshift32 streams for data and pure ACKs, seeded
  `0x12345678` and `0x87654321`, dropping when `value % 100 < 8`. This is a
  reproducible synthetic packet-attempt distribution, not a measured network
  distribution or an exact 8% quota. Report observed counts and burst lengths.
- Burst loss drops the first two of each 32 eligible data attempts and each 31
  pure ACK attempts. The unequal periods avoid aliasing ACK loss with the
  32-segment reply pattern. Require observed maximum runs of exactly two drops.
- SYN/FIN/RST, UDP and other protocols are excluded. ACKs piggybacked on data
  follow the data policy. TCP downstream payloads are not deliberately dropped.
- The fixture guest retransmits an uplink segment after 250 ms, with at most four
  attempts. This tests bridge duplicate handling/recovery, not a full guest TCP
  implementation or its congestion controller.
- The guest waits for the final cumulative ACK to reach the bridge before the
  next round. A lost final ACK must be recovered by actual server timeout
  retransmission and another guest ACK, rather than a later data piggyback ACK.

### Pass criteria and containment

Require exact request/reply/UDP bytes in every round, upload attempt accounting,
at least eight data drops, eight pure ACK drops and eight guest retransmissions
in each lossy phase, and a positive server RTO counter delta in each lossy phase.
The baseline must have no drops or guest retries. Report all phase counts and
durations. Require at least two natural GCs across the whole workload, no forced
GC or runtime-policy changes, sampled heap <=192 MiB, RSS <=384 MiB and <=512
workers. These are the declared capacity/WAN ceilings, not a revision of A1.
Sampling is at packet waits and round boundaries, not a continuous RSS maximum.

Replies permit at most eight buffered pieces, 512 wait/packet iterations and
five seconds. Host and UDP I/O deadlines are three seconds; each phase also has
its 90-second ceiling. Go's whole-test timeout is 330 seconds. Cleanup must leave
zero TCP/UDP flows, pending dials, socket reservations and TCP delivery refusals;
joined device cleanup must restore goroutines to baseline +4 within five seconds.

Run one fresh ordinary process and one fresh race process sequentially in the
existing CI harness: 1 CPU, 2 GiB/no swap, 128 PIDs, read-only root, all capabilities
dropped, 768 MiB work tmpfs, 64 MiB temporary tmpfs, bounded logs and a 600-second
container deadline. Require zero memory/PID limit events/OOM and explicit removal
of container/tmpfs/toolchain image. Evidence retention is 14 days. Failure blocks
WAN/capacity/image gates; no acceptance thresholds are relaxed after failures.

```sh
go test -v -tags=integration,sustained -run='^TestEncryptedSustainedLoss$' -timeout=330s -count=1 -parallel=1 ./pkg/wireguard
go test -v -race -tags=integration,sustained -run='^TestEncryptedSustainedLoss$' -timeout=330s -count=1 -parallel=1 ./pkg/wireguard
```

## Results

### Initial trace failure — 2026-10-04

[Run 37221997690](https://github.com/irctrakz/wgslirp/actions/runs/37221997690)
(`f0e7e41`) completed all 384 rounds with exact payloads. Baseline took 51.271 s
with zero loss/retries/RTO. Seeded loss took 57.104 s, recording 89 data drops,
329 ACK drops, 89 guest retries and 19 server RTOs. Burst loss took 55.786 s,
recording 70 data drops, 256 ACK drops and 70 guest retries, but **zero server
RTOs**; the gate correctly rejected insufficient ACK-timeout evidence.

The initial trace dropped the first two of every 32 ACK attempts, which aligned
with exactly 32 ACKs per reply. Later cumulative ACKs covered every loss.
The revised ACK burst period is 31 (data remains 32), exercising different
positions without weakening the positive-RTO criterion. Payload, duration and
resource thresholds are unchanged. This is a fixture distribution correction,
not a production recovery fix. Cgroup peak was 340,750,336 bytes, with zero
memory/PID limit events or OOM; container/tmpfs/image cleanup was verified.
Race and downstream gates were skipped.

### Accepted finite profile — 2026-10-04

[Run 37222442219](https://github.com/irctrakz/wgslirp/actions/runs/37222442219),
source `672a852`, passed both fresh-process variants sequentially. Each checked
384 rounds and exactly 16,515,072 application bytes, including all UDP echoes.
Only the ACK burst period changed after the first failure; acceptance thresholds
and production code are unchanged.

| Mode / phase | Data attempts / drops | ACK attempts / drops | Guest retries | Server RTOs | Duration (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ordinary / baseline | 1,024 / 0 | 4,097 / 0 | 0 | 0 | 51.265 |
| Ordinary / seeded | 1,113 / 89 | 4,102 / 329 | 89 | 19 | 57.211 |
| Ordinary / bursts | 1,094 / 70 | 4,106 / 266 | 70 | 10 | 57.897 |
| Race / baseline | 1,024 / 0 | 4,097 / 0 | 0 | 0 | 51.270 |
| Race / seeded | 1,113 / 89 | 4,099 / 329 | 89 | 17 | 57.175 |
| Race / bursts | 1,094 / 70 | 4,106 / 266 | 70 | 10 | 58.681 |

Both observed longest seeded drop runs of three packets and burst runs of two,
for both data and ACKs. Actual attempt counts can depend on scheduling and
retransmission timing even with the same seeds. The initial rejected trace
demonstrates why observed recovery counters matter in addition to byte equality.

| Resource | Ordinary | Race |
| --- | ---: | ---: |
| Sampled heap peak (bytes) | 93,140,704 | 101,014,960 |
| Sampled RSS peak (bytes) | 70,033,408 | 339,423,232 |
| Natural GCs after initialization | 10 | 37 |
| Socket buffer peak (bytes) | 80,439 | 80,439 |
| Cgroup peak including compilation/tmpfs (bytes) | 338,817,024 | 590,196,736 |
| Whole Go test (s) | 166.436 | 168.250 |

There were no forced collections, memory/PID limit events, OOM kills or race
reports. Final flows, dial/buffer reservations and TCP delivery refusals were
zero, and worker cleanup passed. Both artifacts verify container/tmpfs/toolchain
image removal. Race teardown logged one late guest reset rejected after socket
Stop; injection is asynchronous and this control packet raced shutdown. It did
not affect application delivery or the independently checked cleanup invariants.

These results establish this paced one-pair profile, not saturation throughput,
per-instance memory cost or immediate return to cold RSS. Larger concurrent/
saturation, full-sequence and deployment-specific traffic distributions remain
separate scope decisions.

The same run also passed standard build/vet, module verification, race unit and
integration tests, both fuzz targets, ordinary/race WAN and real TIME-WAIT capacity
gates, and actual-image forwarding/SIGTERM validation. The tested Linux/amd64
image was promoted without rebuilding:

```text
ghcr.io/irctrakz/wgslirp@sha256:8d1031fd3208cd233f3411652d5735963355ecc87e5cc73e644b2731c63b3c65
```

Non-root image shutdown under traffic completed in 153.8 ms. Release cleanup
verified no owned containers, network, builder, cache volume or local image
remained. GHCR versions are retained; the private server was unused. All work
remains on the development branch, with main/master and latest untouched.
