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

Acceptance remains pending. Larger concurrent/saturation, full-sequence and
deployment-specific traffic distributions remain separate scope decisions.
