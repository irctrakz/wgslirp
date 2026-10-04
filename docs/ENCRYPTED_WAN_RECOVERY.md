# Bounded encrypted WAN recovery

## Acceptance declared before execution — 2026-10-03

`TestEncryptedWANRecovery` uses real wireguard-go devices, ordinary loopback
TCP/UDP sockets and a bounded userspace ciphertext relay. No kernel TUN, netem,
raw sockets or elevated network privileges are used. Production timers and
budgets are unchanged. This is deterministic impairment/recovery evidence,
not a measured Internet distribution, throughput or long-duration soak claim.

Two profiles add fixed **20 ms and 60 ms each way**. Each runs nine exact
256-byte UDP round trips (first excluded from RTT calibration), one 1 KiB TCP
request and three exact TCP replies:

1. **Consecutive loss:** a 1 KiB reply with two consecutive server ciphertext
   data drops. Require exactly two drops and at least two actual RTO events.
2. **Reordering:** a 4 KiB reply whose first large ciphertext is delayed an
   additional 150 ms. Require observed delivery-order inversion and exact
   bounded reassembly at the guest.
3. **Receiver reneging:** a 4 KiB reply with its first large ciphertext dropped.
   The guest advertises SACK permission, SACKs later segments, then discards them
   before advancing its cumulative ACK. Require timeout recovery, retransmission
   of discarded segments, exact final bytes and three total drops per profile.

Calibration measures relay residence time separately in each direction (up to
4,096 samples each). Require at least eight samples, none below the configured
delay and none above delay +400 ms (including deliberate reordering). Eight warm
UDP RTTs must lie between twice the delay and twice the delay +250 ms. Report
actual min/median/max relay time and min/max RTT, not only configured delay.
Loss is targeted at server-to-guest data; these profiles do not claim ACK-loss,
uplink-loss, jitter-distribution, congestion or full-sequence-space coverage.

Each profile allows 45 seconds; the combined test has a 120-second timeout.
Each I/O has a five-second deadline, each reply at most 64 received packets,
guest reassembly at most eight pieces, and relay storage at most 64 datagrams of
2,048 bytes. Application payload per profile totals 14.5 KiB excluding
headers, handshakes and retransmissions. Require zero relay/sample overflow,
heap <=192 MiB, RSS <=384 MiB and <=512 goroutines at samples. These bounds match
the capacity profile, not the older A1 memory criterion. No forced GC is used.
After shutdown require zero TCP/UDP flows, dial/buffer reservations and TCP
output refusals; device/relay cleanup must return goroutines to baseline +4
within five seconds.

One fresh ordinary process and one fresh race process run sequentially through
the shared bounded CI harness: 1 CPU, 2 GiB RAM/no swap, 128 PIDs, 768 MiB work
and 64 MiB temporary tmpfs, read-only root, dropped capabilities and a 600-second
container deadline. Require no cgroup limit events/OOM, zero exit, and explicit
container/tmpfs/toolchain-image removal. Evidence is retained for 14 days.
The private server remains unused. WAN failure blocks capacity and image promotion.

```sh
go test -v -tags=integration,wan -run='^TestEncryptedWANRecovery$' -timeout=120s -count=1 -parallel=1 ./pkg/wireguard
go test -v -race -tags=integration,wan -run='^TestEncryptedWANRecovery$' -timeout=120s -count=1 -parallel=1 ./pkg/wireguard
```

## Results

Run [37171673559](https://github.com/irctrakz/wgslirp/actions/runs/37171673559)
(`e59d7ef`) passed the 20 ms consecutive-loss phase with two RTO events and
reordering with exact payloads, then failed the reneging reply assertion. Race,
capacity and image publication were skipped. Cgroup peak was 342,839,296 bytes,
with zero memory/PID-limit events or OOM kill; container/tmpfs/image removal
was verified.

The timeout loop skipped selectively acknowledged data indefinitely. The fix
invalidates advisory SACK state on timeout and retransmits the oldest outstanding
segment under existing state/queue locks. A focused socket regression covers
reneging both normally and across sequence-number wrap. The encrypted guest now
sends each discarded block's SACK once, avoiding artificial repeated SACK storms;
failure diagnostics include byte counts and recovery state. Payload/resource/time
criteria remain unchanged. Successful execution is pending.

Preserve failures and do not relax criteria to obtain a pass.
The existing soak relay is shared without changing its original impairment policy.
