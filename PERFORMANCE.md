# Bounded transport performance comparison

## Scope and budgets selected before measurement

Compare pre-extraction `5d6f291` with the current architectural branch using the
same `TestTransportPerformance` fixture, Go 1.23.12, one CPU and fresh processes.
Five samples per protocol each use eight loopback clients, 16 warm-up exchanges
per client and 256 measured 1,024-byte exchanges per client. TCP handshakes are
measured separately. Every echo is checked byte-for-byte. The fixture uses real
host sockets and the production socket bridges plus the bounded library packet
processor. It does not include WireGuard encryption or the application executable.

Report the median across five runs for each metric. Candidate limits relative
to baseline, fixed before inspecting performance results:

- Payload throughput: no more than 25% lower (one direction, decimal MB/s).
- Round-trip p50/p95 and TCP handshake p95 latency: no more than 35% higher.
- Allocation count and allocated bytes per measured exchange: no more than 20% higher.
- Sampled heap and RSS: no more than 25% higher plus 4 MiB runtime allowance.
- Reservation peak must stay within configured limits; final reservations must be zero.

Memory is sampled after measured traffic without forced GC; RSS is not a
continuous process peak. Cgroup peaks separately include compilation and are
containment evidence, not application memory benchmarks. Allocation deltas cover
all process activity during the measured phase, including fixture overhead.
Handshake p95 is the largest of only eight observations per sample; these are
small-workload regression signals, not population tail-latency estimates.

Run each revision sequentially in its own disposable source copy/container with
1 CPU, 2 GiB RAM/no swap, 128 PIDs, bounded tmpfs, a 120-second Go test timeout and
600-second outer deadline. Review cleanup/resource evidence after every stage.
Do not change limits or budgets to accommodate failures.

```sh
go test -v -tags=integration,performance -run='^TestTransportPerformance$' -timeout=120s -count=1 -parallel=1 ./pkg/socket
```

Ordinary integration runs exclude the explicit `performance` tag. Race-enabled
runs validate the fixture and protocol correctness; compare timing only without
race instrumentation. Environment-specific SSH/snapshot drivers stay private.

## Remaining deployment evidence

This finite loopback profile does not establish saturated link throughput,
WAN loss/latency/reordering, long-idle expiry, full sequence-cycle transfers,
encrypted high-churn sizing or sustained soak behavior. Those remain F10e;
release-image and external review gates remain F10d. No upstream action is needed
or performed for this comparison.

## Results (2026-09-18)

Baseline `5d6f291` versus candidate production code `fb99a4c`, with the identical
new fixture copied into the temporary baseline tree. Fixture SHA-256:
`e745829399206febe77ed221ed785711b033fccd2df2cb0cd53ab0cc74ea71e6`.
All preselected comparisons passed. Values below are medians of five samples;
percent changes describe this run and do not imply statistically proven speedups.

| Protocol | Metric | Baseline | Candidate | Change |
| --- | --- | ---: | ---: | ---: |
| TCP | Payload MB/s | 26.890 | 27.870 | +3.64% |
| TCP | RTT p50 (us) | 271.922 | 264.678 | -2.66% |
| TCP | RTT p95 (us) | 576.866 | 529.495 | -8.21% |
| TCP | Handshake p95 (us) | 163.692 | 213.019 | +30.13% |
| TCP | Allocations/exchange | 53.039 | 53.038 | -0.00% |
| TCP | Allocated bytes/exchange | 38882.398 | 38882.332 | -0.00% |
| TCP | Sampled heap (MiB) | 2.347 | 2.792 | +18.98% |
| TCP | Sampled RSS (MiB) | 11.566 | 11.508 | -0.51% |
| TCP | Reservation peak (bytes) | 269216.000 | 269216.000 | +0.00% |
| UDP | Payload MB/s | 51.690 | 54.048 | +4.56% |
| UDP | RTT p50 (us) | 154.996 | 154.250 | -0.48% |
| UDP | RTT p95 (us) | 257.937 | 242.411 | -6.02% |
| UDP | Allocations/exchange | 30.016 | 30.016 | +0.00% |
| UDP | Allocated bytes/exchange | 4140.828 | 4140.828 | +0.00% |
| UDP | Sampled heap (MiB) | 1.383 | 2.168 | +56.69% |
| UDP | Sampled RSS (MiB) | 13.332 | 13.316 | -0.12% |
| UDP | Reservation peak (bytes) | 526640.000 | 526640.000 | +0.00% |

TCP handshake p95 increased 30.13%, within the 35% budget but close enough to
retain as a signal for broader dial-load validation. Sampled UDP heap increased
56.69% (about 0.78 MiB); it passed the preselected 25% plus 4 MiB allowance, while
RSS and allocation rate stayed essentially unchanged. Neither value is hidden by
the overall pass. No forced collection or threshold adjustment was used.
Every sample verified payload correctness and zero final reservations.

The normal integration/race suite also ran this fixture with the explicit
performance tag and passed. Baseline/candidate measurement container peaks were
297,062,400 / 299,761,664 bytes; the full integration/race peak was 778,158,080.
Final build/module tidy/verification passed with unchanged module files (peak
437,202,944 bytes). Vet including integration/performance tags passed (peak
368,021,504 bytes); ACK benchmark median was 662.5 ns/op, 34 B/op, 2 allocs/op.
All five stages recorded zero memory/OOM/PID-limit events, independently verified
zero owned container/network/workspace/lock residue, and restored pause guards.
Gofmt and whitespace checks passed. The local temporary baseline source was also
removed; private harness/evidence files remain excluded from the commit.

This closes the bounded loopback performance comparison for PR 4.3. F10 deployment
and extended workload evidence remain open as described above.
