# Sustained encrypted pooling comparison

## Outcome

Across twelve pairs on two independent CI runners, median paired throughput
improved **0.78%**, short-request p95 improved **1.53%**, and short-request p99
worsened **0.38%**. Throughput improved in eight pairs and regressed in four.
These are observations, not a statistical confidence guarantee.

Under the owner's performance-first priorities, marginal repeatable gains can
justify higher memory use. Memory is not a reason to reject pooling here.
The evidence supports throughput-oriented opt-in trials, but does not establish
a consistent throughput-and-tail-latency advantage for a general default.
Default enablement remains a separate policy decision requiring actual
release-image acceptance; this comparison leaves the default unchanged.

## Reproduction and evidence

Source: `498b5365ac54310f9ffd93190cd9767bfb00291f`, Go 1.23.12 linux/amd64,
toolchain image digest `sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db`.
Dispatch the Docker workflow on `codex/architecture-hardening` with
`pooling-study=true` and `pooling-profile=sustained`; this skips image publishing.

- [Initial run 37693103205](https://github.com/irctrakz/wgslirp/actions/runs/37693103205)
  passed on its first attempt.
- [Confirmation run 37694066819](https://github.com/irctrakz/wgslirp/actions/runs/37694066819)
  passed on its first attempt with identical source/toolchain and bounds.
  It checked uncertainty in the performance result, rather than retrying a failed
  correctness test. Both runs are retained without excluding adverse pairs.
- [All ordinary samples](POOLING_SUSTAINED_SAMPLES.csv) preserve 24 process
  measurements, run IDs, counts and adverse results.
- [Selected CPU profile measurements](POOLING_SUSTAINED_CPU_SAMPLES.csv) preserve
  flat/cumulative percentages beyond the CI artifacts' 14-day retention. Artifacts
  contain full logs, profiles/top reports, inspected limits and cleanup records.

The [predeclared protocol](POOLING_ACCEPTANCE.md#sustained-comparison-protocol-declared-before-its-first-run)
uses six counterbalanced off/on pairs per runner. Each fresh process verifies
512 MiB upload plus 512 MiB echoed download across two streams while four short
request workers and one UDP worker continue until bulk completion. Generation
and verification use fixed 64 KiB blocks. Race sustained payloads are smaller
and excluded from performance comparisons.

## Performance

Off/on columns are sample medians. Changes are medians of within-run paired
percentage changes, so their values can differ from ratios of the displayed
medians. Positive latency/CPU changes mean worse values; positive throughput
means better. Comparisons remain paired by runner before combining the runs.

| Metric | Off median | On median | Paired change |
| --- | ---: | ---: | ---: |
| Verified bulk throughput per direction | 41.043 MiB/s | 41.536 MiB/s | +0.78% |
| Bulk completion time | 12.476 s | 12.327 s | -0.77% |
| Short completion p50 | 11.564 ms | 11.411 ms | -1.12% |
| Short completion p95 | 20.301 ms | 20.011 ms | -1.53% |
| Short completion p99 | 26.081 ms | 25.442 ms | +0.38% |
| UDP round-trip p95 | 10.969 ms | 10.862 ms | -1.50% |
| UDP round-trip p99 | 14.551 ms | 14.590 ms | -2.09% |
| Process CPU | 12.466 s | 12.308 s | -0.69% |
| Allocated bytes | 4.90 GiB | 4.36 GiB | -11.09% |
| Allocated objects | 14,984,435 | 14,564,576 | -2.81% |
| GC cycles | 58 | 52 | -10.35% |
| Sampled peak heap | 213.6 MiB | 209.3 MiB | -1.33% |
| Sampled peak RSS | 209.2 MiB | 204.3 MiB | -1.85% |

Allocated-byte totals measure cumulative churn, not simultaneously resident
memory. Allocation/GC improvements support the analysis but do not determine
success. Both modes used equal finite budgets.

### Reproducibility

| Run | Throughput | Short p95 | Short p99 | UDP p95 |
| --- | ---: | ---: | ---: | ---: |
| Initial | +2.13% | -5.74% | -4.66% | -6.71% |
| Confirmation | +0.23% | +0.52% | +2.42% | +2.57% |

Initial throughput improved in five of six pairs; confirmation improved in three
of six. The initial sixth pair regressed 7.40% in throughput, 14.59% in short p95
and 30.39% in short p99. Across both runs throughput changes ranged -7.40% to
+4.60%. The confirmation did not reproduce the initial tail-latency benefit;
there is no basis to discard the adverse pair as irrelevant noise.

Each ordinary process completed 1,259–1,399 short requests and 1,037–1,130 UDP
exchanges. Clients are closed-loop with pauses: counts vary with duration and
latency. All met the declared minimum counts/overlap checks. This describes the
specified concurrency/mix, rather than a fixed offered request rate or maximum
requests-per-second test.

### CPU attribution

Whole-process CPU includes the router, independent guest, echo endpoints and
instrumentation. Median profile percentages across twelve profiles per mode:

| Function | Off | On | Measure |
| --- | ---: | ---: | --- |
| `internal/runtime/syscall.Syscall6` | 39.28% | 39.04% | Flat, ordinary socket operations across endpoints |
| `runtime.mallocgc` | 5.14% | 4.93% | Cumulative allocation path |
| `socket.buildIPv4TCPWindow` | 1.62% | 1.62% | Cumulative router encoding path |
| `SocketInterface.WritePacket` | 21.66% | 21.63% | Cumulative router guest-packet processing path |

Nested cumulative percentages overlap and must not be added. Shared runtime,
WireGuard crypto and socket costs cannot be wholly attributed to the router.
Profiles do not establish a single cause for the small throughput change.
These are local encrypted fixture results, not router-only or WAN/loss throughput
claims. Earlier WAN acceptance remains a separate profile.

## Correctness, resources and cleanup

Both runs passed build/vet (including tagged fixtures), unit/race and
integration/race checks. Combined evidence includes 24 ordinary sustained
processes, four race sustained processes, eight legacy mixed acceptance
processes, four streaming-verifier processes and four race queue-capacity controls.
The verifier rejected corrupted, truncated and trailing payloads. Every sustained
process delivered exact expected bytes, had no admission refusals or empty
host connections, returned reservations and joined workers.

Each run used one CPU, 2 GiB RAM with no additional swap, 128 PIDs, non-root user,
dropped capabilities, read-only root, bounded tmpfs/logs, Go memory limit 512 MiB
and a 900-second container deadline. Socket limits remained unchanged. The
container bound includes compilation/cache/tmpfs; it is not a 256 MiB actual-image
acceptance result.

| Evidence | Initial | Confirmation |
| --- | ---: | ---: |
| Container memory peak including compilation/tmpfs | 1,082,945,536 B | 1,073,717,248 B |
| Container runtime | 355 s | 362 s |
| Exit code | 0 | 0 |
| OOMKilled | false | false |
| Memory/PID limit events | all zero | all zero |

Both cleanup records verified removal of owned containers/tmpfs and toolchain
images. No owned network or persistent volume was created. The private SSH server
was unused. No production routing code, pooling default, resource limit or image
artifact changed; main was untouched.

## Remaining decisions

- [ ] If selecting default-on, validate that separate candidate's actual release
  image under the deployment/ownership/shutdown gates before promotion.
- [x] Compare a separate policy excluding tiny ACK/control packets from pooling.
  [Selective results](SELECTIVE_PACKET_POOLING.md) retain all six three-policy
  groups: correctness/resource/cleanup gates passed, with faster isolated tiny
  storage but no sustained throughput advantage over full pooling.
