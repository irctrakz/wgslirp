# Release validation and remaining gates

F10 remains open. Local evidence does not establish repository enforcement,
independent approval or the behavior of a published image. No upstream push,
workflow dispatch, publication or repository-setting change was performed.

## Completed bounded coverage

- `pkg/wireguard/encrypted_integration_test.go` creates two real wireguard-go
  devices with ephemeral keys and loopback UDP transport. Guest plaintext crosses
  encryption/decryption, the production WGTun, socket bridges and reply processor
  in both directions. Real host TCP and UDP peers verify exact payloads. The test
  uses in-memory TUNs and ordinary sockets, with IPv6 sysctl changes disabled.
- `pkg/socket/tcp_churn_integration_test.go` completes 128 short host-first TCP
  connections in two default-capacity batches, verifies TIME-WAIT refusal and
  expiry recovery, and checks released payload storage. Expiry uses an injected
  time value; this does not represent a wall-clock soak. Default sizing and its
  explicit churn constraint are in [RESOURCE_BUDGETS.md](RESOURCE_BUDGETS.md).
- `pkg/socket/tcp_sack_wrap_test.go` exercises segmentation, loss, SACK and ACK
  processing near sequence wrap. It reproduced a real recovery bug before the
  fix. Sequence boundaries are seeded, avoiding multi-gigabyte test traffic.
  [PACKET_VALIDATION.md](PACKET_VALIDATION.md) records the supported scope.
- `go mod tidy` and `go mod verify` ran inside the disposable bounded build
  container. Checksums of both module files were unchanged after tidy.
- Workflow job deadlines are now explicit: 15 minutes for Go tests and 20 minutes
  for image build/publication jobs. Fuzzing also has a 120-second test deadline.
  These are repository configuration changes; they have not executed on GitHub.

## External verification still required

| Gate | Evidence required to close | Current status |
| --- | --- | --- |
| Branch enforcement | Actual default-branch protection/rulesets: required checks, independent approving review, stale-approval handling and bypass permissions | Read-only GitHub protection request returned HTTP 401 on 2026-09-18. Settings are **unknown**, not assumed enabled or absent. No authenticated GitHub connector/CLI was available. |
| Independent review | Another reviewer assesses this branch, especially ownership, TCP protocol behavior and containment changes; record review URL and reviewed commit | Pending. Author self-review and automated tests do not satisfy this gate. |
| Workflow execution | Successful Go and image-build runs for the exact reviewed candidate SHA, with links and logs; failed checks must block merge | Pending upstream authorization. Local runs do not execute GitHub workflow semantics. |
| Release image | Build the actual Dockerfile, record digest/toolchain, run it as non-root with all capabilities dropped, readonly root, no-new-privileges and bounded CPU/memory/PIDs; verify startup, encrypted forwarding and SIGTERM shutdown | Not run. The approved remote harness uses a cached test image and does not permit host image builds, pulls or Docker socket access. The in-process encrypted fixture is not a release-image check. |
| Publication and rollback | Publish only the tested/reviewed image, verify commit-addressed digest and non-mutating rollback selection | Pending explicit upstream authorization. Current workflow builds for PRs and publishes only on master; its publish job currently rebuilds the image. Candidate/runtime equivalence still needs evidence or a reviewed promotion change. |

Read both branch protection and repository rulesets when credentials are available;
one endpoint alone cannot establish effective enforcement. Required-check names
must match actual workflow check runs. Do not dispatch `docker.yml` on master as
a read-only validation: that path can publish to GHCR.

## Remaining workload work

- Bounded long-lived transfers spanning a full sequence cycle, SACK loss/reorder
  workloads with latency, and receiver-reneging behavior. Seeded wrap fixtures
  cover arithmetic and ownership, not a complete TCP interoperability matrix.
- Wall-clock long-idle/close expiry and finite-duration soak with stable workload,
  explicit abort thresholds and resource/cleanup evidence.
- Larger deployment profiles and high-churn cap sizing under mixed encrypted
  traffic. The default-cap fixture demonstrates refusal/recovery, not optimal
  throughput or suitability for a busy proxy.
- Startup/configuration/signal behavior of the actual application executable in
  its release image, beyond the production components exercised in process.

Each workload must retain finite duration, traffic and concurrency bounds. The
previous host OOM is not permission to run overnight tests or relax containment.
Environment-specific launchers and raw evidence stay private and ignored.

## Validation record

See F10 in [ARCHITECTURE_PLAN.md](ARCHITECTURE_PLAN.md) for the completed stage
results and resource/cleanup evidence. Do not mark F10 complete until the external
and workload gates above have recorded results or an explicit scope decision.

## Bounded refactoring performance evidence

[PERFORMANCE.md](PERFORMANCE.md) records the pre-extraction/current loopback
comparison and its preselected budgets. It passed throughput, latency, allocation
and sampled-memory checks for eight clients per protocol. This advances PR 4.3;
it does not replace encrypted/high-churn deployment sizing, WAN or soak evidence
listed above, and does not close F10.

## Initial encrypted WAN/soak investigation

[ENCRYPTED_WORKLOADS.md](ENCRYPTED_WORKLOADS.md) describes the explicit opt-in
30-second TCP/UDP fixture with userspace ciphertext delay, selective loss and
reordering. It has produced both guard failures and a finite successful diagnostic
completion; memory acceptance is unresolved. The separately tagged diagnostic may
force one collection after traffic stops to measure live retention. It does not
satisfy natural-GC soak acceptance. Ordinary CI excludes the `soak` tag, and F10e
remains open, including the concrete encrypted-memory follow-up in the plan.

**A1 update (2026-09-22):** F10e.2's finite low-rate natural-GC baseline is now
accepted under a separately declared criterion, with three fresh ordinary and
three fresh race runs. The original 64 MiB guard and failures were preserved;
the new profile observes natural collection, sampled heap/RSS limits, continued
payload recovery and complete teardown without forced GC. Details and exact
limits are in [ENCRYPTED_WORKLOADS.md](ENCRYPTED_WORKLOADS.md). This closes that
memory-baseline investigation, not F10e's larger/higher-rate/long-duration work
or F10d's release-image gate. No production runtime or server limits changed.
