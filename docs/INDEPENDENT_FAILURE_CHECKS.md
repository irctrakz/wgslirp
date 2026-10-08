# Independent failure checks

The **Independent failure checks** GitHub Actions workflow is independently triggered and does
not gate builds, publishing or tested-image promotion. Select this development
branch in Actions, then choose `all` or one check. Each control has separate
ordinary and race jobs; failures remain visible without cancelling the other
controls. No private server is used and no image is published.
It also runs when the workflow, its supervisor/oracle, or the dedicated fragment
recovery test changes on this branch. Routine production changes do not trigger
these extra jobs automatically.

## Initial controls

| Check | Deliberate defect | Independent observation required |
| --- | --- | --- |
| `retransmission` | Suppress the RTO retry packet while retaining timer processing | Captured packets must show the original sequence retransmitted; absence fails |
| `reservation-release` | Lose the release callback's budget decrement | The shared budget must return from 296 bytes to zero after concurrent repeated releases |
| `fragment-recovery` | Retain per-source slots after expired assemblies are released | A previously saturated source must admit a full new set of assemblies, even when aggregate accounting is zero |
| `dial-cancellation` | Leave a successful late dial socket open after cancellation | The independent host socket must observe EOF, not a read deadline |

Each job copies tracked source into an owned temporary directory. The original
checkout is never mutated. It requires the selected test and package to pass
unchanged, applies exactly one reviewed mutation anchor, verifies the mutant
compiles, and requires the selected test to fail with its specific diagnostic.
Missing tests, skips, panics, race reports, compilation errors, unexpected exit
codes and supervisor timeouts are failures of the control, not successful
detection. A changed/ambiguous anchor fails closed and requires review.

`tools/ci/test_failure_checks.py` separately checks this acceptance oracle.
Artifacts retain the source commit, original/mutated file hashes, mutation,
baseline/compile/mutant JSON test output, result, container settings, resource
events and cleanup evidence for 14 days. Logs from the intentionally failing
mutant are expected; only `result.json` with `passed: true` proves acceptance.

Each fresh test container runs non-root with all capabilities dropped, a
read-only root/source, no new privileges, one CPU, 2 GiB RAM with no swap,
128 PIDs, bounded tmpfs/logs and an independent 600-second deadline. The
supervisor also bounds each command and the workflow bounds every job.
Resource-limit events fail the job. Cleanup removes the owned container,
source copies, tmpfs and toolchain image, including on failure. At most two
jobs run concurrently on separate disposable GitHub runners.

## Scope and follow-ups

These controls establish that selected regression tests detect selected defects.
They do not establish complete mutation coverage, interoperability, endurance
or production performance. No runtime forwarding code or release gate changes.

- [ ] Add independent path-failure checks for prolonged outage/recovery,
  variable delay/loss, slow readers and MTU black holes.
- [ ] Expand real client-stack interoperability beyond the current independent
  userspace TCP stack and scripted protocol fixtures.
- [ ] Add an opt-in bounded endurance workload against the actual release image,
  with retained resource/recovery evidence and the same cleanup requirements.
- [ ] Review publishing-path acceptance separately: development promotion has
  stronger gates than PR builds and `master` publishing. These optional controls
  deliberately remain outside those release dependencies.

Run controls after changes to the relevant ownership/recovery paths or when
auditing test sensitivity. They can be selected individually without running
the full release pipeline.
