# Development release-image validation

This path builds the development branch event's exact commit once and tests the
image's normal entrypoint. Go checks, image source and runtime fixture use that
same commit. The candidate is published to GHCR, pulled by immutable digest and
tested. Only a successful validation job (including cleanup) permits promotion
of that digest to a unique development tag. Promotion does not rebuild the image.

## Latest validation — 2026-10-05

[Run 37343127478](https://github.com/irctrakz/wgslirp/actions/runs/37343127478)
passed the standard checks and all sequential ordinary/race mixed, sustained,
WAN and capacity gates for `6126e4202de7244624ea31e914a9dcb493300e68`.
See [ENCRYPTED_MIXED.md](ENCRYPTED_MIXED.md) for the new independent-peer evidence
and retained initial fixture failure.

The actual image passed UID 100 startup, encrypted TCP/UDP and SIGTERM under
traffic (70.192637 ms), using the unchanged dropped-capability and resource
constraints. The fixture omits `WG_PEERS`, verifying automatic discovery through
the image's normal startup path. Cleanup verified no owned runtime containers, networks, builder,
cache volume or local image remained. CI promoted the same immutable artifact:

`ghcr.io/irctrakz/wgslirp@sha256:8d5ce2a61a607c624300aabe090b92bf4dea2f903874f2e1194629f311fc181a`

as `dev-6126e4202de7244624ea31e914a9dcb493300e68-37343127478-1`.
This covers linux/amd64; main/master and `latest` were untouched.

The actual-image log regression injected sixteen encrypted IPv4 fragments,
synchronizing each with the error counter to avoid the existing TUN batch early
return. It required exactly sixteen observed failures, one immediate diagnostic
and a shutdown summary of fifteen repeats; subsequent TCP/UDP traffic succeeded.
Both capacity modes also exercised the periodic summary: two expected flow-limit
failures produced one immediate line and a thirty-second summary of one repeat.
Unexpected errors retain immediate logging, and packet errors/counters are not
suppressed. The failed first fixture and batch follow-up remain recorded in
[HARDENING_REVIEW.md](HARDENING_REVIEW.md).

## Execution environment

Use an ephemeral GitHub-hosted Linux runner with Docker and cgroup v2. The private
SSH test server remains outside this image-build path: its existing cached-image
harness does not authorize host image builds, pulls or Docker socket mounts.

Push to `codex/architecture-hardening` to run `.github/workflows/docker.yml`.
The development-only `release-image-test` job depends on the ordinary Go checks
and sequential ordinary/race independent-peer mixed, sustained-loss, WAN and capacity gates;
`promote-development` depends on successful image validation. Publication is
restricted to `irctrakz/wgslirp` and that exact branch on push/manual events;
pull requests cannot enter these jobs. No default-branch change is required for
the push trigger. Manual dispatch also selects this branch, but GitHub requires
the workflow to exist on the default branch before dispatch is available. There
is no longer a `release_ref` input: tests and image must cover the same revision.

The validation job has a 20-minute deadline and promotion five minutes. This path
does not run the master-only publisher, move source release tags or publish
`latest`. It validates **linux/amd64 only**. Do not advertise its development tag
as an arm64 or multi-platform release; each additional platform needs validation.

Both publishing jobs use job-scoped `packages: write` and the automatic
`GITHUB_TOKEN`. For an existing GHCR package, grant `irctrakz/wgslirp` Write access
under Package settings → Manage Actions access if it does not already inherit
access. No personal access token is required.

The dedicated BuildKit container uses 1 CPU, 2 GiB memory/no swap and, after
bootstrap, a 128-PID limit. Limits are inspected before the bounded ten-minute
build. This is a Docker build on a disposable runner, not an extension of the
private server's resource policy. Base image tags still float as specified in the
release Dockerfile; metadata captures the actual build. Input pinning and artifact
rollback remain separate release work. The existing master publisher is unchanged
and still requires separate migration to tested-artifact promotion.

## Runtime checks

`TestReleaseImage` (tags `integration,releaseimage,linux`) starts the exact built
image with its normal non-root entrypoint and default IPv6 policy. It uses:

- A dedicated internal Docker network with no published ports.
- Read-only root filesystem, all capabilities dropped, no-new-privileges.
- 1 CPU, 256 MiB memory with no swap, 128 PIDs, bounded 16 MiB tmpfs and logs.
- Ephemeral WireGuard keys in a private temporary env file, excluded from evidence.
- A real wireguard-go guest using an in-memory TUN and ordinary host TCP/UDP peers.

The fixture verifies Docker's effective configuration, nonzero UID, PID 1's empty
effective capability set and no-new-privileges flag, and actual cgroup CPU/memory/
swap/PID limits. It verifies at least nine exact 1 KiB TCP/UDP echo rounds through
encryption, the release executable and real host sockets. It samples memory/PID
events after eight rounds and requires zero events. Traffic continues while Docker
sends SIGTERM; the process must exit zero within ten seconds without OOM kill.

The traffic worker is joined on cleanup. Every Docker command has a 15-second
deadline; Go has a 120-second deadline and an outer 180-second timeout. The always
cleanup step removes resources matching the job's dedicated identity, its builder,
cache volume and tested image, and checks absence before recording success.
GitHub-hosted runner teardown supplies the final isolation boundary after a canceled
job; this is not a guarantee of user callbacks or arbitrary host filesystems.

## Evidence and image retrieval

Candidate: `ghcr.io/irctrakz/wgslirp:candidate-<run-id>-<attempt>`.
Validated tag: `ghcr.io/irctrakz/wgslirp:dev-<full-commit>-<run-id>-<attempt>`.
Unique run/attempt tags avoid competing runs moving a shared development alias.
Registry tags are not inherently immutable: deployments should use the recorded
`ghcr.io/irctrakz/wgslirp@sha256:…` reference.

The workflow checks that the runtime report passed, names the expected digest
reference and source commit, and records the pulled image's local content ID as
the actual container image. A missing/skipped fixture report fails the job.
Promotion copies the existing manifest with `imagetools create
--prefer-index=false`, then checks that the development tag resolves to the
tested digest. It has no checkout or build step.

Seven-day Actions artifacts `release-image-<run-id>-<attempt>` and
`promotion-<run-id>-<attempt>` contain sanitized runtime inspection, test logs,
source/fixture commits, local image content ID, build metadata, registry digest,
cleanup status and promotion identity. They exclude configuration/private keys.
The successful promotion also writes the tag and digest to the Actions summary.
Retrieve the tested image with `docker pull` using `image-reference.txt`.

Candidate images remain in GHCR even when validation fails; a candidate tag is
not evidence of acceptance. Runner cleanup removes local resources only, and
seven-day Actions artifact expiry does not delete registry images. Registry
retention/deletion remains an explicit maintenance decision; this workflow does
not request package-administration privileges or delete published versions.

## Sustained-loss release verification — 2026-10-04

[Run 37222442219](https://github.com/irctrakz/wgslirp/actions/runs/37222442219)
passed for `672a852986c54a13c8bfbdbcfa2540df9370301e`: standard regression and
fuzz checks, both sustained-loss modes, both WAN modes, both capacity modes and
actual-image validation. The ordinary/race sustained profiles each checked
15.75 MiB with seeded and burst ACK/uplink loss; see
[ENCRYPTED_SUSTAINED.md](ENCRYPTED_SUSTAINED.md).

The non-root UID-100 image passed encrypted TCP/UDP forwarding and SIGTERM under
traffic in 153.8 ms, under the unchanged dropped-capability, read-only,
1 CPU/256 MiB/no-swap/128-PID profile. The tested and promoted digest is:

```text
ghcr.io/irctrakz/wgslirp@sha256:8d1031fd3208cd233f3411652d5735963355ecc87e5cc73e644b2731c63b3c65
```

Tag: `dev-672a852986c54a13c8bfbdbcfa2540df9370301e-37222442219-1`.
Cleanup verified no owned container, network, builder, cache volume or local
image remained. GHCR versions are retained. Main/master, latest and the private
server were untouched; validation covers Linux/amd64 only.

## WAN recovery release verification — 2026-10-04

[Run 37172091744](https://github.com/irctrakz/wgslirp/actions/runs/37172091744)
passed for `36da09c2c00c9b58030c2c8d9f1f20a5c99ad8cb`: standard regressions,
ordinary/race calibrated encrypted WAN recovery, ordinary/race capacity and
actual-image validation. The WAN fixture exposed a receiver-reneging recovery
bug; timeout retransmission now invalidates advisory SACK state and retries the
oldest cumulatively unacknowledged data. Detailed bounds and failures are in
[ENCRYPTED_WAN_RECOVERY.md](ENCRYPTED_WAN_RECOVERY.md).

The actual Linux/amd64 image passed non-root startup (UID 100), encrypted TCP/UDP
forwarding and SIGTERM under traffic in 81.4 ms, using the existing dropped-capability,
read-only, 1 CPU/256 MiB/no-swap/128-PID profile. Promotion preserved this digest:

```text
ghcr.io/irctrakz/wgslirp@sha256:bc326f2fea2bc869dc080c3f5408d0a3511a0c482a2e89f400879c336c664ef6
```

Development tag:
`dev-36da09c2c00c9b58030c2c8d9f1f20a5c99ad8cb-37172091744-1`.
Cleanup verified no owned runtime container, network, builder, cache volume or
image remained locally. Published GHCR versions are retained. Main/master and
stable/latest tags were untouched; the private server was unused.

## Ownership/deployment validation — 2026-10-03

[Run 37147533942](https://github.com/irctrakz/wgslirp/actions/runs/37147533942)
passed for `415f520c9243e22832807fe08aa7666b897ec04b`: module/build/vet,
unit/integration race tests, fuzzing and actual-image tests. Compose validation
accepted the bounded configuration and rejected a missing image selection.
This is configuration validation, not an external host deployment test.

Tested and promoted image:

```text
ghcr.io/irctrakz/wgslirp@sha256:ee771013ad6c5384a1203aa00451f929c6cafb25bf40ddda8b4903fd7476166c
```

The runtime report records non-root UID 100, all capabilities dropped, read-only
root, 1 CPU/256 MiB/no swap/128 PIDs, encrypted TCP/UDP forwarding and clean
SIGTERM exit in 85 ms. Sampled peak after eight rounds was 30,941,184 bytes;
memory and PID event counters were zero. Cleanup verified no owned runner
resources remained. Promotion retained the tested digest. Master/main and
stable/latest tags were untouched; the image is Linux/amd64 only.

Earlier attempts correctly blocked image publication: an obsolete command import
failed build; two pre-existing budget assertions observed delayed ACK packets
mid-delivery. The import was removed and assertions now synchronize with the
ACK worker. The three affected fixture tests passed 100 local repetitions before
the successful full Linux run. No budget assertion was relaxed.

## Previous validation — 2026-10-02

Development publishing/promotion passed on 2026-10-02. The first successful run
was [37045066315](https://github.com/irctrakz/wgslirp/actions/runs/37045066315)
for `58318d9`. After TCP stall/establishment cleanup,
[37050502529](https://github.com/irctrakz/wgslirp/actions/runs/37050502529)
validated `fb18c23e31d9798a71c4c6ffe5c287b44269a392` and promoted:

```text
ghcr.io/irctrakz/wgslirp@sha256:afbdb1bc56392c0c80be8125c1568170ce613f8888a900d825836fe4b3354ae2
```

That runtime report records UID 100, dropped capabilities, read-only root,
1 CPU, 256 MiB/no swap, 128 PIDs, encrypted TCP/UDP forwarding, zero memory/PID
limit events, and SIGTERM exit zero in 76 ms. Sampled cgroup memory peak after
eight rounds was 31,682,560 bytes; this is not a long-duration memory benchmark.
Cleanup evidence confirms no owned runtime container/network/builder/cache
volume/local image remained. The master publisher was skipped. These images
validate linux/amd64 only; source release tags were not changed.

Preparation checks passed on Linux Go 1.23.12: the full ordinary unit/integration
suite with race detection, compilation of the new release-image fixture with
race instrumentation (no image test execution), and vet with `releaseimage` tags.
The workflow YAML parsed successfully and all embedded shell blocks passed
`bash -n`. All three bounded stages recorded zero memory/OOM/PID-limit events and
independent cleanup; the largest container peak was 833,200,128 bytes. No Docker
image was built/pulled on the private server. The later GitHub runs above supply actual image execution; main/master and the
published source tag remain unchanged.
Invalid-config image startup coverage, pinned build inputs and rollback evidence
remain outstanding; the forwarding/SIGTERM fixture does not close those items.

The 2026-10-02 workflow changes passed Actionlint 1.7.7, YAML parsing, `bash -n`
for all 11 workflow shell blocks and compilation of embedded Python. Disposable
local controls exercised the actual promotion shell with mocked registry calls:
success passed; malformed digest, digest mismatch and failed manifest creation
failed. Runtime-evidence checks accepted valid evidence and rejected failed,
missing, wrong-image, wrong-source and wrong-container reports. These checks
performed no registry writes or Docker execution and do not replace a CI run.
