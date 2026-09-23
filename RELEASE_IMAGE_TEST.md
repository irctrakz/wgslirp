# Development release-image validation

This path builds an existing source tag's actual Dockerfile and tests the image's
normal entrypoint. The orchestration fixture comes from the development branch;
the image source is checked out separately, so adding tests does not move a release
tag. Source commit, fixture commit, build metadata and image ID are recorded.

## Execution environment

Use an ephemeral GitHub-hosted Linux runner with Docker and cgroup v2. The private
SSH test server remains outside this image-build path: its existing cached-image
harness does not authorize host image builds, pulls or Docker socket mounts.

Dispatch `.github/workflows/docker.yml` on `codex/architecture-hardening` with
`release_ref=v0.1.0-dev.20260922`. The development-only `release-image-test` job
depends on the ordinary Go checks. Its job deadline is 20 minutes. It never runs
the master-only publication job, moves the release tag or publishes a latest image.

The dedicated BuildKit container uses 1 CPU, 2 GiB memory/no swap and, after
bootstrap, a 128-PID limit. Limits are inspected before the bounded ten-minute
build. This is a Docker build on a disposable runner, not an extension of the
private server's resource policy. Base image tags still float as specified in the
release Dockerfile; metadata captures the actual build. Input pinning and artifact
promotion/rollback remain separate release work.

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

After runtime success, the workflow exports the **same tested image** as
`release-image.tar.gz` with a SHA-256 checksum. The seven-day Actions artifact also
contains sanitized runtime inspection, test logs, source/fixture commits, local
image content ID, build metadata and cleanup status. It contains no configuration
environment/private keys. No GHCR image or release asset is automatically published.

Load the archive using `docker load` in a suitable test environment. Verify its
archive checksum first; the image ID in `image-id.txt` identifies the loaded
content. This is a local image ID, not a published registry manifest digest.

## Status

Implementation is prepared; actual image validation remains pending until the
workflow successfully runs and its evidence is inspected. The existing unit/race
and component-level encrypted tests do not substitute for this runtime gate.

Preparation checks passed on Linux Go 1.23.12: the full ordinary unit/integration
suite with race detection, compilation of the new release-image fixture with
race instrumentation (no image test execution), and vet with `releaseimage` tags.
The workflow YAML parsed successfully and all embedded shell blocks passed
`bash -n`. All three bounded stages recorded zero memory/OOM/PID-limit events and
independent cleanup; the largest container peak was 833,200,128 bytes. No Docker
image was built/pulled on the private server. Runner selection/first dispatch
remain pending, and main/master and the published source tag remain unchanged.
