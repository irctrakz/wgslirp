# Bounded non-root deployment

The executable forwards IPv4 TCP/UDP through ordinary userspace sockets and an
in-memory WireGuard TUN. It needs no kernel TUN device, routing sysctl changes,
root identity or added capabilities. Docker administration is a host deployment
operation; the application receives no Docker socket or host network access.

## Select a validated image

Use Linux/amd64 and a digest from a successful development CI run. Candidate
publication is not acceptance. The pinned image below passed
[actual-image and encrypted workload acceptance](https://github.com/irctrakz/wgslirp/actions/runs/37842268168)
and was promoted without rebuilding. It supports automatic peer discovery,
bounded pooling, default fragment reassembly and default guest echo.
Older digest pins retain their own defaults and architecture coverage.

```sh
export WGSLIRP_IMAGE=ghcr.io/irctrakz/wgslirp@sha256:197701ffd0d6453dd120838f680447a54fd166337f90808d49adb8a0e6bc02e1
```

## Tested-image publishing

After a `master` push, the Docker workflow builds the release Dockerfile once
as a Linux/amd64 and Linux/arm64 candidate index. Native runners test each
architecture from that immutable digest with non-root startup,
encrypted TCP/UDP and guest echo, disabled-feature escape hatches, and SIGTERM
under traffic. Unit, race, integration, fuzz and bounded encrypted capacity,
WAN, sustained, mixed and fragment workloads must also pass before promotion.
Independent failure-control jobs remain separate from this release gate.

Promotion assigns `sha-<commit>` and `latest` to the **same tested manifest**;
it does not rebuild the image. Both tags are checked against the tested digest,
and the workflow retains runtime, cleanup and promotion evidence. Promotion is
serialized per branch. A run whose commit is no longer the current `master`
head skips promotion, so an older run cannot replace a newer release.
A failed acceptance run leaves the existing `latest` unchanged.

Development branches publish only `dev-<commit>-<run>-<attempt>` after the same
gates; pull requests build locally without registry writes. Manual dispatch on
`master` uses the same checks and promotion policy. Pooling-study dispatches
publish no image. The `latest` index includes **Linux/amd64 and Linux/arm64**
only after both runtime fixtures pass. PR builds remain amd64-only.
For reproducible deployment, use the immutable digest
recorded by the successful promotion run rather than the moving `latest` tag.

## Downloadable binaries

Version-tag pushes (`vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-SUFFIX`) run the
same full acceptance pipeline. The tagged commit must belong to `master`.
Both native image-test jobs extract `/usr/local/bin/wgslirp` from their tested
immutable image, check ELF architecture and absence of a dynamic interpreter,
and package it with `LICENSE` and `SOURCE.json`. Linux executables are not rebuilt
after acceptance. The metadata records the commit, image index and binary SHA-256.

After all image/workload gates and image promotion pass, the workflow publishes
Linux amd64/arm64 tar archives, a Windows amd64 ZIP and `SHA256SUMS` on a
versioned GitHub Release. Suffix tags produce prereleases. Assets are uploaded to a draft before publication; an already
published version is never overwritten. Reruns may finish an incomplete draft.
Version tags also publish the tested container index under the version tag;
they do not change the container's `latest` tag. GitHub Release publication does
not change the repository's existing latest-release designation.

Ordinary branch builds provide seven-day CI binary artifacts after each
platform's validation, but create no GitHub Release. PR builds do not publish binaries.
Download a matching architecture archive and `SHA256SUMS` from the version's
[release page](https://github.com/irctrakz/wgslirp/releases), then verify and extract:

```sh
sha256sum --ignore-missing --check SHA256SUMS
tar -xzf wgslirp-<commit>-linux-amd64.tar.gz
```

Use the arm64 archive for ARM Linux. The standalone executable uses the same
environment configuration and userspace forwarding as the container. Run it as
an ordinary user with finite process/memory limits and working CA certificates;
Linux ping-socket permission still applies. Container security/resource limits
are supplied by the container runtime and are not embedded in the binary.

### Windows amd64

The Windows job builds `wgslirp.exe` with CGO disabled, runs native unit tests,
and exercises encrypted TCP/UDP plus fragmented traffic against that exact
executable before packaging. Its `SOURCE.json` records the commit, platform and
binary hash; the Windows executable is built separately from the Linux images.
All three platforms must pass before container promotion and binary publication.

Extract the ZIP and configure the same `WG_PRIVATE_KEY` and `WG_PEER_<index>_*`
environment variables. **Set `ICMP_ECHO=false` on Windows**: the unprivileged
ping-socket API is unavailable there. Startup fails with an actionable error if
echo is left enabled; no ping process or elevated raw-socket fallback is used.
TCP/UDP forwarding requires no kernel TUN, Wintun installation or Administrator
identity. Firewall policy and outbound access still belong to the deployment.
Check the ZIP with PowerShell `Get-FileHash -Algorithm SHA256` against SHA256SUMS.

The Windows fixture forcibly terminates its child process for bounded cleanup;
it does not establish Linux-equivalent graceful shutdown, service integration,
Job Object resource containment or Windows ARM64 support. Unix FD-limit metrics
are unavailable and omitted on Windows. Capture remains off by default; if
enabled, secure its directory with NTFS ACLs because Unix file-mode bits do not
restrict Windows file access.

## Keep credentials in a private local file

From the repository root, create `deploy/wgslirp.env` with mode 0600 (use
`umask 077` before creating it). Fill these fields using a local editor:

```dotenv
WG_PRIVATE_KEY=<server-private-key>
WG_LISTEN_PORT=51820
WG_MTU=1380
WG_PEER_0_PUBLIC_KEY=<client-public-key>
WG_PEER_0_ALLOWED_IPS=10.77.0.2/32
```

`WG_PEERS` is optional: the executable discovers numeric peer indices from the
configured `WG_PEER_<index>_*` fields. Sparse indices work; every discovered peer
must have a valid public key. An explicitly set `WG_PEERS` retains its selection
behavior, including an empty value selecting no peers. Lookup-only library callers
using `DeviceConfigFromEnv` still supply a selector; use
`DeviceConfigFromEnvironment` with an environment map for automatic discovery.

Generate keys with `wg genkey > private.key` under the same restrictive umask;
derive the public key with `wg pubkey < private.key > public.key`. Share only the
public key. Both `private.key` and the deployment env file are excluded from Git and Docker
build contexts.
Private keys are not printed in setup commands or passed as literal command-line
arguments. Environment configuration remains visible to Docker administrators;
an env file is not a secret manager. Avoid posting rendered configuration or
unfiltered container inspections containing credentials.

## Start and stop

The versioned [Compose configuration](../deploy/compose.yaml) uses the image's
non-root user, all capabilities dropped, no-new-privileges, a read-only root,
1 CPU, 256 MiB memory/no swap, 128 PIDs, a 16 MiB temporary filesystem and bounded
logs. Only the WireGuard UDP port is published. Defaults retain finite application
queues and budgets without extra TCP tuning overrides.

```sh
docker compose -f deploy/compose.yaml config --quiet
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml logs --tail 50
docker compose -f deploy/compose.yaml down
```

Stop allows ten seconds for SIGTERM before Docker's forced termination. The CI
fixture verified clean SIGTERM under encrypted TCP/UDP traffic with these runtime
restrictions. It used an internal test network and did not validate your host
firewall, public UDP port reachability or production workload sizing. These
resource limits are a tested small-workload baseline, not a capacity promise.

Repeated known WireGuard TUN write failures (unsupported IPv4 fragments,
flow/dial/buffer limits and queue saturation) log the first occurrence per category,
then a suppressed-count summary every 30 seconds while failures occur. Quiet
burst tails are flushed by that timer and at device shutdown. Categories are
fixed per device; unexpected errors still log immediately. Packet errors, drop
behavior and admission counters are unchanged. Aggregation does not enable
incoming IPv4 fragment support.

Counts describe TUN write error callbacks, not necessarily individual packets:
wireguard-go may batch packets. WGTun attempts the remaining packets after a
failure and returns the first error; only accepted packets/bytes are counted.

Incoming IPv4 reassembly is enabled by default in newly built images. Set
`IPV4_REASSEMBLY: "false"` in Compose's environment to retain fragment rejection.
Older pinned images retain their original default. Reassembly keeps finite
byte/datagram/source/range limits and shares the socket buffer budget. The quota
is per source IP, not authenticated peer: four sources can occupy all 32 slots.
Watch quota refusals and expiry recovery before increasing traffic or limits;
see [configuration, ownership and acceptance gates](CONTRACTS.md).

Capture is off by default. Enabling `WG_PCAP` requires an explicitly writable
path with private permissions and an appropriate `WG_PCAP_MAX_BYTES` cap. The
temporary filesystem is bounded and ephemeral; do not expect captures to persist.
Default `WG_DISABLE_IPV6=false` leaves sysctls unchanged. Do not add privileges
to enable the legacy opt-in in this deployment profile.

<a id="optional-icmp-scope"></a>

## Guest ping and ICMP scope

New builds enable guest IPv4 ping by default using only unprivileged ping
sockets. Set `ICMP_ECHO=false` to disable it. The network namespace must permit
the image's process group through `net.ipv4.ping_group_range`; startup fails with
an actionable error if it cannot open the socket. The application does not change
that policy, add capabilities or execute a ping binary. Permission is namespace
policy managed by deployment tooling, including any Kubernetes/ECS restrictions.
Destination firewalls and cloud rules can still block echo.

Ping uses the container's normal network path. It supports echo only, not every
ICMP type, GRE, EoIP or Ethernet tunnels. Correlation retains guest identity with
finite request, expiry and shared-memory limits. Older pinned images retain
their prior activation policy; the image above includes default-enabled echo.

Library callers selecting `Config.Protocol = "ip4:icmp"` (the retained library
default) try raw ICMP, then ping sockets. Capability-free Linux ping sockets
require the process group to be allowed by the host's `net.ipv4.ping_group_range`.
The application does not change that policy. Echo fallback has bounded request
correlation and was tested without raw-socket capabilities. It does not provide
arbitrary raw ICMP forwarding. Startup fails if neither socket is available.

Privileged raw-ICMP deployment is **outside this validated deployment profile**.
Its library implementation remains for compatibility; do not claim its runtime
behavior was covered by the executable image gate. Library users wanting the
same privilege contract as the executable should select `ip4:tcp` and `ICMPEcho=true`,
which activates the TCP/UDP bridges and unprivileged echo. See [README.md](README.md#icmp-privileges).

Compose option semantics follow the [Docker Compose service reference](https://docs.docker.com/reference/compose-file/services/).
