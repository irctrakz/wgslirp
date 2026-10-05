# Bounded non-root deployment

The executable forwards IPv4 TCP/UDP through ordinary userspace sockets and an
in-memory WireGuard TUN. It needs no kernel TUN device, routing sysctl changes,
root identity or added capabilities. Docker administration is a host deployment
operation; the application receives no Docker socket or host network access.

## Select a validated image

Use Linux/amd64 and a digest from a successful development CI run. Candidate tags
are not validation evidence. See [RELEASE_IMAGE_TEST.md](RELEASE_IMAGE_TEST.md)
for the current tested source/digest and run reports. The example below uses the
validated automatic-peer-discovery, log-aggregation and opt-in reassembly image. Arm64 runtime
validation remains separate.

```sh
export WGSLIRP_IMAGE=ghcr.io/irctrakz/wgslirp@sha256:e5a746f0737361e523fd052dc8525fd5b43bc93ec599baf34fe05c93517421be
```

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

Incoming IPv4 reassembly is opt-in with `IPV4_REASSEMBLY: "true"` in Compose's
environment. It keeps finite byte/datagram/source/range limits and shares the
socket buffer budget. Bounded image acceptance passed; default enablement remains
a separate deployment review. For opt-in testing,
see [configuration, ownership and default-enablement gates](IPV4_FRAGMENT_REASSEMBLY.md).

Capture is off by default. Enabling `WG_PCAP` requires an explicitly writable
path with private permissions and an appropriate `WG_PCAP_MAX_BYTES` cap. The
temporary filesystem is bounded and ephemeral; do not expect captures to persist.
Default `WG_DISABLE_IPV6=false` leaves sysctls unchanged. Do not add privileges
to enable the legacy opt-in in this deployment profile.

## Optional ICMP scope

The executable explicitly chooses TCP/UDP mode; adding `CAP_NET_RAW` does not
activate guest ping. There is no supported executable ICMP-enable switch.

Library callers selecting `Config.Protocol = "ip4:icmp"` (the retained library
default) try raw ICMP, then ping sockets. Capability-free Linux ping sockets
require the process group to be allowed by the host's `net.ipv4.ping_group_range`.
The application does not change that policy. Echo fallback has bounded request
correlation and was tested without raw-socket capabilities. It does not provide
arbitrary raw ICMP forwarding. Startup fails if neither socket is available.

Privileged raw-ICMP deployment is **outside this validated deployment profile**.
Its library implementation remains for compatibility; do not claim its runtime
behavior was covered by the executable image gate. Library users wanting the
same privilege contract as the executable should explicitly select `ip4:tcp`,
which activates the TCP/UDP bridges. See [README.md](README.md#icmp-privileges).

Compose option semantics follow the [Docker Compose service reference](https://docs.docker.com/reference/compose-file/services/).
