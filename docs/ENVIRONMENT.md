# Environment variables

These settings apply to the executable unless marked library-only. Startup reads
one environment snapshot and validates it before creating resources. There is no
JSON/YAML configuration-file or command-line override layer. Booleans accept
`true/false`, `1/0`, `yes/no` and `on/off`; empty or malformed supported values
fail startup. See [configuration contracts](CONTRACTS.md) for validation,
zero-value rules and Go library adapters.

## Core WireGuard (required/primary)

- `WG_PRIVATE_KEY`: Base64 private key for the device (required).
- `WG_LISTEN_PORT`: UDP listen port, default 51820.
- `WG_MTU`: Plaintext MTU for the userspace TUN (default 1380).
- Peers are discovered from `WG_PEER_<index>_*` settings when `WG_PEERS` is absent.
  Indices are canonical nonnegative decimal integers (`0`, `2`, `10`); gaps are
  allowed and discovery uses numeric order. Incomplete peers and unknown peer
  setting names fail startup. Set `WG_PEERS` explicitly to select/reorder peers
  using the existing behavior; an explicit empty value selects none. For each index `i`:
  - `WG_PEER_i_PUBLIC_KEY`: base64 peer public key (required for each peer).
  - `WG_PEER_i_ALLOWED_IPS`: comma-separated CIDRs for overlay routing decisions.
  - `WG_PEER_i_ENDPOINT`: `host:port` (optional; learned from authenticated client traffic when absent).
  - `WG_PEER_i_KEEPALIVE`: seconds (optional; typical 25).

## Overlay routing (optional)

- `WG_OVERLAY_ROUTING`: enable overlay re-route for packets destined to AllowedIPs.
- `WG_OVERLAY_EXCLUDE_CIDRS`: CIDRs that should always egress via slirp.
- `WG_DISABLE_IPV6`: defaults to false and leaves namespace sysctls unchanged. Explicit true preserves the legacy best-effort IPv6-disable writes; failures remain nonfatal. Deployments relying on the old default must opt in or manage namespace policy externally; see [migration notes](CONTRACTS.md). This setting does not enable IPv6 forwarding.

## Logging and diagnostics

- `DEBUG`: enable verbose logging. Packet ownership and copying are explicit and independent of logging.
- `WG_DEBUG`: verbose wireguard-go logging (chatty).
- `WG_PCAP`: file path to write plaintext IPv4 frames (DLT_RAW) captured by the userspace TUN.
- `WG_PCAP_MAX_BYTES`: capture file size limit, including headers; defaults to 67108864 (64 MiB). Must be an integer of at least 24. Capture stops before a complete record would exceed the limit and stays stopped until process restart. Invalid values fail startup without touching the file; capture is opened at startup and cannot follow later environment changes. Forwarding continues when capture stops. Capture files use private permissions (0600).

## Metrics and health

- `METRICS_LOG`: `true` enables periodic metrics logging; `false` disables it even if an interval is set.
- `METRICS_INTERVAL`: positive duration like `15s` (default `30s`). Setting it enables metrics unless `METRICS_LOG=false`; leaving both unset disables metrics.
- `METRICS_FORMAT`: `text` (default) or `json`.
- `HEALTHCHECK`: `true` enables one-time startup probes. These log results; they are not continuous readiness monitoring. Probes have five-second operation timeouts and are canceled and joined during shutdown.
- `HEALTH_HTTP_URL`: URL for the host-stack HTTP probe (default `https://httpbin.org/ip`). The final response must have a 2xx status.
- `HEALTH_DNS_NAME`: name for both host resolver and slirp DNS probes (default `example.com`).
- `HEALTH_DNS_IP`: IPv4 DNS server for the slirp probe (default `1.1.1.1`). Success requires a complete response from the expected server to the probe's address/port, matching transaction ID and question, successful DNS status, and an A answer for `HEALTH_DNS_NAME` (including CNAME chains).

## Guest ping

`ICMP_ECHO` defaults to true in the executable. It enables IPv4 echo requests
through a ping socket (`SOCK_DGRAM`), never raw sockets or subprocesses. False
disables guest echo. The container network namespace must allow the process group
in `net.ipv4.ping_group_range`; unavailable sockets fail startup with instructions
to permit that group or disable echo. The application does not alter sysctls.
The reader reserves 64 KiB plus entry overhead from the shared socket budget.
Outstanding requests are capped at 1,024, expire after five seconds and also
consume that budget; see `icmp_echo_limit` in [observability](CONTRACTS.md).
Only echo request/reply is supported, not arbitrary ICMP or encapsulated tunnels.
The older [issue #3 example](https://github.com/irctrakz/wgslirp/issues/3) used
`SOCKET_PROTOCOL`; the executable has no such selector. Use `ICMP_ECHO` and
remove `TCP_GATE_LOG` from older configurations.

Library callers retain the legacy protocol default. For capability-free TCP/UDP
plus echo, set `Config.Protocol="ip4:tcp"` and `Config.ICMPEcho=true`. This bool
controls ping sockets in TCP/UDP mode; it does not override legacy `ip4:icmp` mode.

## Queues and pooling

| Setting | Default | Meaning |
|---|---:|---|
| `WG_TUN_QUEUE_CAP` | 1024 | Outbound packet queue to wireguard-go; range 1-65536. |
| `POOLING` | true | Cache synthesized packet buffers through 16,384 bytes, including ACK/control packets. False selects exact-sized storage. Idle cache retention is bounded at 960 KiB. |
| `PROCESSOR_WORKERS` | 4 | Library worker pool only, range 1-256; inactive in the executable and warns when set. |
| `PROCESSOR_QUEUE_CAP` | 1000 | Library worker queue only, range 1-65536; inactive in the executable and warns when set. |

Pooling does not extend into UDP reply or IPv4 reassembly storage. Packet
ownership is explicit and independent of logging. See [packet ownership](CONTRACTS.md).

## Flow and buffer limits

| Setting | Default | Meaning |
|---|---:|---|
| `TCP_FLOW_LIFETIME_SEC` | 120 | Idle TCP lifetime; zero uses the default. |
| `UDP_FLOW_LIFETIME_SEC` | 60 | Idle UDP lifetime; zero uses the default. |
| `TCP_REASSEMBLY_CAP_BYTES` | 131072 | Out-of-order storage threshold per TCP flow; zero uses the default. |
| `IPV4_REASSEMBLY` | true | Bounded incoming TCP/UDP/ICMP fragment reassembly; explicit false disables it. See [limits and acceptance gates](CONTRACTS.md). |
| `IPV4_FRAGMENT_BUFFER_CAP_BYTES` | 4194304 | Finite fragment storage cap sharing the socket budget; zero uses the default. Fixed datagram/source/range quotas also apply. |
| `MAX_TCP_FLOWS` | 256 | Maximum registered TCP flows, including TIME-WAIT; explicit zero is unlimited. |
| `MAX_UDP_FLOWS` | 512 | Maximum registered UDP flows; explicit zero is unlimited. |
| `MAX_PENDING_TCP_DIALS` | 64 | Concurrent fast/async TCP dial attempts; one reservation spans fallback. |
| `SOCKET_BUFFER_CAP_BYTES` | 67108864 | Shared TCP/UDP and downstream queue buffer budget (64 MiB). |
| `TCP_PEND_CAP_BYTES` | 65536 | Per-flow TCP data accepted before host connection completes. |
| `TCP_RETRANSMIT_CAP_BYTES` | 1048576 | Per-flow unacknowledged TCP payload storage (1 MiB). |

Zero selects the finite default for pending-dial, shared-buffer, pending-write,
retransmission and fragment-storage limits. It does not disable them. Only the
two flow admission caps support explicit zero for unlimited admission. Idle
expiry is checked periodically; TIME-WAIT retains a TCP flow slot for four minutes.

The shared budget limits accounted live storage, not process RSS. Kernel socket
buffers, allocator/GC overhead and other metadata require separate headroom.
See [resource budgets](CONTRACTS.md) and [fragment quotas](CONTRACTS.md).

## TCP and packet headers

| Setting | Default | Meaning |
|---|---:|---|
| `TCP_ACK_DELAY_MS` | 10 | Delayed ACK scheduling in milliseconds; zero requests immediate ACKs. |
| `TCP_ACK_IDLE_GATE_MS` | 6000 | Gate host reads after this long without ACK/window progress; zero disables gating and ACK-idle failure. |
| `TCP_ACK_IDLE_MIN_INFLIGHT` | 0 | Minimum bytes in flight for gating; zero uses one MSS. |
| `TCP_ACK_IDLE_FAIL_SEC` | 120 | Reset an ACK-stalled flow after this interval; zero disables this check. |
| `TCP_ACK_TRACE` | false | Log ACK classification. |
| `TCP_MSS_CLAMP` | 0 | Advertised/segmentation MSS ceiling, up to 65535; zero leaves peer/MTU limits. |
| `TCP_PACE_US` | 0 | Inter-segment pacing in microseconds; zero disables. |
| `TCP_ERROR_SIGNAL` | icmp | Dial-failure signaling: `icmp`, `rst`, or `none`. |
| `TCP_LOG_HANDSHAKE` | false | Log SYN-ACK MSS decisions. |
| `TCP_FAST_DIAL_MS` | 5 | Wait for an immediate dial result before SYN-ACK; zero retains the historical 1 ms minimum. The same dial continues asynchronously, with a total deadline of the greater of this wait and 5 seconds. |
| `TCP_CC` | newreno | Congestion control: `newreno` (`reno`/`new-reno` aliases) or `off`. |
| `TCP_INIT_CWND_MSS` | 0 | Positive values reduce the RFC 6928 initial window to at most this many MSS; zero uses the RFC default. |
| `TCP_SOCK_RCVBUF` | 0 | Requested host receive-buffer bytes; zero uses OS defaults. |
| `TCP_SOCK_SNDBUF` | 0 | Requested host send-buffer bytes; zero uses OS defaults. |
| `TCP_WS_OUT` | 7 | Preferred TCP window scale, 0-14, negotiated only when offered. Receive space stays bounded by `TCP_REASSEMBLY_CAP_BYTES`; small caps lower the scale. See [receive recovery](CONTRACTS.md). |
| `TCP_ENABLE_SACK` | false | Legacy force-SACK option; peer-offered SACK is still honored when false. |
| `COPY_TOS` | false | Preserve guest DSCP/ECN in supported synthesized reply paths. |
| `IP_TTL` | 64 | Synthesized reply TTL, 1-255. |

The operating system may clamp requested socket buffer sizes. Setter failures
are logged. Peer SACK negotiation is honored with the default
`TCP_ENABLE_SACK=false`; setting true forces the legacy option.
Independent flow, retransmission and close timers still apply when ACK-idle
failure is disabled. See [TCP receive recovery](CONTRACTS.md).

## Configuration summary and removed settings

`PRINT_CONFIG=true` prints a sanitized JSON effective-settings summary at startup,
independent of log level. It omits keys, peer endpoints, routing prefixes,
capture paths and health targets.

`POOL_WRAP` and `TCP_GATE_LOG` have been removed. Their presence fails startup,
even when false/off; delete them. Old `FLOW_*`, `SIMPLE_MODE` and asynchronous
TUN-input switches are not configuration controls for the current inline pipeline.
See [API migration](API_MIGRATION.md) before updating older deployments or callers.
