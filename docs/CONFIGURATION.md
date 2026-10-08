# Startup configuration contract

`wgslirp` snapshots the environment once, parses and validates all supported
settings, then creates resources. Defaults are overridden by explicitly present
environment values. Changing the environment afterward cannot change an existing
bridge, TUN, device, capture, pooling policy, health probe or metrics reporter.
Explicit runtime MTU/MSS/pacing APIs remain separate, deliberate operations.

The executable has no JSON/YAML file or command-line override layer. The
[environment reference](ENVIRONMENT.md) lists its settings.
Unknown variables are not rejected (the process inherits unrelated OS variables).

## Validation and migration

- Boolean controls accept `true/false`, `1/0`, `yes/no`, `on/off`, ignoring case
  and surrounding whitespace. Empty/unknown boolean values fail startup.
- `IPV4_REASSEMBLY` defaults to true in the executable and `socket.DefaultConfig()`.
  Explicit `false` disables it; a zero-value library `socket.Config{}` stays
  disabled for compatibility. Its finite
  `IPV4_FRAGMENT_BUFFER_CAP_BYTES` defaults to 4 MiB (zero also selects that
  default), sharing the aggregate socket budget. Enabled support requires at
  least 69,631 bytes. Fixed datagram/source/range limits and expiry are documented
  in [IPv4 fragment reassembly](IPV4_FRAGMENT_REASSEMBLY.md).
- Numeric controls reject empty, malformed, overflowing and out-of-range values.
  Unset values retain defaults. WireGuard listen port zero requests an ephemeral
  port; MTU is 576-65535 and keepalive is 0-65535 seconds.
- `METRICS_LOG=true` enables metrics. An explicit `METRICS_INTERVAL` also enables
  metrics unless `METRICS_LOG=false` overrides it. Both unset means disabled.
  `METRICS_FORMAT` is `text` or `json`; intervals must be positive durations.
  Previously any nonempty `METRICS_LOG` or `HEALTHCHECK` value enabled the feature.
  Use a real boolean now; `false` disables it and empty values are invalid.
- Health URL, DNS name and IPv4 server are validated even if health is disabled.
  `HEALTH_DNS_NAME` now drives both host-resolver and slirp DNS probes, including
  response validation. The default remains `example.com`.
- `WG_TUN_QUEUE_CAP` defaults to 1024, range 1-65536. These queue slots consume
  metadata separately from the shared packet payload budget.
- `MAX_TCP_FLOWS` defaults to 256 registered flows, including TIME-WAIT;
  `MAX_UDP_FLOWS` defaults to 512. These limits apply across peers on the socket
  interface. Explicit positive overrides and zero/unlimited admission remain
  supported. Pending-dial and aggregate buffer limits are independent.
- `PROCESSOR_WORKERS` and `PROCESSOR_QUEUE_CAP` are **inactive in the executable**,
  which forwards inline. Startup warns when either is present. Remove these
  variables from deployments. The optional library processor still supports
  them through the adapters below; it defaults to 4 workers and 1000 slots and
  accepts 1-256 workers and 1-65536 slots.
- `POOLING` defaults to true. Its process-wide policy is frozen
  before the first socket interface or packet allocation. A repeated identical
  configuration is safe; conflicting reconfiguration returns an error.
  With `POOLING=true`, all pool-capable synthesized packets through 16,384 bytes
  use the bounded packet cache, including ACK/control packets. Larger buffers
  remain exact-sized. `POOLING=false` selects exact-sized storage at every size.
  Live reservations follow the actual storage capacity. Packet constructors choose
  ownership explicitly; configurable wrapping was removed. Idle retention stays
  bounded at 960 KiB process-wide.
  This does not extend pooling into UDP reply or IPv4 reassembly storage.
- Capture is disabled unless `WG_PCAP` names a path. `WG_PCAP_MAX_BYTES` defaults
  to 64 MiB, minimum 24 bytes. Parsing and opening happen at startup, so invalid
  settings or inaccessible files fail startup before forwarding. Packet-time
  environment changes cannot enable or redirect capture. Repeating a configured
  capture does not truncate it. After close, write failure or size exhaustion it
  cannot reopen within the process. Runtime capture failures stop capture while
  forwarding continues. Existing 0600 permissions and complete-record limits apply.
- `WG_DISABLE_IPV6` now defaults to **false**: startup leaves IPv6 sysctls unchanged.
  This is an intentional default change; it does not add IPv6 forwarding support
  or affect userspace IPv4 TCP/UDP forwarding. Deployments relying on the previous
  best-effort disable attempt must explicitly set `WG_DISABLE_IPV6=true` (existing
  true aliases remain supported), or configure their network namespace through
  deployment tooling. Explicit false remains a no-op. Explicit true retains the
  same three sysctl writes and nonfatal failure behavior; it grants no privileges.
  Do not grant elevated privileges merely to preserve the old implicit default.
  Library callers using nil/default options also get false; an explicit
  `DeviceOptions{DisableIPv6: true}` preserves the legacy opt-in behavior.

`PRINT_CONFIG=true` emits a JSON effective-settings summary at startup, independent
of logging level. The summary includes transport/resource controls, queue/pool
settings, device port/MTU, peer/exclusion counts, diagnostic flags and limits.
It omits private/public keys, peer endpoints, routing prefixes, capture paths and
health URLs/names. It does not enable packet or WireGuard debug logging.

## Go library callers

Environment parsing is explicit for new code:

| Component | Typed configuration | Environment adapter / constructor |
|---|---|---|
| Socket bridge | `socket.Config` | `ConfigFromEnv`, `NewSocketInterface` |
| Optional worker pool | `socket.ProcessorConfig` | `ProcessorConfigFromEnv`, `NewSocketPacketProcessorWithConfig` |
| WireGuard device | `wireguard.DeviceConfig` / `DeviceOptions` | `DeviceConfigFromEnv`, `StartDevice` |
| Userspace TUN | `wireguard.TunConfig` | `TunConfigFromEnv`, `NewWGTunWithConfig` |
| Process capture | `wireguard.CaptureConfig` | `CaptureConfigFromEnv`, `ConfigurePCAP` before workers; `ClosePCAP` at shutdown |
| Process pooling | `socket.PoolConfig` | `PoolConfigFromEnv`, `ConfigurePooling` before constructing interfaces/packets |

Adapters accept a lookup function so tests and callers can supply stable inputs.
Use the corresponding `Default...Config` / `DefaultDeviceOptions` functions before
overriding individual fields. Constructors copy retained configuration values;
WireGuard copies its options and exclusion slice for startup. Callers must not
concurrently mutate input while a constructor is reading it.

The old exported `NewWGTun` and `NewSocketPacketProcessor` signatures remain as
deprecated compatibility adapters. They snapshot environment overrides once;
because they cannot return errors, invalid settings log a warning and select
bounded defaults. Explicit constructors return errors before allocating queues.
`DeviceConfig.LoadFromEnv` remains an adapter and leaves its receiver unchanged
on failure. `StartDevice` itself no longer reads environment settings. Library
users relying on implicit pooling/capture environment reads must explicitly parse
and configure those process-wide policies before creating components.

## Retired configuration surfaces

The legacy `pkg/config` JSON/YAML model and its core router/WireGuard types have
been removed. Use validated `socket.Config` and `wireguard.DeviceConfig`, or
explicit environment parsers. Legacy file settings never configured the executable.

`POOL_WRAP` and inactive `TCP_GATE_LOG` are removed. Startup rejects their presence,
including false/off values, with instructions to remove them. `POOLING=false`
remains supported. Debug controls logging only and never changes packet ownership.
See [breaking-change migration and policy](API_MIGRATION.md).
