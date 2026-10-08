# Changes from master

## Architectural hardening

- Validate one startup configuration snapshot; keep credentials out of summaries.
- Bound flows, pending dials, queue storage, TCP buffers, capture and echo requests.
- Make packet ownership, reservation release and shutdown cancellation explicit.
- Correct TCP close states, ACK/SACK recovery, receive windows and segmentation.
- Split establishment, registry/lifecycle, receive, recovery and diagnostics helpers.
- Share packet encoding and validation; remove proven private residue.
- Add versioned metrics, admission reasons and actionable aggregated diagnostics.
- Validate bounded encrypted workloads and promote the actual tested image digest.

## Defaults and migration

- Default to 256 TCP flows, 512 UDP flows and a 1024-packet WireGuard queue.
- Enable bounded packet pooling, incoming IPv4 reassembly and guest echo by default;
  POOLING=false, IPV4_REASSEMBLY=false and ICMP_ECHO=false remain supported.
- Leave IPv6 sysctls untouched unless WG_DISABLE_IPV6=true is explicitly selected.
- Discover peer indices automatically when WG_PEERS is absent.
- Remove unsupported kernel-TUN constructors, the legacy configuration model,
  debug-dependent packet APIs, optional wrapping and inactive GateLog.
  Remove POOL_WRAP and TCP_GATE_LOG even when set to false/off.

See [API migration](API_MIGRATION.md), [environment settings](ENVIRONMENT.md) and
[runtime contracts](CONTRACTS.md) for compatibility boundaries and operating limits.
