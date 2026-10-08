# Development API retirement

## 2026-10-08 cleanup

This update deliberately retires the surfaces below. Repository-local non-use
alone does not prove no external consumers. Existing library consumers can pin
commit `a15579b` on the development branch while migrating. Consult these
replacements before upgrading; this guide does not change a stable image tag.

| Removed surface | Migration |
| --- | --- |
| `tun.CreateTUN`, `tun.OpenTUNWithPath` | These constructors always failed. Use `wireguard.NewWGTunWithConfig` for the userspace WireGuard adapter; no kernel TUN replacement is provided. |
| `pkg/config`, `core.RouterConfig`, `core.WireGuardConfig`, `core.WireGuardPeer` | Use validated `socket.Config` and `wireguard.DeviceConfig`, or their explicit environment parsers. Legacy JSON/YAML and `ROUTER_*`/`WIREGUARD_*` settings never configured the executable. |
| `core.NewPacket`, `core.SimplePacket` | Choose `NewBorrowedPacket` for stable caller storage or `NewCopiedPacket` for an independent snapshot. |
| `core.SetDebugMode`, `core.IsDebugMode` | Configure logging through `pkg/logging`. Debug logging no longer changes packet copying or aliasing. |
| `socket.WrapPacket`, `socket.PoolConfig.Wrap`, `POOL_WRAP` | Choose explicit copied/borrowed packets, or `NewPooledPacket` with an explicit release callback and reservation ownership. Remove `POOL_WRAP`, including an explicit false value. |
| `socket.TransportConfig.GateLog`, `TCP_GATE_LOG` | Remove the field/setting; it controlled no active logger. Active TCP diagnostics retain their own policies. |

Startup rejects either retired environment setting with its name and an action
to remove it, without echoing its value. `PRINT_CONFIG` no longer includes
`Pool.Wrap` or `Socket.Transport.GateLog`. CI evidence no longer has the obsolete
`pool_wrap` field. Metrics schema and transport defaults are unchanged.

Custom `core.Packet` implementations must make `Data()` return a borrowed,
read-only view for the ownership lifetime and expose retained capacity for
accounting. `CopyPacketData` is the explicit independent-copy operation.
Borrowing never authorizes reuse or mutation while another consumer retains
the packet. Pooled release and shared buffer reservations remain explicit;
`POOLING=false` remains supported and idle packet-cache retention stays at 960 KiB.

## Policy for future removals

Document a replacement and migration before removing a public API or setting.
Keep historical evidence intact, but update current deployment and ownership
guidance. Distinguish internal deletion from externally visible breaks; local
non-use alone is insufficient justification. Record breaking changes in the
changelog and release notes, with the last compatible commit/image when available.
Publish deliberate compatibility boundaries with stable releases. This retirement does not authorize removing other exported
constructors or mock interfaces.

A breaking metrics change requires a new `schema_version`; additive fields may
remain compatible. Release notes identify the source commit and tested image
digest. A rebuilt image is a new artifact and must not be described as the same
tested image.
