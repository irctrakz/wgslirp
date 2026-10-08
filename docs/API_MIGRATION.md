# Development API retirement

## 2026-10-08 cleanup

The user explicitly selected removal of the legacy surfaces below on
`codex/architecture-hardening`. This is a deliberate breaking library/configuration
change, not a claim that repository-local non-use proves no external consumers.
Existing consumers can pin the preceding commit `a15579b` while migrating.
No stable release version or `latest` tag is changed by this document.

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
Publish deliberate compatibility boundaries with stable releases. This branch's
explicitly authorized retirement does not authorize removing other exported
constructors or mock interfaces.

A breaking metrics change requires a new `schema_version`; additive fields may
remain compatible. Release notes identify the source commit and tested image
digest. A rebuilt image is a new artifact and must not be described as the same
tested image.

## Validation

Retain independent aliasing/copy/capacity checks, exactly-once pooled release,
fan-out/rejection ownership, finite pooling and sanitized fail-fast migration
errors. Require Linux unit/race, integration/race, fuzz and bounded encrypted
workloads plus actual-image forwarding/shutdown validation before promoting
the cleanup candidate. Runtime privilege, queue, byte-budget, cancellation,
TCP negotiation and segmentation requirements remain unchanged.

### Acceptance at `4b2e254`

[Release pipeline 37825299733](https://github.com/irctrakz/wgslirp/actions/runs/37825299733)
passed all 19 jobs: Linux build/vet, unit/race, integration/race, three fuzz
checks, sixteen bounded encrypted workload samples, actual-image validation
and promotion. The separate [Go Tests run](https://github.com/irctrakz/wgslirp/actions/runs/37825299160)
also passed. [Independent controls 37825368016](https://github.com/irctrakz/wgslirp/actions/runs/37825368016)
passed all eight ordinary/race mutation controls; retained artifacts confirmed
the expected assertion failures, source identity, resource gates and cleanup.

All sixteen workload resource/cleanup artifacts were independently inspected.
Maximum cgroup memory was 1,061,855,232 bytes, below the unchanged 2 GiB limit,
with no memory-limit/OOM/PID-limit events. Capacity recovered after the real
four-minute TIME-WAIT interval; ordinary/race peak RSS was 42,172,416 / 421,019,648
bytes, within the existing respective limits.

The actual image ran as UID 100 with all capabilities dropped, read-only root,
one CPU, 256 MiB RAM/no swap and 128 PIDs. Default/disabled configurations passed
encrypted TCP/UDP, fragment and shutdown checks; SIGTERM under traffic completed
in 80 / 77 ms. Sampled cgroup peaks after eight rounds were 57,327,616 / 27,500,544
bytes. These are acceptance samples, not claims of a measured performance gain.

The tested and promoted artifact was identical, with no rebuild:

```text
ghcr.io/irctrakz/wgslirp@sha256:be56bb216de910559d457e3b23dd7cf0b796f2577474bcbc503a2ee759973e1b
```

Development tag:
`dev-4b2e254d0d66648af2b89384129a85a26c470ba6-37825299733-1`.
Main/`master` and `latest` were untouched. No private server was used.
Local focused ownership/configuration tests, package vet and Linux cross-build
passed; the full Windows run retained its recorded empty-UDP and POSIX file-mode
test failures. Linux CI provides the complete acceptance evidence above.
