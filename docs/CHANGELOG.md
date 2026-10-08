# Changelog

## Unreleased — development branch

- Enable guest IPv4 ping by default using unprivileged ping sockets, with
  `ICMP_ECHO=false` as an opt-out. Unavailable sockets fail startup actionably;
  no capabilities, sysctl writes, raw fallback or subprocesses are introduced.
- Remove always-unsupported kernel-TUN constructors and the unused legacy
  JSON/YAML configuration package and core configuration types.
- Retire debug-dependent packet APIs and configurable packet wrapping in favor
  of explicit borrowed/copied/pooled ownership. Debug now affects logging only.
- Remove inactive send-gate configuration. `POOL_WRAP` and `TCP_GATE_LOG` now
  fail startup with migration instructions, including explicit false/off values.
- Remove obsolete effective-summary and CI-evidence fields for those policies.

These are breaking library/configuration changes. See [migration and policy](API_MIGRATION.md).
Userspace socket forwarding, resource bounds, pooling defaults and metrics
schema remain unchanged. Release images are still promoted by tested digest.
