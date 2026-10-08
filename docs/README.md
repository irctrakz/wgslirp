# wgslirp

A userspace WireGuard router that forwards IPv4 TCP/UDP through ordinary host
sockets, slirp-style. The executable needs no kernel TUN device, forwarding/NAT
rules or added kernel capabilities. Outbound traffic uses the server network path.

This integration checkpoint contains: **harden tcp recovery, packet validation and metrics**.
It is a review boundary, not a newly accepted release image. Historical plans and
benchmark records remain on the architecture-hardening branch; the PR description
records the validation and migration relevant to this checkpoint.

## Configuration

The executable validates one environment snapshot before creating resources.
Supply a server private key and a distinct client public key/address:

```dotenv
WG_PRIVATE_KEY=<server-private-key>
WG_LISTEN_PORT=51820
WG_MTU=1380
WG_PEERS=0
WG_PEER_0_PUBLIC_KEY=<client-public-key>
WG_PEER_0_ALLOWED_IPS=10.77.0.2/32
```

Keep private keys out of source control and command history. Docker administrators
can inspect container environment; environment files are not a secret manager.
Configure the client with the matching endpoint, server public key and MTU.
IPv6 and arbitrary ICMP forwarding are outside the executable's TCP/UDP scope
at this checkpoint. Startup health probes are not continuous readiness checks.

Finite queues and byte/dial budgets protect the process under pressure. Flow caps
can explicitly be set to zero for unlimited admission, but storage/dial zero
values select finite defaults. Inspect admission/queue pressure and leave memory
headroom for kernel buffers and the Go runtime when choosing resource limits.
Capture and debug logging should remain disabled for normal operation.

## Build and check

Use Go 1.23.x (CI pins 1.23.12); Linux is the full acceptance target:

```sh
go build -o wgslirp ./cmd/wgslirp
go vet ./...
go test -race -timeout 120s -count=1 ./...
go test -race -tags=integration -timeout 120s -count=1 ./...
```

[Go CI](../.github/workflows/go.yml) validates each integration branch.
[Container CI](../.github/workflows/docker.yml) builds PR images without publishing
`latest`. Automatic master publication is suspended while this stack is reviewed.
Each curated PR depends on its predecessor; review and land them in order.
TCP/UDP routing stays in userspace throughout these changes.

[Apache 2.0 license](../LICENSE).
