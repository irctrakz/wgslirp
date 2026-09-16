
[![Docker Build](https://github.com/irctrakz/wgslirp/actions/workflows/docker.yml/badge.svg)](https://github.com/irctrakz/wgslirp/actions/workflows/docker.yml)
[![Go Tests](https://github.com/irctrakz/wgslirp/actions/workflows/go.yml/badge.svg)](https://github.com/irctrakz/wgslirp/actions/workflows/go.yml)

# Userspace WireGuard slirp Router

A high-performance, user-space WireGuard router that forwards decrypted IPv4 traffic via generic TCP/UDP/ICMP socket bridges (slirp-style), requiring zero kernel privileges or custom netstacks.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
  - [Using Docker](#using-docker)
  - [Building from Source](#building-from-source)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [WireGuard Configuration](#wireguard-configuration)
  - [System Configuration](#system-configuration)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Overview

This router combines WireGuard VPN with a userspace networking implementation to provide efficient, secure, container-friendly routing. It uses a slirp-style approach to handle TCP, UDP, and ICMP (when running with CAP_NET_RAW) traffic between WireGuard tunnels and the host network.

### Key Features

- **WireGuard Integration**: Secure, modern VPN tunneling with WireGuard protocol
- **User-space Networking**: TCP/UDP bridges implemented in userspace
- **Protocol Support**: Handles TCP, UDP, and ICMP traffic with NAT capabilities
- **Performance Monitoring**: Built-in metrics collection and reporting
- **Health Checking**: Integrated health checks for monitoring system status
- **Container Ready**: Designed to run in containerized environments
- **Configurable**: Extensive configuration options via environment variables

## Architecture

The router consists of several key components:

1. **WireGuard Interface**: Handles encrypted tunnel traffic using the WireGuard protocol
2. **Socket Interface**: Manages TCP/UDP bridges for network traffic translation
3. **Slirp Bridges**: Direct inline delivery between slirp bridges and the processor (No FlowManager or egress limiter — simpler, predictable pipeline).
4. **Metrics Reporter**: Collects and reports performance metrics

The system uses a packet processing pipeline to efficiently route traffic between WireGuard tunnels and the host network.

```mermaid
graph TD
    A[WireGuard Tunnel] -->|Encrypted| B[WG Interface]
    B -->|Plaintext| C[Packet Processor]
    C -->|IPv4 Packets| D[Socket Interface]
    D -->|TCP| E[TCP Bridge]
    D -->|UDP| F[UDP Bridge]
    D -->|ICMP| G[ICMP Bridge]
    E -->|Return| C
    F -->|Return| C
    G -->|Return| C
    C -->|Encrypted| B
    B -->|WireGuard Protocol| A
    I[Metrics & Health] -.->|Stats| B
    I -.->|Stats| C
    I -.->|Stats| D
```

## Installation

### Using Docker

The easiest way to run the router is using Docker:

```yaml
services:
  wg-router:
    image: ghcr.io/irctrakz/wgslirp:latest
    container_name: wgslirp
    ports:
      - "51820:51820/udp"
    environment:
      
      # Sensible defaults - probably 99% of configs would use this
      - "POOLING=1"
      - "PROCESSOR_WORKERS=8"
      - "PROCESSOR_QUEUE_CAP=4096"
      - "WG_TUN_QUEUE_CAP=2048"
      - "TCP_ACK_DELAY_MS=5"
      - "TCP_ENABLE_SACK=1"
      
      #  If you want tcp / flow debugging enabled 
      #- "METRICS_INTERVAL=60s"
      #- "METRICS_FORMAT=text"
      #- "TCP_GATE_LOG=on"
      - "TCP_GATE_LOG=off"

      # If you want to fill up your logs fast
      #- "DEBUG=1"

      # WG config - this MUST be set
      - "WG_PRIVATE_KEY=<server-private-key>"
      - "WG_LISTEN_PORT=51820"
      - "WG_MTU=1200"
      
      - "WG_PEERS=0"
      - "WG_PEER_0_PUBLIC_KEY=<client-public-key>"
      - "WG_PEER_0_ALLOWED_IPS=10.77.0.2/32"
    restart: "no"
```

### Building from Source 
#### Container is at ghcr.io/irctrakz/wgslirp:latest

To build from source:

```bash
# Clone the repository
git clone https://github.com/irctrakz/wgslirp.git
cd wgslirp

# Build the binary
go build -o wgslirp ./cmd/wgslirp

# Or build the Docker image
docker build -t wgslirp -f Dockerfile .
```

## Quick Start

Get up and running quickly with these steps:

1. **Generate WireGuard Keys**:
   ```bash
   # Generate private key
   wg genkey > private.key
   
   # Generate public key from private key
   cat private.key | wg pubkey > public.key
   
   # View your keys
   echo "Private key: $(cat private.key)"
   echo "Public key: $(cat public.key)"
   ```

2. **Start the Router**:
   ```bash
    docker run --name wgslirp \
      -p 51820:51820/udp \
      -e POOLING=1 \
      -e PROCESSOR_WORKERS=8 \
      -e PROCESSOR_QUEUE_CAP=4096 \
      -e WG_TUN_QUEUE_CAP=2048 \
      -e TCP_ACK_DELAY_MS=5 \
      -e TCP_ENABLE_SACK=1 \
      -e TCP_GATE_LOG=off \
      -e WG_PRIVATE_KEY=<private_key> \
      -e WG_LISTEN_PORT=51820 \
      -e WG_MTU=1200 \
      -e WG_PEERS=0 \
      -e WG_PEER_0_PUBLIC_KEY=<public_key> \
      -e WG_PEER_0_ALLOWED_IPS=10.77.0.2/32 \
      --restart=no \
      ghcr.io/irctrakz/wgslirp:latest
   ```

3. **Configure Client**:
   Create a WireGuard client configuration:
   ```ini
   [Interface]
   PrivateKey = <client-private-key>
   Address = 10.77.0.2/32
   DNS = 8.8.8.8
   MTU = 1200
   
   [Peer]
   PublicKey = <your-public-key>
   Endpoint = <your-server-ip>:51820
   AllowedIPs = 0.0.0.0/0
   PersistentKeepalive = 25
   ```

4. **Verify Connection**:
   ```bash
   # Check router logs
   docker logs wgslirp
   
   # From client, ping through the tunnel
   ping 10.0.0.1
   ```

  Note: If you're not running with CAP_NET_RAW you can't ping, try a tcp connection

## Configuration

The router is configured primarily through environment variables:

### WireGuard Configuration

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `WG_PRIVATE_KEY` | Base64-encoded WireGuard private key (required) | - |
| `WG_LISTEN_PORT` | UDP port for WireGuard to listen on | 51820 |
| `WG_PEERS` | Comma-separated list of peer configurations | - |
| `WG_OVERLAY_ROUTING` | Enable overlay routing mode (1/true/yes/on) | - |
| `WG_OVERLAY_EXCLUDE_CIDRS` | Comma-separated CIDRs to exclude from overlay routing | - |

### System Configuration

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `DEBUG` | Enable debug logging (1/true/yes/on) | - |
| `METRICS_LOG` | Enable metrics logging | - |
| `METRICS_INTERVAL` | Interval for metrics reporting | 30s |
| `METRICS_FORMAT` | Format for metrics output (text/json) | text |
| `HEALTHCHECK` | Enable health checking | - |

### Environment Variables (reference)

Core WireGuard (required/primary)

- `WG_PRIVATE_KEY`: Base64 private key for the device (required).
- `WG_LISTEN_PORT`: UDP listen port, default 51820.
- `WG_MTU`: Plaintext MTU for the userspace TUN (default 1380).
- `WG_PEERS`: Comma-separated peer indices (e.g., `0,1`). For each index `i`:
  - `WG_PEER_i_PUBLIC_KEY`: base64 peer public key (required for each peer).
  - `WG_PEER_i_ALLOWED_IPS`: comma-separated CIDRs for overlay routing decisions.
  - `WG_PEER_i_ENDPOINT`: `host:port` (optional if static endpoint is used).
  - `WG_PEER_i_KEEPALIVE`: seconds (optional; typical 25).

Overlay routing (optional)

- `WG_OVERLAY_ROUTING`: enable overlay re-route for packets destined to AllowedIPs.
- `WG_OVERLAY_EXCLUDE_CIDRS`: CIDRs that should always egress via slirp.
- `WG_DISABLE_IPV6`: truthy to attempt disabling IPv6 sysctls (best effort).

Logging and diagnostics

- `DEBUG`: enable verbose logging and disable packet copy-elision in wrappers.
- `WG_DEBUG`: verbose wireguard-go logging (chatty).
- `WG_PCAP`: file path to write plaintext IPv4 frames (DLT_RAW) captured by the userspace TUN.
- `WG_PCAP_MAX_BYTES`: capture file size limit, including headers; defaults to 67108864 (64 MiB). Must be an integer of at least 24. Capture stops before a complete record would exceed the limit and stays stopped until process restart. Invalid values disable capture without touching the file. Forwarding continues when capture stops. Capture files use private permissions (0600).

Metrics and health

- `METRICS_LOG`: any non-empty value enables periodic metrics logging.
- `METRICS_INTERVAL`: duration like `15s` (default `30s`).
- `METRICS_FORMAT`: `text` (default) or `json`.
- `HEALTHCHECK`: any non-empty value enables one-time startup probes. These log results; they are not continuous readiness monitoring. Probes have five-second operation timeouts and are canceled and joined during shutdown.
- `HEALTH_HTTP_URL`: URL for the host-stack HTTP probe (default `https://httpbin.org/ip`). The final response must have a 2xx status.
- `HEALTH_DNS_NAME`: name for the host resolver probe (default `example.com`).
- `HEALTH_DNS_IP`: IPv4 DNS server for the slirp probe (default `1.1.1.1`). Success requires a complete response from the expected server to the probe's address/port, matching transaction ID and question, successful DNS status, and an A answer for `example.com` (including CNAME chains).

Socket lifecycle

Socket interfaces are single-use: configure the packet processor before `Start`, then call `Stop` to close connections and join accepted work. Repeated or concurrent `Stop` calls are safe; restart and writes after shutdown return errors. Processor replacement after startup is ignored with a warning. Create a new interface to change the processor or restart. Delivery callbacks must return promptly; shutdown waits for in-flight callbacks to complete.

Packet processing and TUN (userspace)

Guest IPv4 datagrams are validated before forwarding: header and total lengths must be consistent, TCP header offsets must fit, and UDP length must match the IP payload. Bytes beyond the declared IP length are ignored as padding. Incoming fragments are rejected because guest-fragment reassembly is not implemented; configure guest MTU accordingly. This does not disable fragmentation of synthesized host-to-guest UDP replies. Malformed packets return `socket.ErrMalformedPacket`; unsupported incoming fragments return `socket.ErrUnsupportedFragment`, available through `errors.Is`.

- `PROCESSOR_WORKERS`: number of workers in the socket processor (default 4).
- `PROCESSOR_QUEUE_CAP`: processor channel capacity (default 1000).
- `WG_TUN_QUEUE_CAP`: capacity of the WGTun outbound queue to wireguard-go (default 1024).
- `POOLING`: enable pooled buffers (1/true/on) for lower GC when throughput is high.

TCP slirp (userspace)

Resource controls are parsed once before socket startup. Invalid, empty, negative, or overflowing numeric values fail startup. The following environment settings override application defaults:

| Setting | Default | Meaning |
|---|---:|---|
| `TCP_FLOW_LIFETIME_SEC` | 120 | Idle TCP lifetime; zero uses the default. |
| `UDP_FLOW_LIFETIME_SEC` | 60 | Idle UDP lifetime; zero uses the default. |
| `TCP_REASSEMBLY_CAP_BYTES` | 131072 | Out-of-order storage threshold per TCP flow; zero uses the default. |
| `MAX_TCP_FLOWS` | 0 | Maximum registered TCP flows; zero is unlimited. |
| `MAX_UDP_FLOWS` | 0 | Maximum registered UDP flows; zero is unlimited. |

`TCP_ACK_DELAY_MS` defaults to 10; zero requests immediate ACK scheduling. Go callers should use `socket.DefaultConfig()` for defaults and set fields explicitly. The TCP bridge now honors these typed fields; it no longer reads `TCP_ACK_DELAY_MS` directly from the environment. Flow admission errors are available through `errors.Is(err, socket.ErrFlowLimit)`. Active-flow caps do not yet bound concurrent preliminary TCP dials or total buffering; those limits are separate follow-up work. Expiry is checked periodically, so removal can occur after the configured idle lifetime.

- `TCP_ACK_DELAY_MS`: delayed ACK timer (ms). Lower (e.g., 5) reduces ACK latency.
- `TCP_ENABLE_SACK`: advertise SACK permitted in SYN-ACK (recommended 1 for modern stacks).
- `TCP_MSS_CLAMP`: clamp advertised MSS (bytes). Leave unset unless troubleshooting PMTUD.
- `TCP_PACE_US`: microseconds to sleep between host→guest segments (0 disables). Use only when packet bursts cause loss/ECN on marginal paths.
- `TCP_GATE_LOG`: controls send-gating logs; `off` disables, `debug` logs at debug level, `info` logs at info level (default).
- `TCP_CC`: congestion control algo for host→guest path; `off` to disable, default newreno.
- `TCP_ERROR_SIGNAL`: how to signal outbound connect failure to the guest: `icmp` (default), `rst`, or `none`.
- `TCP_FAST_DIAL_MS`: fast pre-dial timeout (ms) to map immediate refusals to ICMP/RST without sending SYN-ACK first (default ~5ms).
- `TCP_SOCK_RCVBUF`, `TCP_SOCK_SNDBUF`: optional OS socket buffer sizes for host TCP connections.
- `TCP_ACK_IDLE_GATE_MS`, `TCP_ACK_IDLE_MIN_INFLIGHT`, `TCP_ACK_IDLE_FAIL_SEC`: advanced gating of host reads when no guest ACK progress. Defaults: `TCP_ACK_IDLE_GATE_MS=6000`, `TCP_ACK_IDLE_FAIL_SEC=120`; `TCP_ACK_IDLE_MIN_INFLIGHT` defaults to ~1 MSS when unset.

IP header synthesis

- `COPY_TOS`: truthy to copy DSCP/ECN from outbound to synthesized return packets.
- `IP_TTL`: override TTL for synthesized return packets (1–255; default 64).

Notes:
- Simple mode is always on: there is no FlowManager or egress limiter in the pipeline. Any legacy FLOW_* envs are ignored.
- `WG_TUN_ASYNC_WRITE` and related `WG_TUN_IN_*` knobs are ignored in simple mode.

### Performance Tuning (optional)

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `POOLING` | Enable pooled buffers to reduce alloc/GC (1/true) | off |
| `PROCESSOR_WORKERS` | Number of packet processor workers | 4 |
| `PROCESSOR_QUEUE_CAP` | Processor channel capacity | 1000 |
| `WG_TUN_QUEUE_CAP` | WGTun out queue capacity toward wireguard-go | 1024 |
| `TCP_ACK_DELAY_MS` | Delayed ACK timer (milliseconds) | 10 |

### Simple Mode

The router now always operates in simple mode: inline delivery, no FlowManager, no egress limiter. `SIMPLE_MODE` is treated as on by default and may be removed in future releases.

<!-- Auto-Fallback removed -->

### Metrics Reporter

Enable periodic metrics logs for visibility. Text or JSON formats are supported. Set either env to any non-empty value to enable.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `METRICS_LOG` | Enable metrics logging | - |
| `METRICS_INTERVAL` | Interval for metrics reporting (e.g., `15s`) | 30s |
| `METRICS_FORMAT` | `text` or `json` | text |

Selected counters (subset):
- Totals per bridge (packets/bytes/errors) and active flows.
- TCP extras: `rto`, `active_rto_flows`, `rto_delta`.
- Async dial/pending (tcp slirp): `dial_start`, `dial_ok`, `dial_fail`, `dial_inflight`, `pend_enq`, `pend_flush`, `pend_drop`.
- WG plaintext: `plaintext_from_wg`, `plaintext_to_wg`, `queue_drops`.


#### Tuning Example (docker-compose) with metrics enabled

```yaml
services:
  wg-router:
    image: wgserver:latest
    container_name: wgserver
    ports:
      - "51820:51820/udp"
    environment:
      - "POOLING=1"
      - "PROCESSOR_WORKERS=8"
      - "PROCESSOR_QUEUE_CAP=4096"
      - "WG_TUN_QUEUE_CAP=2048"
      - "TCP_ACK_DELAY_MS=5"
      - "METRICS_INTERVAL=15s"
      - "METRICS_FORMAT=json"
      - "DEBUG=0"
      - "WG_PRIVATE_KEY=<base64-private-key>"
      - "WG_LISTEN_PORT=51820"
      - "WG_MTU=1380"
      - "WG_PEERS=1"
      - "WG_PEER_0_PUBLIC_KEY=<base64-peer-public>"
      - "WG_PEER_0_ALLOWED_IPS=0.0.0.0/0"
    restart: "no"
```

These values have proven effective for high‑throughput, low‑latency operation on multi‑core hosts. Adjust upward/downward based on observed metrics (processor queue drops, Flow max_depth, WG queue_drops) and available memory/CPU.

### ICMP Privileges

ICMP echo and other raw ICMP operations require raw socket privileges (e.g., `CAP_NET_RAW`). In typical container environments without this capability, the router will silently drop ICMP packets from guests (logged at debug level) to avoid disrupting TCP/UDP traffic. If ICMP is required, grant the container appropriate capabilities or run outside a restricted environment.

**Note**: To disable metrics completely, ensure both `METRICS_LOG` and `METRICS_INTERVAL` are unset or empty. Setting either of these variables to any non-empty value will enable metrics reporting.

## Usage Examples

### Basic WireGuard Router

```bash
docker run --name wgslirp \
  -p 51820:51820/udp \
  -e POOLING=1 \
  -e PROCESSOR_WORKERS=8 \
  -e PROCESSOR_QUEUE_CAP=4096 \
  -e WG_TUN_QUEUE_CAP=2048 \
  -e TCP_ACK_DELAY_MS=5 \
  -e TCP_ENABLE_SACK=1 \
  -e TCP_GATE_LOG=off \
  -e WG_PRIVATE_KEY=<private_key> \
  -e WG_LISTEN_PORT=51820 \
  -e WG_MTU=1200 \
  -e WG_PEERS=0 \
  -e WG_PEER_0_PUBLIC_KEY=<public_key> \
  -e WG_PEER_0_ALLOWED_IPS=10.77.0.2/32 \
  --restart=no \
  ghcr.io/irctrakz/wgslirp:latest
```

### Docker Compose full example

```
version: "2.4"

services:
  wg-router:
    image: ghcr.io/irctrakz/wgslirp:latest
    container_name: wgslirp
    ports:
      - "51820:51820/udp"
    environment:
      - "POOLING=1"
      - "PROCESSOR_WORKERS=8"
      - "PROCESSOR_QUEUE_CAP=4096"
      - "WG_TUN_QUEUE_CAP=2048"
      - "TCP_ACK_DELAY_MS=5"
      - "TCP_ENABLE_SACK=1"
      - "TCP_GATE_LOG=off"
      - "WG_PRIVATE_KEY=<private_key>"
      - "WG_LISTEN_PORT=51820"
      - "WG_MTU=1200"
      - "WG_PEERS=0"
      - "WG_PEER_0_PUBLIC_KEY=<public_key>"
      - "WG_PEER_0_ALLOWED_IPS=10.77.0.2/32"
    restart: "no"
```

## Troubleshooting

### Common Issues

1. **Connection Failures**
   - Verify WireGuard keys are correctly formatted (base64-encoded)
   - Check that UDP port 51820 (or your configured port) is open in firewalls
   - Ensure peer endpoints are reachable

2. **Performance Issues**
   - Enable metrics logging to identify bottlenecks
   - Check for excessive connection counts or packet drops
   - Consider adjusting MTU settings if needed

3. **High CPU Usage**
   - This can be normal for high-throughput scenarios
   - Consider disabling debug mode in production

### Debugging

View logs with:

```bash
docker logs wgslirp
```

## License

This project is licensed under the Apache 2.0 - see the LICENSE file for details.

## Acknowledgments

- [WireGuard](https://www.wireguard.com/) for the secure VPN protocol
- All contributors to this project
