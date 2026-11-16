# wgslirp helper protocol version 1

Status: approved v1 protocol baseline. The Go implementation is
`cmd/wgslirp-helper`.

Launch `wgslirp-helper` with redirected standard streams to open a session.
`wgslirp-helper --version` prints the binary version followed by a newline and
exits before opening a session or acquiring network resources.

The controller owns persistent configuration. One helper process owns one runtime
and its active state. The initial forwarding profile maps configured IPv4 TCP
destinations to host IPv4 TCP destinations and denies all other guest traffic.

The [message schema](../protocol/v1/message.schema.json) specifies message shapes.
This document specifies framing, sequencing and semantic checks that JSON Schema
cannot express. Both are part of the contract. The shared
[compatibility fixtures](../protocol/v1/README.md) exercise those rules.

## Transport and limits

- Redirect stdin for requests and stdout for responses. Reserve stderr for
  diagnostics. Write exactly one UTF-8 JSON object per line. Emit LF, accept LF
  or CRLF, and count at most 65,536 payload bytes before the line ending. Use
  strict JSON with no BOM or duplicate object keys at any depth. Require valid
  UTF-8 and paired Unicode surrogates in strings. Allow at most 16 nested
  objects/arrays including the root. Object order has no meaning.
- Use case-sensitive names. Close all v1 message objects to unknown properties.
  The protocol version list and capability names are extension points. Add a new
  protocol version for changes to the v1 wire shape. The independent binary
  version identifies an artifact and does not determine protocol compatibility.
- Write JSON integers as unsigned decimal digits with no sign, fraction,
  exponent or leading zeros (except `0`). IDs, revisions and other general
  integer values fit in the exact JSON range up to `9007199254740991`. Transfer
  and refusal counters are canonical decimal strings from `0` through
  `18446744073709551615` so they retain full uint64 precision.
- Process requests in arrival order with at most one executing and one queued.
  Emit one correlated response per accepted request unless shutdown interrupts
  it. The controller normally
  sends one request at a time. It may queue one `status` behind a timed-out peer
  mutation to reconcile it. There are no unsolicited status updates.
- Bound input and output to the same frame size. The helper must continue to
  detect stdin EOF while a request is executing. Use bounded response buffering
  off the forwarding path. A broken stdout or a write stalled for 5 seconds
  triggers shutdown, rather than allowing a blocked controller to hold the
  helper indefinitely.
- EOF at a line boundary triggers cleanup and exit without a reply. An
  incomplete final line, malformed frame, oversized frame or queue overflow is
  terminal and exits nonzero. The corresponding diagnostic is
  `invalid_frame`, `frame_too_large` or `queue_full` when it can be delivered.
- Report `frame_too_large` as soon as the payload exceeds 65,536 bytes,
  without waiting for LF or EOF. At the limit, a following CR can still be
  part of CRLF. Wait for the next byte or EOF to decide. If LF follows, the
  CR is part of the delimiter. Otherwise the CR counts toward the payload
  and the frame is oversized. EOF with a nonempty unfinished frame within
  the limit is `invalid_frame`. EOF with no buffered bytes is clean.

EOF, a terminal framing or queue error, and stdout failure all close admission
to new requests and new forwarding work. At that point, discard queued requests
and cancel the executing request, if any. Serialize this transition with
publication of readiness, peer revisions and correlated responses. Once shutdown
has begun, the interrupted request cannot publish a new runtime or revision or
send a correlated response. A response whose terminating LF was already written
remains valid. If shutdown interrupts a write after a prefix has reached stdout,
stop writing and close stdout. Do not complete that response, add a newline, or
append a terminal frame. The controller discards the unterminated prefix on EOF
and treats the pending request outcome as uncertain. An interrupted output
frame is a pipe failure and exits nonzero.

An executing operation may already own resources or have changed the device.
Wait for it to relinquish those resources before finishing teardown. If an
underlying call cannot be cancelled, keep forwarding closed, let the call finish
as part of teardown, and close its resources without publishing the result.
Tear down the entire runtime, including partial startup and any peer work. The
10-second shutdown limit covers both waiting for the interrupted operation and
cleanup. EOF at a line boundary exits zero after cleanup. A fatal pipe or protocol
error exits nonzero, as does shutdown exceeding the deadline.

Choose the terminal diagnostic after cleanup completes or the shutdown deadline
expires. If the deadline expires, `shutdown_timeout` takes precedence over
the initiating error, including `queue_full`. Attempt at most one diagnostic
frame, only when stdout is usable and at a frame boundary. If it cannot be
delivered, exit nonzero without a complete diagnostic. The controller must
observe process exit even when no diagnostic arrives.
The Go helper bounds its final stdout attempt to one second, reserving time
within the controller's shutdown grace period for the process to exit.

## Session and response rules

The controller sends `hello` first, with ID `1` and an array of distinct
supported protocol versions. This bootstrap request has no `instance_id`.
The helper selects the highest common version. A successful response includes
the selected version, binary version, OS, architecture and capability list.
Use Go target names for `os` and `arch`, such as `linux` and `amd64`.
The bootstrap envelope and `unsupported_version` error apply even when no
version is shared. On no match, return that error and exit without opening
network resources. A first frame other than a well-formed `hello` is a terminal
`invalid_frame`.

Every response carries an opaque `instance_id`, generated from 128 random bits
as 32 lowercase hex digits and stable for the life of the process. Every
post-handshake request must echo it. A controller discards responses from an
unexpected instance and never reuses configuration state across instances.

Request IDs must increase strictly for the session and may skip values. A
well-framed object with a valid `id` and `op` consumes its ID even if the
request is later rejected. An ID at or below the last consumed ID returns
`duplicate_id` and never replays or re-executes the request. A post-handshake
frame without a valid ID and operation token is terminal `invalid_frame`.

Each correlated response echoes `id` and `op` and includes `instance_id`,
`revision` and `ok`. A success has `result` and an error has `error.code`.
The helper does not return raw decoder errors or arbitrary messages. Rejections
carry the current revision. The error codes are stable machine-readable values.

After the handshake, apply these checks in order and return the first failure.

1. Require a valid `id` and `op` token or terminate with `invalid_frame`.
   Return `duplicate_id` for an ID at or below the high-water mark. Otherwise
   consume the ID before performing any remaining checks.
2. Validate the generic envelope. It must contain exactly `id`, `op`,
   `instance_id` and `params`. The instance ID must be well formed and
   `params` must be an object. Reject a fresh post-handshake `hello` here as
   well. Any failure in this step returns `invalid_request`.
3. Compare the instance ID and return `wrong_instance` on a mismatch.
4. Recognize the operation and check its advertised capability. Return
   `unknown_operation` or `unsupported_capability` as appropriate.
5. Validate the operation-specific contents of the `params` object. Return
   `invalid_request` for the wrong shape.
6. Check runtime state, then the expected revision if present. Return
   `invalid_state` or `revision_conflict` as appropriate.
7. Check operation-specific semantic values, then conflicts and capacity.

The request schema describes accepted shapes. It cannot select an error for a
rejected request. For example, an unknown operation with `params: null` fails
the envelope check. With `params: {}` and the correct instance, it fails the
operation check.

The revision starts at `0` with no runtime. Successful `start` sets it to `1`.
Each successful peer addition or removal increments it once. Validation, status
and stop do not increment it. All operations, including status, are ordered
with mutations. A controller can compare an authoritative status snapshot with
its desired state before deciding whether another mutation is needed.

| Operation | Required capability | State | Result on success |
| --- | --- | --- | --- |
| `hello` | Bootstrap | Before negotiation | Negotiated version, binary version, OS, architecture and capabilities |
| `validate` | `restricted_tcp` | Idle or running | Empty result after checking the full candidate configuration |
| `start` | `restricted_tcp` | Idle | Bound UDP port and server public key, with revision `1` |
| `status` | Core | Idle or running | Snapshot of the current state, including applied peers |
| `peer_add` | `live_peers` | Running | Empty result with new revision |
| `peer_remove` | `live_peers` | Running | Empty result with new revision after revocation and cleanup |
| `stop` | Core | Idle or running | Empty result after cleanup, followed by exit |

A usable v1 helper advertises `restricted_tcp`. The `live_peers` capability
enables both peer operations. Controllers ignore unknown capability names and
check required capabilities before sending keys. The early integration helper
can omit `live_peers` until it implements the full revocation contract.

`start` succeeds only after the configuration is applied and the WireGuard UDP
listener is operational. This reports local readiness. A launch can still need
external firewall, endpoint or port publication configuration. A configuration
that fails semantic validation leaves the process idle and returns
`invalid_config`. If runtime construction fails after validation, finish cleanup,
return `start_failed` with a required `error.reason` and exit nonzero. Classify
startup errors using the underlying platform error where available.

| Startup reason | Meaning |
| --- | --- |
| `address_in_use` | The UDP listener could not bind because the address or port is occupied. |
| `permission_denied` | A startup operation failed because the platform denied access. |
| `other` | The failure could not be classified as either of the above. |

The reason is a fixed token. Use `other` when classification is unavailable.
The controller can select a user-facing message without parsing stderr.

Successful `stop` responds only after runtime cleanup is complete,
then exits zero. A terminal operation drops queued requests. If cleanup cannot
finish within 10 seconds after shutdown begins, apply the terminal diagnostic
and exit rules above.

## Restricted configuration and status

`validate` and `start` accept the same configuration. Validation is local and
side-effect free. It never binds a listener, probes a host or resolves DNS.
Use `invalid_config` for semantically invalid values that pass schema checks.

- Supply a server private key and distinct peer public keys in canonical padded
  standard Base64, each encoding a nonzero 32-byte value. A peer has one
  canonical dotted-decimal IPv4 source address, configured as its sole `/32`.
  Reject a peer key equal to the server public key, duplicate keys or addresses,
  and overlap with any virtual service IP.
- Require dotted-decimal IPv4 with no leading-zero octets. For configured IPs,
  reject `0.0.0.0/8` and `224.0.0.0/3`. Loopback is permitted only on the host
  side of a mapping. Reject duplicate guest `(IP, port)` pairs with
  `invalid_config`, whether their host targets match or differ.
  Require at least one mapping, cap the configuration at 32 mappings and
  permit up to 128 peers. Configure peers as passive listeners on the server
  side. The client specifies the public WireGuard endpoint separately.
- The server listens on UDP. Omit `listen_port` for `51820`, or supply `0`
  to request an ephemeral port. Successful startup reports the actual bound
  port, which must equal the requested or default port unless the request
  supplied zero. It also reports the WireGuard public key derived from the
  supplied private key. Running status repeats both values.
  The plaintext MTU accepts `576`–`9000` bytes and
  defaults to `1380`.
- Omitted resource limits use the defaults in the schema. Apply finite limits
  for TCP flows, concurrent pending TCP dials, shared socket buffer bytes and
  TUN queue packets. Other transport settings use the helper's core defaults.
  The restricted profile disables overlay forwarding, guest ICMP echo, packet
  capture and direct egress probes. Retain the guest-visible address in replies.
- Server key, listener, MTU, mappings and resource budget changes require a new
  helper process. Only the peer set changes in a running v1 session. Peers can
  be imported by public key in v1. Key generation for later provisioning needs
  a separately specified operation.

Status always includes state, listener port, server public key, uptime, applied
peers and counters. For `idle`, the listener port, server key and metrics are
`null`, uptime is zero, and the peer list is empty. For `running`, the listener
port and server public key match the successful `start` response for the life
of the process. Uptime is milliseconds since runtime
readiness measured with a monotonic clock. Order peers by public key using ASCII
order. The applied peer list is authoritative even when per-peer telemetry is
unavailable. If that list cannot be established safely, fail the session with
`runtime_state_uncertain`.

Each peer reports its assigned address and most recently observed WireGuard
endpoint (`IPv4:port` or `[IPv6]:port`, with a scope zone when present), handshake
timestamp (whole Unix seconds) and transfer counters. Use `null` for unavailable
observations. A peer without a completed handshake has a null handshake.
`rx_bytes` and `tx_bytes` are cumulative WireGuard counters from
the helper's perspective, received from and sent to the peer, respectively.
They reset on runtime replacement or peer recreation. Zero is a known value.

Runtime metrics report current registered TCP flows (including TIME-WAIT),
current shared buffer reservations in bytes, and cumulative refusal counters
for flow limits, pending dials and aggregate buffer limits. Refusal counters
reset with the runtime. A running helper may return null metrics if collection
is unavailable. Status and logs never contain raw WireGuard UAPI data, private
keys, request bodies or packet payloads. Pass private configuration over the
control pipe, keeping it out of the command line and environment.

## Peer updates and recovery

Both peer operations include `expected_revision`, the controller's last known
applied revision. A mismatch returns `revision_conflict` before any side effects.
`peer_add` takes a peer record. A peer key equal to the server public key or
an address used by a virtual service returns `invalid_config` before conflict
or capacity checks. Return `peer_conflict` if
its public key or source address is in use or its address was previously
revoked in this process.
To avoid reassigning queued traffic in v1, restoring a revoked address requires
replacing the helper.
Keep up to 1,024 distinct assignments (active or revoked) per process. The
controller persists its own allocation history across process replacement.
Exceeding either the assignment limit or 128 active peers returns `peer_limit`.
`peer_remove` takes the public key and returns `peer_not_found` if absent.
Invalid peer keys or source addresses return `invalid_config` after the
payload shape has been checked. `peer_conflict` and `peer_limit` apply only
to addition. `peer_not_found` applies only to removal.

Successful removal means the peer cannot admit new traffic, its WireGuard entry
is gone, and its existing flows, pending dials and fragment state have been
cleaned up. An operation that fails with the prior state verified intact returns
`peer_update_failed`. If the helper cannot establish which policy is active
after an update, stop forwarding and terminate with `runtime_state_uncertain`.
Do not claim a revision or successful cleanup that cannot be confirmed.

The controller bounds each request write to 5 seconds and starts a response
deadline when the full line has been written. A failed or timed-out write can
leave a partial frame. Close stdin and reap the helper before replacing it.
Use 5 seconds for `hello`, `validate` and `status`, 15 seconds for `start`, and
10 seconds for peer updates. Allow 15 seconds for `stop` to accommodate cleanup
and the response write. A response deadline is a controller-side wait
limit. It does not cancel or roll back a request. On a peer update timeout, keep
the original ID reserved and send one `status` with a higher ID. Allow that
status up to 15 seconds because it can queue behind the mutation. Read both
responses by ID. The mutation reply precedes the queued status reply. Require
the status revision to match the revision reported by the mutation reply.
A rejected mutation reports the current helper revision, which may differ
from the request's expected revision.

Use the mutation reply to determine whether this request applied. Use the
status peer set to determine whether the desired state holds. A successful
addition must appear with the requested address, and a successful removal
must be absent. A rejection does not establish the desired state. For example,
`peer_not_found` leaves the peer absent without applying a new removal. Send
no further requests until both checks are complete. Use the reconciled
revision and peer state to decide whether another mutation is needed.

If reconciliation fails, times out, or the pipe becomes unusable, close stdin
if still open and reap the helper before replacing it from durable desired
state. A terminal session error or unexpected process exit during
reconciliation counts as failure, even without a correlated reply. A terminal
session error or stdout failure can close request admission while the
controller's stdin pipe is still open. Closing that pipe afterward preserves
the failure outcome. The controller can close its end after observing process
exit. Both pipe closure and reaping must be complete before replacement.
For other control timeouts, close stdin and reap the helper before replacing it.
After closing stdin on failure, allow up to 15 seconds for the helper to exit, then
terminate the owned process if it is still running. Wait for confirmed exit
and reap the process after termination before starting its replacement.

| Correlated error | Meaning |
| --- | --- |
| `unsupported_version` | The bootstrap version sets have no intersection. The helper exits. |
| `duplicate_id` | The request ID was already consumed or fell below the high-water mark. |
| `invalid_request` | The correlated envelope or known payload has the wrong shape. |
| `wrong_instance` | The instance ID belongs to another process. |
| `unknown_operation` | The operation token is unrecognized. |
| `unsupported_capability` | The operation requires a capability that was not advertised. |
| `invalid_state` | The operation is unavailable in the current state. |
| `invalid_config` | Configuration or peer values fail semantic validation. |
| `start_failed` | Validated startup failed. The required `reason` identifies the failure category. The helper exits after cleanup. |
| `revision_conflict` | The expected revision is stale. Refresh status before deciding what to do. |
| `peer_conflict` | The key or address is assigned or the address was revoked in this session. |
| `peer_limit` | The active peer or process assignment limit was reached. |
| `peer_not_found` | The requested public key is absent. |
| `peer_update_failed` | A `peer_add` or `peer_remove` failed to apply with the prior state verified intact. |

`session_error` frames are terminal and carry one of `invalid_frame`,
`frame_too_large`, `queue_full`, `runtime_state_uncertain` or `shutdown_timeout`.

The wire format uses [JSON (RFC 8259)](https://www.rfc-editor.org/rfc/rfc8259).
Message definitions use [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12).
