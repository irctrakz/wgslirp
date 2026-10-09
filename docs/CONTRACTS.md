# Runtime contracts

## Configuration and compatibility

Startup validates one environment snapshot before allocating resources. Supported
malformed or empty values fail with the setting name. There is no executable
JSON/YAML configuration-file or command-line override layer. Use the typed
configuration constructors and explicit environment parsers for Go callers.
Constructors copy retained configuration; do not mutate inputs concurrently.

Use DefaultConfig/DefaultDeviceOptions before overriding individual fields.
Hand-built socket configurations retain their documented zero-value semantics:
flow caps of zero are unlimited, while zero byte/dial limits select finite defaults.
IPV4_REASSEMBLY=false and POOLING=false are supported escape hatches. Pooling is
process-wide, frozen before first use; identical reconfiguration is safe and a
conflicting configuration returns an error. Legacy compatibility constructors
that cannot return errors warn and choose bounded defaults for invalid settings.

WG_DISABLE_IPV6 defaults to false. Explicit true retains legacy best-effort
namespace sysctl writes with nonfatal errors. It does not enable IPv6 forwarding
or grant privileges. Prefer externally managed namespace policy.

## Packet ownership

Published packet data is read-only for its entire ownership lifetime.
NewBorrowedPacket retains caller storage without copying: the caller must keep
that storage valid and unmodified until consumers finish. NewCopiedPacket takes
an independent snapshot. BorrowPacketData returns a view; CopyPacketData returns
an independent mutable copy. Copying does not release the source.

NewPooledPacket supplies explicit release ownership. A successful ProcessPacket
transfers ownership to its consumer; on rejection the producer releases it.
ReleasePacket is safe to repeat sequentially for built-in implementations, but
packet access and release must not race. Custom Packet implementations must
expose retained capacity for accounting. Data may expose capacity beyond payload
length; it remains read-only. Logging never changes aliasing or release behavior.

WritePacket borrows its input only until it returns. Fan-out needs an independent
copy before the first consumer can release the original. Each retained allocation
has one release owner and one live budget reservation. Generic packet constructors
do not automatically reserve the production socket budget.

The WireGuard TUN waits for its first queued packet, then drains ready frames up
to 128 without waiting to fill the batch. Each dequeued frame releases its
reservation after copy or rejection. Close releases remaining queued frames;
partial errors report the count already copied.

## Lifecycle and concurrency

Start/Stop and accepted work have explicit synchronization. Shutdown cancels
pending dials, wakes blocked workers and joins accepted goroutines before returning.
Flow registry insertion and retirement own admission slots. One pending-dial
reservation spans the fast wait and asynchronous continuation of the same dial;
there is no second speculative connection attempt.

TCP state, transmission and SACK synchronization have different responsibilities.
Keep documented lock ownership when editing helpers; apparent overlap is not
proof a lock is redundant. External delivery and release callbacks must respect
local lock contracts. Lifecycle, ownership, callback and cancellation regressions
remain beside their implementation packages so they can inspect private invariants.

## Resource bounds

Defaults are 256 registered TCP flows, 512 UDP flows, 64 pending dials, a 1024-frame
WireGuard queue and a shared 64 MiB live-storage budget. Per-flow bounds are
64 KiB pre-connect payload, 128 KiB out-of-order TCP storage and 1 MiB unacknowledged
TCP payload. These independent maxima cannot all be filled simultaneously.

TCP TIME-WAIT retains a registry slot for four minutes after active/simultaneous
close, with bounded extension on duplicate FINs. Host sockets and acknowledged
payload storage can be released earlier. Idle expiry is checked periodically.
Capacity planning must include active traffic, close rate and burst headroom.

Accounted bytes follow retained capacity and applicable metadata, not only payload
length. Reservations cover retained TCP/UDP buffers, scratch, synthesized replies
and downstream queues sharing the socket budget. Buffer refusal may decline a
packet, defer a host read or reset a flow whose accepted data cannot be retained.
Refusal responses are best effort and can themselves lack capacity.

Pooling caches supported synthesized packets through 16384 bytes, including
ACK/control packets. Larger allocations remain exact-sized. Idle packet-cache
retention is at most 960 KiB process-wide. UDP reply storage and IPv4 fragment
storage use their own allocation paths. Released live reservations do not imply
Go has returned heap pages to the OS. Kernel socket buffers, runtime overhead and
metadata need memory headroom beyond the accounted budget.

## Packet validation and fragmentation

IPv4 headers, declared lengths and applicable checksums are validated before
transport forwarding. IPv4 options are rejected. TCP sequence comparisons and
SACK recovery preserve wraparound and negotiation behavior. TCP receive windows
reflect bounded receive space; delayed ACKs, retransmissions and segmentation
must preserve the advertised window and negotiated MSS.

Incoming IPv4 reassembly is enabled by default and bounded independently by a
4 MiB fragment-storage cap, 32 datagrams per interface, eight per source IP and
128 ranges per datagram. Source-IP fairness is not authenticated-peer fairness.
The key includes source, destination, protocol and IPv4 identification.

Each assembly reserves 69631 bytes of worst-case storage/metadata up front.
Small assemblies start with 2048-byte storage and promote as needed. Small assembly
objects may be reused with an idle-plus-live ceiling of 32; promoted full buffers
are not retained in that cache. The fragment cap shares the socket budget.
Expiry is 60 seconds from first arrival; duplicates do not extend it.

Conflicting overlaps/final lengths, invalid alignment, malformed headers and
inconsistent fragment input are rejected. Transport validation follows completed
reassembly. Input is copied before WritePacket returns; completed reserved storage
is retained through synchronous dispatch. Expiry feedback runs outside the cache
lock before release. Shutdown joins expiry work and releases assemblies.
There is no completed-ID replay cache: late fragments can start a new incomplete
assembly, still bounded by quotas and expiry. Host-to-guest UDP replies can also
be fragmented. Disabling reassembly restores incoming-fragment rejection.

## Metrics and actionable diagnostics

JSON reports declare schema_version 1 and wg_available. Additive fields are
compatible; consumers must ignore unknown keys. A breaking schema change requires
a new version. Missing host statistics mean unavailable, not zero. Snapshots are
race-safe and detached, but are not a transaction across every counter.

Admission counters are cumulative attempted checks, not unique dropped packets.
Repeated SYNs or reservation retries are new attempts. Legacy counters overlap
new counters; do not sum them as independent loss. tcp_retransmit_waits counts
backpressure episodes rather than drops. IPv4 fragment counters distinguish
received, completed, duplicate, rejected and expired input with storage gauges.
Transport counters count completed datagrams; accepted TUN bytes include buffered
fragments. icmp_echo_limit counts outstanding echo quota refusals.

Known TUN errors log their first occurrence per fixed category and aggregate
repeats over 30 seconds, flushing quiet tails and shutdown. Unexpected errors
still log immediately. These counts describe write-error callbacks; WireGuard
may batch input, so they are not necessarily individual packet counts.

Accepted oversized packets increment packet_size.accepted_oversized with optional
debug logging. They continue processing; acceptance does not prove remote delivery.
Actual local rejection reports its reason. TCP recovery activity alone is not
connection failure: diagnose sustained lack of progress or consequential refusal.
CloseWrite outcomes add fixed TCP extended counters: close_write_disconnected
(ENOTCONN), close_write_local_shutdown (net.ErrClosed during recorded local
shutdown) and close_write_failed (other errors). JSON exposes these under tcp_ext;
text reports a tcp_shutdown line. Known teardown retains its error
result and the existing reset/removal/release behavior but emits only optional
debug logging and does not increment generic Errors. It does not prove graceful
completion. An unrecorded local close remains an error; payload-write errors are
unaffected. The legacy buffer_dropped counter still includes this abort path and
must not be added to shutdown counters as independent packet loss.

Capture failures stop capture while forwarding continues; captures have private
permissions and complete-record byte limits and do not reopen after exhaustion.

## Validation and release boundaries

Linux is the full acceptance target. Go CI checks build/vet, race-enabled unit
and integration suites and bounded fuzz targets. Encrypted workloads cover mixed
short requests, bulk and UDP, churn/capacity/TIME-WAIT, WAN loss/reordering,
sustained traffic and fragmented datagrams. Ordinary and race runs have finite
CPU, memory/no-swap, PID, temporary-storage and wall-clock limits plus cleanup gates.

The actual release-image fixture checks non-root startup, dropped capabilities,
read-only storage, encrypted TCP/UDP and echo, explicit feature opt-outs, denied
ping-socket policy and SIGTERM during traffic. Promotion copies the tested manifest
and verifies the digest without rebuilding. Candidate publication alone is not
acceptance. Arm64 runtime acceptance and production WAN capacity are not implied
by Linux/amd64 bounded fixtures.

Automatic master/latest publication is suspended during curated integration.
A stable release policy requires separate review; integration promotion only
creates a development tag and leaves latest unchanged.

Independent fault controls in tools/ci deliberately mutate disposable copies and
require specific assertion failures and cleanup. They run separately from release
gates. No finite suite proves every deployment or unlimited duration/capacity.
