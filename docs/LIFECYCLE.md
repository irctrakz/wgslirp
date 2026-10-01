# Lifecycle and callback contracts

## Socket shutdown

Configure the processor before `SocketInterface.Start`. Instances are single-use;
`Stop` before startup also makes an instance terminal. Repeated/concurrent shutdown
is safe. Work admitted before shutdown is joined; new writes are rejected.

- `RequestStop()` closes public admission and returns a shared completion channel.
  Exactly one finalizer signals TCP cancellation and closes UDP/raw descriptors,
  removes flows, and joins accepted work. A delivery callback may call this method
  but must return without waiting for the completion channel.
- `StopContext(ctx)` requests the same shutdown and bounds the caller's wait by
  the context. A deadline error means cleanup is still pending; it does **not**
  mean callbacks were terminated or their buffers reclaimed. The completion
  channel closes after cleanup actually finishes. Retrying joins the same work.
- `Stop()` waits without a deadline, preserving the existing API and join contract.

These are additive methods on concrete types; existing core interfaces are unchanged.
The mock socket and mock TUN expose the same request/wait distinction. Mock TUN
shutdown also drains its receive queue. Processor replacement after startup is
ignored; use a new instance to change processors or restart. Mock histories are
detached byte copies, including snapshots returned to tests.

## Callback boundaries and ownership

Socket delivery is synchronous and can occur with a TCP flow's state lock held.
Processors must be concurrency-safe, return promptly, and avoid synchronous
re-entry into flow operations (`WritePacket`, flow resets, `DetailedMetrics`) or
blocking shutdown (`Stop`). `Metrics` and `RequestStop` are safe from a socket
callback. A callback must not wait on work that needs its current flow lock.
Schedule flow operations after returning, using an application-owned bounded
queue if such behavior is required. No goroutine is created for each delivery.

The production WireGuard sink copies into its bounded TUN queue and rejects
saturation without waiting for a queue slot. Optional packet capture performs
synchronous file I/O and can delay that callback; arbitrary custom callbacks and
blocked filesystems have no unconditional completion bound. A context timeout
bounds the shutdown caller's wait, not such I/O. Host TCP writes have a five-second
deadline **per write**, not a five-second guarantee for whole-interface shutdown.
Accepted queued packets remain owned by their downstream consumer until it
processes or drains them; stop that consumer too during application teardown.

Successful `ProcessPacket` transfers ownership; the consumer must eventually
release pooled packets. A rejection leaves release responsibility with the
producer (a synchronous consumer may already have released the packet).
`WritePacket` borrows until return; retained history/data must be copied. Mock
socket receive simulation transfers to its processor on success and leaves
ownership with its caller on rejection. A WireGuard processor without a TUN
rejects rather than silently accepting ownership.

## Adjacent lifecycle boundaries

`SocketPacketProcessor.Stop` joins workers and drains accepted queue entries.
Its synchronous `SocketWriter` must return and must not call `Stop` on the
processor executing that write. `WGTun.Close` closes queue admission, wakes
readers and drains unread frames; an already-dequeued read or synchronous write
retains its reservation until that operation returns. Close the owning
WireGuard device/join callers as well when waiting for complete teardown. These
existing contracts are covered by the processor and TUN lifecycle tests; the
new socket timeout API does not silently change their completion semantics.

## Flow identity and maintenance

TCP expiry, health resets, manual resets and RTO tracking retain the observed
flow pointer, not just its tuple string. Old readers/maintenance observations
cannot delete a replacement or its RTO tracking. Expiry and health predicates are
rechecked under flow state before removal, and reset methods return the number
actually removed. UDP removal already uses identity-checked registry operations.

Regression coverage lives beside the implementation: socket lifecycle/audit and
TCP concurrency tests, mock TUN lifecycle tests, processor ownership tests, and
WireGuard TUN concurrent read/inject/close tests. Run them with the race detector
inside a resource-contained Linux environment; broader integration checks also
exercise queue draining and shared-budget recovery.

## TCP FIN recovery

Host EOF closes the host-to-guest stream after all preceding host bytes have
been queued. It reserves one FIN sequence number and keeps both unacknowledged
data and the FIN recoverable. FIN retries use that same sequence number, with
an initial delay clamped to 200 ms–2 s and exponential backoff capped at 2 s.
Packet-budget or downstream refusal does not discard the FIN state. The existing
owned retransmission worker performs retries and close expiry; shutdown joins it.

A guest FIN is consumed only after its preceding bytes are accepted. Payload and
FIN can share a packet, including the handshake's third ACK. A duplicated payload
prefix does not hide a new trailing FIN. Future FINs are not consumed early:
admitted out-of-order data is retained and the peer must retransmit FIN after the
missing range arrives. Refused payload never advances the cumulative ACK or FIN.
Before an asynchronous dial completes, accepted data stays reserved in the pending
queue and is flushed before the host socket's write side closes.

| Event | Result |
|---|---|
| Host EOF first | FIN-WAIT-1; keep accepting guest data and retransmit unacknowledged output. |
| Guest ACKs the host FIN | FIN-WAIT-2; the guest may still send data. |
| Guest FIN first | CLOSE-WAIT; close only host write after accepted input drains, and continue forwarding/acknowledging the host response. |
| Host EOF after guest FIN | LAST-ACK; retry the host FIN until acknowledged, then remove the flow. |
| Both FINs before the host FIN ACK | CLOSING; wait for the host FIN ACK. |
| Active/simultaneous close completes | TIME-WAIT; release the host socket and retain tuple/ACK state for duplicate FINs. |

A half-closed flow expires after **two minutes without new accepted guest bytes
or cumulative ACK progress**, with a fresh deadline on a new FIN transition.
Duplicate ACKs, window-only updates and FIN retries do not extend that deadline.
Expiry records an error, logs the timeout, attempts a budgeted RST, and releases
the flow. Reset delivery is best-effort when the output budget/consumer refuses.
Healthy transfers that continue making progress are not cut off at a fixed age.

Normal TIME-WAIT is **four minutes**, using twice the two-minute MSL in
[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.6.1).
A matching duplicate FIN is ACKed and refreshes TIME-WAIT, capped at six minutes
from the last close progress/transition. This cap is a deliberate resource policy
for repeated control traffic; it does not promise unlimited linger extensions.
Ordinary idle expiry does not shorten close recovery or TIME-WAIT. Explicit
reset and shutdown still remove flows immediately.

TIME-WAIT records count against the existing TCP flow cap (64 by default), and
`ActiveFlows`/`ConnectionsClosed` retain their registry-membership meanings.
This increases slot retention for short-lived connections. The existing F03
capacity fixture measures persistent flows. F10 adds two 64-connection churn
batches with refusal and simulated-expiry recovery; see [RESOURCE_BUDGETS.md](RESOURCE_BUDGETS.md)
for the default cap's approximately 16 host-first closes/minute constraint. Larger
encrypted churn/soak sizing remains open in [RELEASE_VALIDATION.md](RELEASE_VALIDATION.md). No automatic tuple reuse or unlimited tombstone map
is introduced. Tests advance close deadlines explicitly rather than sleeping for
minutes, and real-socket fixtures verify loss recovery and both half-close orders.
