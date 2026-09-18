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
