# Explicit packet ownership

Packet bytes are read-only once published. Copying/borrowing and ownership transfer
are separate decisions: a no-copy wrapper does not make caller-owned storage safe
to reuse while an asynchronous consumer still holds it.

| API | Contract |
| --- | --- |
| `core.NewBorrowedPacket(data)` | No copy. Caller keeps storage valid and unmodified until all consumers finish. |
| `core.NewCopiedPacket(data)` | Independent snapshot; caller can immediately reuse its input. Packet access remains read-only. |
| `core.BorrowPacketData(packet)` | Read-only view for the ownership lifetime; no diagnostic copies for built-in packets. |
| `core.CopyPacketData(packet)` | Independent mutable bytes, valid after the original is released. Does not release the original. |
| `core.NewPooledPacket(data, release)` | Transfer immutable storage with an optional release callback; accepted consumers eventually call `ReleasePacket`. |

All explicit APIs have the same ownership behavior with debug on or off. Custom
`Packet` implementations supply `Data()` as a borrowed read-only view, valid
for their ownership lifetime, exposing retained capacity for buffer accounting.
Copying is explicit through `CopyPacketData`.

## Transfer and retention

[IPv4 reassembly](IPV4_FRAGMENT_REASSEMBLY.md), enabled by `DefaultConfig`, copies fragment payloads
before `WritePacket` returns. Completion passes the same reserved allocation to
synchronous transport dispatch; it remains charged until dispatch returns.
Expiry detaches entries under the cache lock, delivers feedback outside that lock
and then releases ownership. Joined shutdown releases any remaining cached entries.
Released small assembly objects can be reused only after that boundary; full-size
promoted payloads are never cached. The bounded idle-object cache is described in
[allocation accounting](REASSEMBLY_ALLOCATION_CHURN.md#released-object-reuse-during-default-policy-validation).

`WGTun.Read` copies queue-owned frames into WireGuard-owned buffers at the supplied
offset. It waits for the first frame, then drains only already ready frames up to
128, with no delay to fill a batch. Each dequeued frame releases its reservation
after copying or local size rejection. A partial error reports the number already
copied; Close releases every frame not dequeued. Batching does not transfer the
queued allocation to WireGuard or change packet ordering, queue caps or byte
metrics, which count successful enqueue rather than read completion.

Successful `ProcessPacket` transfers ownership. On rejection, the caller retains
release responsibility; sequential repeated release of built-in pooled packets
is harmless. Access/release must not race: these are single-owner packets, not
reference-counted objects. `WritePacket` borrows only until return.

For asynchronous work with a reusable receive buffer:

```go
packet := core.NewCopiedPacket(receiveBuffer[:n])
if err := consumer.ProcessPacket(packet); err != nil {
    core.ReleasePacket(packet)
}
// receiveBuffer can be reused immediately: packet owns a separate snapshot.
```

For synchronous writing of a newly built packet:

```go
err := writer.WritePacket(core.NewBorrowedPacket(wire))
// wire can be reused after WritePacket returns.
```

Fan-out must copy before the first consumer can release the original. Give each
independently retaining consumer its own packet/storage; do not share a pooled
packet across owners. Health fan-out snapshots the observer packet before primary
delivery. The health sink copies retained bytes and releases accepted input even
when its bounded queue is full. ICMP sequence/checksum edits finish in the owned
builder before the result is published as a packet.

## Interfaces and budgets

`Packet.Data()` returns a borrowed read-only view. The explicit access helpers
make borrowing versus independent copying apparent at call sites. Debug logging
has no ownership side effects. Legacy constructors, debug-mode state and
configurable wrapping have been removed; see [migration](API_MIGRATION.md).

General-purpose constructors do not reserve application byte budgets. Production
forwarding must continue reserving capacity before allocation and attaching its
release callback, as described in [RESOURCE_BUDGETS.md](RESOURCE_BUDGETS.md).
These APIs do not authorize bypassing queue/admission limits or retaining borrowed
storage past release. Tests cover aliasing, detached copies, retained capacity,
fan-out, rejection, queue saturation and pooled release.
