# TCP receive recovery and advertised capacity

The bridge advertises receive space bounded by `TCP_REASSEMBLY_CAP_BYTES`, rather
than always encoding 65,535 under the default scale of seven (almost 8 MiB).
The default cap remains 128 KiB. `TCP_WS_OUT` sets the preferred encoding scale,
not additional buffer capacity; small caps lower the scale to keep a nonzero
window. Peers without window scaling receive at most 65,535 bytes of advertised
space. SYN windows are unscaled. Peer scale values are clamped to 14 and an
offered scale of zero still participates in negotiation.

The receive window is a fixed span ahead of the cumulative ACK. Buffered future
bytes occupy that span; they are not subtracted from its width, which would
retract its right edge while the missing bytes still need recovery. Header
quantization rounds capacity down. ACK, data, retransmission, FIN and reset paths
encode the same window, computing checksums once inside the existing packet
reservation before transfer. No lock or buffer ownership changes are required.

With peer SACK permission, immediate and delayed control ACKs also report up to
four retained out-of-order ranges, most recently received first. Refused bytes
are never selectively or cumulatively acknowledged. The legacy forced sender
SACK setting cannot grant receiver permission on the peer's behalf. Existing
storage/aggregate admission limits and the bounded numeric sequence-epoch queue
remain independent defensive checks; this is not a promise that arbitrary peers
honor advertised capacity or that host sockets cannot apply backpressure.

Focused tests validate wire checksums, negotiation including absent/zero/invalid
scales, tiny caps, consistent packet windows, retained-byte feedback, quota
refusal and wrap edges. Disposable negative controls detect missing SACK and the
previous oversized advertisement. Independent-stack encrypted acceptance uses
the unchanged [unpaced workload gates](UNPACED_FRAGMENT_ACCEPTANCE.md).

References: [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018.html#section-4),
[RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2).
