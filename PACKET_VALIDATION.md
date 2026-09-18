# Guest packet validation and supported scope

The socket boundary consumes complete IPv4 packets with finalized checksums.
`SocketInterface.WritePacket` and the direct TCP/UDP/ICMP bridge entry points
reject invalid input before dialing, retaining payloads, writing to a host socket,
or generating a network response. Errors are returned to the caller; socket-level
rejections increment the existing error metric. Input slices are not modified.

## Supported and rejected packets

| Boundary | Policy |
| --- | --- |
| IPv4 lengths | Version 4, at least 20 header bytes, declared length at least the header length and no larger than supplied data. Trailing link padding is ignored. |
| IPv4 checksum | Validate the entire declared header, including any options, before transport parsing. |
| IPv4 options | Reject every IHL greater than 5, including NOP/EOL-only padding, source routes, timestamps, unknown and malformed options. Host socket forwarding cannot preserve their semantics. TCP options are separate and remain supported by the existing TCP implementation. |
| Incoming fragments | Reject MF or any nonzero fragment offset, including first fragments. DF alone is permitted; the reserved flag is malformed. No incoming fragment cache or reassembly is provided. |
| TCP | Validate data offset and checksum over the complete TCP header/options/payload and IPv4 pseudoheader. TCP checksum omission is not supported. |
| UDP | Length must equal the IP payload length and include at least eight header bytes. Validate nonzero checksums, including the pseudoheader. Accept zero as IPv4 checksum omission. Synthesized UDP packets encode a computed zero as `0xffff`. |
| ICMP | Require at least eight bytes and validate the whole ICMP message checksum, without an IP pseudoheader. Raw-socket availability remains a separate capability requirement. |

`errors.Is` identifies `socket.ErrMalformedPacket`,
`socket.ErrInvalidChecksum` (also an `ErrMalformedPacket`),
`socket.ErrUnsupportedIPOptions`, and `socket.ErrUnsupportedFragment` through
caller wrapping. Structural IP errors and fragment rejection precede checksum
checks; an invalid IP checksum precedes the unsupported-option error. Callers
must not rely on a particular error when several independent defects coexist.

Checksum behavior follows [RFC 1122 sections 3.2.1.2 and 4.1.3.4](https://www.rfc-editor.org/rfc/rfc1122.html)
and [RFC 9293 section 3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1).
The option and fragment restrictions are deliberate limits of this socket proxy,
not a claim of complete IP-host compliance.

## Compatibility and deployment

Previously accepted packets with corrupt or unfinished checksums, or any IPv4
options, are now rejected. There is no validation-disable configuration. Callers
must finalize checksums before submission; this API carries no checksum-offload
metadata. IPv4 UDP's explicit zero-checksum encoding remains accepted.

Incoming fragment reassembly remains intentionally unsupported: no supported
workload currently justifies a fragment cache, overlap policy, timers and new
resource admission controls. Configure guest MTU and application datagram sizes
to avoid guest-originated fragmentation. Fragmentation of synthesized UDP replies
toward the guest remains supported and budgeted; the guest reassembles those.

## TCP sequence wrap and out-of-order data

In-order payload and FIN/cumulative-ACK sequence arithmetic can cross zero. The
out-of-order receive queue uses numeric ranges within a single sequence epoch.
It refuses a future segment that crosses zero or starts after zero while the
missing range is still before zero. Refusal retains no payload or reservation and
sends the unchanged cumulative ACK; the peer must retransmit when the bytes are
in order. A queued pre-wrap segment overtaken by in-order progress is released.
Ordinary bounded out-of-order reassembly resumes after wrap. This is not a claim
of comprehensive wrap support in the SACK/recovery algorithms.

## Verification

Regression tests cover checksum corruption at public and direct bridge boundaries,
odd payloads, pseudoheader corruption, UDP zero/all-ones checksums, TCP options,
trailing padding, rejected IP options/fragments, no rejection side effects, and
wrap refusal followed by exact in-order delivery with released reservations.
`FuzzTransportBoundaries` exercises both raw bytes and checksum-repaired copies
to reach deeper parsing paths, checking accepted lengths, flags, checksums and
input immutability. Fuzzing is bounded evidence, not exhaustive proof.
