# Bounded encrypted fragment evidence

Status: acceptance pending. Default enablement remains separate from this test change.

## Profile and preselected gates

`TestEncryptedFragments` uses tags `integration,mixed,fragments,linux`. CI runs
fresh ordinary and race containers sequentially, using the existing 1 CPU,
2 GiB/no-swap, 128-PID, read-only, dropped-capability, bounded tmpfs/log and
600-second container deadline. Go's test deadline is 300 seconds. Container
memory/PID events must remain zero; owned container/image removal and absence
checks remain mandatory. The private SSH server is unused.

- Independent gVisor guest TCP stack: 128 short requests, two bulk connections
  checking 8 MiB in each direction, and 512 UDP round trips concurrently. A
  test-only guest TUN splits large TCP packets into at most 1200-byte IP fragments,
  duplicates the initial range, reverses subsequent ranges and deliberately
  drops one range from each of two packets. TCP must recover through its own
  retransmission behavior; exact host/guest payload checks remain unchanged.
- Raw guest datagrams cross actual WireGuard encryption/decryption and production
  reassembly. Check 48 UDP datagrams of 8192, 16384 and 65507 payload bytes, using
  legal aligned fragments at MTUs 1200 and 1380. Host checks the entire payload;
  a small digest reply verifies the encrypted return path. This deliberately
  avoids requiring a second fragment reassembler as the test oracle.
- A late noninitial fragment replay after completion starts a bounded incomplete
  assembly; an exact repeat cannot extend its fixed lifetime. A separate UDP
  range is lost: no partial datagram may reach the host. Both assemblies must
  expire naturally, and the lost datagram must work when retried afterward.
- Two global-quota cycles: four sources retain eight incomplete datagrams each.
  A ninth for an already-full source increments only `source_limit`; a fresh
  source increments only `global_limit`. Completing one existing assembly must
  release its slot and admit the previously refused source. Its allocation cannot
  evict existing assemblies. All remaining 32 assemblies must expire each cycle.
- Ordinary encrypted TCP and UDP must progress while partial assemblies occupy
  the global quota, and after every expiry cycle. All fragment reservations and
  aggregate reservations must return to zero on joined teardown. Worker counts
  must return within four of the initial baseline within five seconds.

Sample heap/RSS every 100 ms during mixed traffic and on every ordinary round
during expiry. Ordinary bounds: 192 MiB sampled heap, 384 MiB sampled RSS; race
bounds: 256 MiB heap, 768 MiB RSS. Both permit at most 512 goroutines. Report
allocation bytes/objects and natural GC cycles, with three idle observations
after teardown. No forced GC, scavenging or runtime-limit changes are allowed.
Reservation recovery is asserted; RSS returning to its cold baseline is observed,
not assumed. Limits are fixed before acceptance and are distinct from the
actual release image's existing 256 MiB runtime validation profile.

## Fairness scope and counters

Sources are distinct allowed IPv4 addresses behind one encrypted peer; this tests
IP-source fairness, not authenticated-peer fairness or isolation. Quotas admit in
arrival order: a source can occupy at most eight of 32 live slots, while four
sources can collectively deny further fragmented admission until a slot is freed.
Unfragmented traffic and fragments of already-admitted assemblies bypass *new*
fragment-slot admission. Byte and aggregate budget checks still apply.

The fixed diagnostic map adds `source_limit`, `global_limit`, `storage_limit`,
`aggregate_limit`, `live_peak` and `source_peak`. Exactly one new-admission
reason is counted per refused attempt, in source/global/storage/aggregate order.
`rejected` still includes all fragment failures. Successful or rejected assembly
completion releases ownership after transport dispatch; timeout feedback runs
outside the cache lock. No addresses or dynamic labels appear in production metrics.

Expected quota totals on the datagram interface: `live_peak=32`, `source_peak=8`,
`source_limit=2`, `global_limit=4`, and `expired=66`. Other mixed-interface partial
assemblies are released by joined shutdown and do not count as timeout expiry.

## Acceptance and default-policy decision

Record runtime, allocation/RSS, counter and owned-cleanup evidence here before
marking this profile accepted. Review the measured arrival-order fairness limit
and workload scope explicitly. A separate default-policy commit must preserve
`IPV4_REASSEMBLY=false`, verify the normal default-enabled image startup path and
the explicit disabled image path, and pass the unchanged full pipeline. There is
no claim of production capacity, authenticated-peer scheduling fairness or
successful UDP delivery when an actual fragment is lost.
