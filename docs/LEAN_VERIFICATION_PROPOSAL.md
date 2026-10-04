# Deferred Lean verification proposal

Status: deferred at user request on 2026-10-04. This is a proposal, not an
implemented verification gate or a claim that the Go implementation is proved.

## Proposed pilot

Start with TCP sequence arithmetic and ACK/SACK recovery. Use Lean fixed-width
bitvectors to represent 32-bit arithmetic, with the half-sequence-space window
assumptions explicit. Prove interval/comparison behavior across wrap, that SACK
alone does not release payload ownership, that cumulative ACKs release only
acknowledged bytes, and that stale SACK state cannot exclude an expired oldest
segment from retransmission. State delivery and scheduling fairness assumptions
separately for eventual recovery; a safety proof alone does not prove liveness.

Later candidates, in order:

1. Resource accounting: admitted reservations preserve `0 <= used <= limit`,
   refusal preserves usage, and ownership tokens allow release at most once.
2. FIN/TIME-WAIT state transitions: FIN consumes one sequence number, duplicate
   control traffic cannot indefinitely retain a slot, and expiry respects the
   documented reset/shutdown exceptions.

## Connection to Go and acceptance

- Keep the pilot small; no production rewrite or runtime Lean dependency.
- Map model definitions and assumptions to specific Go functions and invariants.
- Run shared vectors and differential tests against Go. These strengthen the
  connection but do not constitute a formal model/implementation equivalence proof.
- Pin the proof toolchain and check proofs in bounded CI. Reject unfinished
  proofs (`sorry`) and unapproved axioms; review assumptions and theorem scope.
- Include an intentionally false property as a rejected verification control.
- Document the remaining model-to-Go gap and maintenance obligations when either
  implementation or specification changes.
- Retain race, integration, encrypted workload and actual-image tests. The pilot
  does not prove Go concurrency, OS behavior, dependencies or deployment safety.

Lean's [bitvector reference](https://lean-lang.org/doc/reference/latest/Basic-Types/Bitvectors/)
describes the relevant fixed-width reasoning support. Reassess implementation
cost and the pilot's practical benefit before expanding its scope.
