# CRAB-2: Child ownership after nonterminal waits

Status: accepted

## Summary

Decide whether the native x86-64 `Child` should admit nonterminal waits. The
current API deliberately consumes its unique owner on every result, including
`NOHANG` with no status. The recommendation is to return that owner whenever
the wait has not reaped the child, while preserving the existing Linux options.
The owner accepted this recommendation; see Decision.

## Motivation

[`Child::wait`](../../crabc-rs/src/process_x86_64.rs) accepts `NOHANG`,
`UNTRACED`, `CONTINUED` and future option bits, but takes `self` and returns
only a status or error. A child may still run after `None`, a stop/continue
report or an error, and the caller no longer has its safe wait owner.
The synchronized [ownership test](../../crabc-rs/tests/x86_64_child_ownership.rs)
demonstrates this: after a live child produces `None`, cleanup uses unsafe
`wait4_raw`. This is the documented contract, not an accidental regression.

The [facade design](../design/crabc-rs.md) promises one consuming wait and
treats polling/retry as separate work. The decision is whether to restrict
the options to that narrow contract or retain ownership through the outcomes
the existing options already permit. Unique ownership should remain useful
through completion without introducing a process supervisor.

## Design

If nonterminal waits remain in scope, use explicit ownership-bearing outcomes:

| Kernel outcome | Result and ownership |
| --- | --- |
| Exited or signaled and reaped | Return terminal `WaitStatus`; consume `Child`. |
| No reportable change with `NOHANG` | Return the same `Child`. |
| Stopped or continued | Return the same `Child` with the observed status. |
| `EINTR` | Retry internally with the same owner, as today. |
| Other error | Return the same `Child` with the typed error for an explicit caller decision. |

A result enum can express these cases without cloning a PID or adding a
nullable owner. An owned error does not promise that the kernel child still
exists: external reaping can invalidate the underlying relationship. Keep
the existing explicit `pid(self)` transfer and document that callers using
raw/C wait operations must coordinate their ownership.

Retain exact Linux status decoding and one-child selection. Add no general
`waitpid` selector, scheduler, background reaper, automatic signal or blocking
`Drop`. Update the facade contract only after the scope decision is accepted.

Acceptance requires a synchronized live-child test that gets a nonterminal
result and later reaps through the safe returned owner, plus stop/continue
and error paths that retain ownership. Preserve the compile-fail proof that a
consumed owner cannot be waited twice and the existing EINTR retry behavior.

## Alternatives considered

- **Restrict the consuming method to terminal blocking waits.** Remove the
  nonterminal options from this surface and decide error ownership explicitly.
  This best preserves the current one-shot scope, but reduces the accepted API.
- **Keep the documented behavior.** Callers can explicitly transfer the PID
  and manage raw waits. This requires no change but retains the gap illustrated
  by the existing cleanup test.
- **Borrow `&mut Child` for waits.** This preserves the owner while pending,
  but requires a reaped state and runtime checks on later method calls. Returning
  ownership makes the terminal transition visible in the result type instead.

## Open questions

1. Should the facade preserve strict one-shot terminal waiting or support the
   nonterminal options it already accepts? Recommend ownership-returning
   outcomes for those options; choosing the narrower contract is also coherent.
2. Should an API change replace the current method directly or add a transition
   period? Recommend direct replacement with updated callers and documentation,
   consistent with the repository's experimental, commit-pinned API policy;
   add a compatibility layer only for an identified consumer.

## Decision

Accepted by the owner on 2026-11-12: ownership-returning outcomes for the
existing options, replacing the previous method directly. `Child::wait` returns
`WaitOutcome::{Reaped, Running, Changed}` or a `WaitError` carrying the owner.
`crabc-rs/tests/x86_64_child_ownership.rs` covers the synchronized `NOHANG`
retry through the returned owner, stop and continue reports, and an `EINVAL`
error that returns the owner.
