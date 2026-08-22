# Active TODO — Linux/AArch64

This is the living, scope-filtered work list for `crabc`. It replaces the
chronological “next” language in [the historical delivery records](docs/history/)
as the planning source. The exact machine-readable capability state remains
[`compat/crabc-rs/coverage.toml`](compat/crabc-rs/coverage.toml): this document
is its reviewed, human-oriented projection.

Current scope is Linux/AArch64 little-endian with Linux 5.10 as the kernel
baseline. Every item below needs a narrow contract, observable tests,
Linux/AArch64 direct-boundary or ABI evidence where applicable, and musl/POSIX
evidence appropriate to its C behavior. Do not start several broad families
at once.

## Current status

M0–M12 are complete. Current ledger validation records 171 verified native
seams, no deferred native capability groups, and 52 documented non-native
boundaries. The current generated dashboard records 1,647/1,647 required musl
dynamic exports, no ABI metadata mismatch, 34/34 measured Alpine corpus cases,
and no current libc-test missing-symbol blocker. These measurements are
evidence, not a claim of complete historical libc breadth.

The C `setreuid`, `setregid`, `seteuid`, and `setegid` success stubs are now
an explicitly tested `-1/EOPNOTSUPP` profile limitation; full musl-compatible
process-wide credential synchronization is an explicitly documented non-native
boundary.

Since this ledger was created, `getpagesize` and `_SC_PAGE_SIZE` have been
made `AT_PAGESZ`-driven (including an 8 KiB synthetic-startup regression), and
the AArch64 loader has a focused `AT_BASE` self-relocation runtime case. They
are retained here as completed scope records, not active work.

The M11 loader introspection row is now verified: `LoadedImageSnapshot` and
`Library::information` copy bounded records through the append-only runtime
bridge without exposing `link_map` or invoking callbacks while ldso is locked.

The named temporary-file row is now verified as `fs::NamedTempFile`; it uses
exclusive descriptor-relative creation, 96-bit `getrandom` suffixes,
`O_CLOEXEC`, and owned unlink-on-drop cleanup. The anonymous `fs::TempFile` row
is also verified through Linux `O_TMPFILE`, with no named-file fallback.
`mktemp`/`tempnam`/`tmpnam` and Linux file-handle operations remain documented
C-only or authority-bearing boundaries rather than a generic native filesystem
API.

The caller-owned resolver row is now verified as `ResolverConfig`: bounded
`/etc/resolv.conf` and `/etc/hosts` snapshots, explicit hosts-before-DNS
precedence, ndots/search candidate ordering, A/AAAA lookup, bounded CNAME
completion, and the existing configured-order retry/failover transport. It
does not discover NSS providers or add DNSSEC, DoH/DoT, mDNS, or IDNA policy.

## Core runtime capability work

| Ledger group | Exact work still left | Do not repeat |
| --- | --- | --- |
| _(none)_ | The currently scoped core runtime slices are complete. | Select a new bounded contract only after updating the ledger and evidence plan. |

## Useful POSIX/runtime capability work

| Ledger group | Exact work still left | Boundary |
| --- | --- | --- |

## Evidence and maintenance frontiers

These are not hidden feature commitments. Promote one only when it helps a
selected scoped capability.

- Expand static-link evidence beyond the existing static pthread/TLS lifecycle
  case; a full static libc-test matrix remains unmeasured.
- Decide whether exhaustive static-archive ABI comparison and broader
  header-feature/layout probing are worth their cost. The current selected ABI
  probe is green but intentionally not exhaustive.
- Use focused fuzzing/property/failure-path testing for high-value parsers and
  ownership state machines when changing them.
- Benchmark a selected hot facade route against Rustix only when a design or
  regression needs the measurement. Preserve M12’s bounded LTO proof; the
  historical static/build-std linker-plugin lane is optional research, not a
  compatibility blocker.
- Extend POSIX, loader, or real-program evidence only in response to a defined
  contract. Existing selected suites are not claims of full standards or
  arbitrary Alpine DSO-graph coverage.

## Not TODO

The 52 `documented` ledger groups are accounted boundaries, not a hidden
backlog. They include C ABI-only machinery, Rust-subsumed operations, internal
runtime exports, and the mimalloc allocator exception. Their exact rationale
is in [`compat/crabc-rs/coverage.toml`](compat/crabc-rs/coverage.toml).

The following are deliberately outside project scope unless the user changes
it explicitly: x86_64, RISC-V, 32-bit, big-endian, and non-Linux `crabc`;
glibc as an oracle or fallback; allocator research; hand-rolled cryptography;
general locale/charset databases; NSS/plugins; bundled tzdata; gettext;
DNSSEC, DoH, DoT, mDNS, and IDNA policy; async runtimes; process-management
frameworks; security-policy frameworks; and a portability abstraction layer.

The bounded native netdb slice is complete for immutable owned snapshots,
lookups, and source-order enumeration of `/etc/hosts`, `/etc/services`, and
`/etc/protocols`. The C static-buffer netdb ABI, `/etc/networks`, and
NSS/provider systems remain outside that slice. Resolver integration is the
separate caller-owned `ResolverConfig` slice described above.

The bounded native glob slice is complete for explicit root path or directory
descriptor expansion. Results own raw pathname bytes and are sorted
lexicographically; no-match returns an empty vector, while root and directory
read errors remain typed. The C `glob`/`globfree` ABI and hidden CWD traversal
policy remain outside this native contract.

The first native IPC slice is complete for owned POSIX named message queues:
open/create, unlink, attributes, priorities, caller buffers, nonblocking
behavior, and absolute realtime deadlines. `mq_notify`, SysV IPC, named
semaphores, AIO, and aggregate IPC frameworks remain outside scope.

The bounded native PTY/session slice is complete for an owned master/slave
`PtyPair`, caller-buffered or owned `ptsname` results, and an explicitly
unsafe Linux session/controlling-terminal handoff. `forkpty`, `login_tty`,
and `vhangup` remain C-only historical helpers because they require process
supervision, prepared-exec, or hangup-authority contracts; `isastream` has no
Linux PTY meaning.

The remaining historical C regex, process-control, credential, environment,
signal, pthread/C11, calendar/clock, and kernel-administration families have
been reviewed against `SCOPE.md`. Their useful native seams are already
separately verified; the rest are C ABI behavior, explicitly constrained
compatibility, or out-of-scope frameworks rather than native crabc-rs work.
The ledger records each rationale and evidence. In particular, process-wide
credential mutation remains the tested C `EOPNOTSUPP` limitation rather than
an unsafe per-thread facade, and global `TZ`/locale/time-control behavior does
not become a native policy layer.

## Choosing the next slice

Start with a single ledger row. Write the ownership/state contract and focused
regression first, then implement against Linux 5.10, prove the boundary, and
update the ledger, this TODO, nearby documentation, and the relevant report.
If the work would need a new dependency, perform the dependency review in
[`SCOPE.md`](SCOPE.md) and obtain the required user approval before adding it.
