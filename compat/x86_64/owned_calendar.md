# Owned calendar and timezone boundary

`owned_calendar.rs`, `owned_timezone.rs`, and `owned_strftime.rs` are selected
only by the owned-runtime feature. The old UTC fixture remains independent.
These modules supply local civil conversion, normalization, ordinary static
calendar strings, process timezone globals, and byte `strftime`/`strftime_l`.
LC_TIME uses the existing identical C/POSIX/C.UTF-8 tables. They do not bundle
zone data, introduce a locale database, or claim wide-stdio/family completion.

## Source and ownership

The algorithm source is MIT-licensed musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, pinned in `compat/upstreams.toml`.

| Source | Owned implementation |
| --- | --- |
| `src/time/__tz.c`, `__map_file.c` | TZ cache, POSIX rule parsing, system TZif mapping, transition search, zone-name validation in `owned_timezone.rs` |
| `localtime[_r].c`, `mktime.c`, `gmtime.c`, `asctime[_r].c`, `ctime[_r].c` | Conversion/lifetime and C fixed-format boundaries in `owned_calendar.rs` |
| `strftime.c` | Directive, ISO-week, width/sign/padding, partial-output semantics in `owned_strftime.rs` |
| `__tm_to_secs.c`, `__secs_to_tm.c`, `__year_to_secs.c`, `__month_to_secs.c` | Existing `timegm.rs` helpers, exposed only to sibling modules |

One timezone lock protects map/cache/rule changes. Returned zone-name pointers
are borrowed until TZ changes; callers coordinate environment mutation and
pointer use. The growth-only TZ cache allocation policy follows musl. Kernel
file mappings are released when the cached TZ value changes. The scoped raw
cursor handles both NUL-terminated environment values and length-delimited
TZif footers without an invented footer-length cap.

The timezone `pthread_fork_prepare/parent/child` hooks occupy musl's timezone
lock position. Child repair resets only the lock, preserving inherited rules,
cache, and mapping. Full fork coordination belongs to the pthread/process
transaction, not this module. `localtime`/`gmtime`/`asctime` retain source-shaped
shared-result overwrite behavior; their `_r` variants use caller storage.

## Pinned native TZif differences

The native x86-64 oracle uses snapshot
`7813e9119eb5fe681b6750b8a033a0490bca0941`. The owned implementation remains
source-derived from musl 1.2.6. Acceptance follows [RFC 9636 §§3.1–3.3](https://www.rfc-editor.org/rfc/rfc9636.html#section-3)
and the [POSIX `tzset` global-offset contract](https://pubs.opengroup.org/onlinepubs/9699919799/functions/tzset.html).
The probe's `check` mode still requires the specified output in every candidate
mode. Its `observe` mode records the snapshot's exact output:

| Probe row | Snapshot output | RFC/POSIX output |
| --- | --- | --- |
| NUL-version v1, fixed UTC+1 | Offset +3600, timezone 4294963696, name ONE | Offset +3600, timezone -3600, name ONE |
| NUL-version v1, fixed UTC-5 | Offset -18000, timezone +18000, name ONE | Offset -18000, timezone +18000, name ONE |
| No transitions, nonempty `XXX-3` footer | Offset 0, timezone -10800, name ONE | Offset +10800, timezone -10800, name XXX |
| Before first transition, type zero is DST, v2 and v3 | Offset +3600, timezone -3600, standard, name TWO | Offset +7200, timezone -3600, DST, name ONE |
| Empty footer, fixed UTC+1 | Offset +3600, timezone 0, name ONE | Offset +3600, timezone -3600, name ONE |

`zi_read32` returns `uint32_t`, so negating a positive offset wraps before
assignment to `long __timezone`. `scan_trans` returns type zero for a file with
no transitions, bypassing a nonempty footer. Before the first transition it
chooses a non-DST type instead of type zero. An empty footer reaches the POSIX
parser, which sets `__timezone` to zero instead of using type zero. The
reader still requires candidate stdout to equal `TZIF_SPECIFICATION_STDOUT`
byte for byte.

Mapped counts, section boundaries, type indices, and abbreviation termination
are checked before access. Invalid ranges fall back to UTC. Leap records are
range-checked but do not redefine the POSIX epoch scale, following musl. For
times after the last transition with no nonempty footer, RFC 9636 leaves local
time unspecified; this slice retains musl's existing rule/default behavior.

## Direct evidence surfaces

`owned_calendar_probe.c PRIVATE_TZIF_PATH` emits deterministic binary records
covering POSIX TZ rules, real system zones, a synthetic v2 transition/footer
file, fold/gap normalization, overflow, extended years, ISO weeks, locale
variants, truncation, cache changes, and concurrent `_r` conversion. Compile
the owned modes with `CRABC_OWNED_CALENDAR` to add malformed-file safety checks
without changing those records. Compare normal output with pinned musl.

`owned_timezone_tzif_probe.c PRIVATE_TZIF_PATH check` asserts six independent
specification cases. Its `observe` mode records the pinned-musl defects and
must not be labeled a parity pass. Both probes require private caller-supplied
paths; no fixture uses a shared scratch filename. The reference executable's
interpreter must be the pinned musl 1.2.6 interpreter, never ambient glibc.
