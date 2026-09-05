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

## Explicit pinned-oracle corrections

The pinned reader has independently reproduced valid-file defects. Acceptance
for these cases follows [RFC 9636 §§3.1–3.3](https://www.rfc-editor.org/rfc/rfc9636.html#section-3)
and the [POSIX `tzset` global-offset contract](https://pubs.opengroup.org/onlinepubs/9699919799/functions/tzset.html),
not those defective results:

| Case | Pinned musl observation | Owned invariant |
| --- | --- | --- |
| NUL-version v1, fixed UTC+1 | Offset zero and empty name | Offset +3600, name ONE, timezone -3600 |
| NUL-version v1, fixed UTC-5 | Offset zero and empty name | Offset -18000, name ONE, timezone +18000 |
| No transitions, nonempty `XXX-3` footer | Uses type-zero offset 0 | Uses footer offset +10800 |
| Before first transition, type zero is DST | Guesses lowest non-DST type | Uses type zero, including one-transition files |
| Empty footer, fixed UTC+1 | Leaves timezone zero | Uses signed type-derived timezone -3600 |

The signed-global defect can also be isolated using musl's nonstandard ASCII
`'1'` header: a +3600 type produces `timezone=4294963696`. The owned parser
accepts the specified NUL/2/3/4 version bytes and casts the signed offset before
negating it. The ordinary v2/v3 differential matrix excludes none of its
existing observations to accommodate these corrections.

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
