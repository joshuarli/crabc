# Installed calendar text parsing

The installed static and dynamic runtimes provide `strptime` through
`libc/src/c_abi/x86_64/owned_strptime.rs`. It uses the existing C/POSIX/C.UTF-8
LC_TIME strings and the owned timezone names. It allocates no memory and
changes only the `struct tm` fields selected by the format. Failed conversions
can retain partial field writes; successful conversions return the first
unconsumed input byte. Epoch and week-number directives retain musl's
parse-only behavior rather than deriving unspecified fields.

The implementation translates `src/time/strptime.c` from MIT-licensed musl
1.2.6, release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417` and archive
SHA-256 `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
The source's numeric-range and numeric-digit branches map to `numeric`, its
language-name lookup maps to `symbolic`, and its main directive loop,
recursive composite formats, and century update map to `parse`. The public
`strptime` boundary retains the exact x86-64 `timegm::Tm` layout.

One source defect is deliberately corrected. With two nonempty timezone
names, an unknown `%Z` name reaches musl's signed-character alphabetic loop.
That loop admits the terminating NUL and reads beyond the string. The native
regression uses `TZ=STD0DST` and puts `Unknown\0` directly before a protected
page: pinned musl faults, while the owned parser stops at NUL and preserves
the untouched `tm_isdst` field and errno. The recorded musl signal is an
oracle failure, not a passing differential result. The correction also stops at digits, punctuation, and control bytes that
musl consumes in this fallback; `Unknown1{`, `Unknown!{`, and a tab delimiter
have explicitly different expected suffixes. A high-byte delimiter is likewise consumed by musl and stops the owned
parser. Separate observations check these boundaries and known `STD`/`DST`
prefix matching with two nonempty names. The 67 ordinary differential cases
retain source behavior, including the empty second timezone-name match where
applicable; they do not claim parity for the corrected unknown-name fallback.

Run the same installed-header object against musl, static ET_EXEC, static PIE,
and dynamic PIE/non-PIE through both installed-interpreter entries:

```sh
bash compat/x86_64/run_owned_strptime.sh
```

Run this leaf inside the pinned x86 container with `SYS_CHROOT` and physical
checkout `.work` temporary storage. A supplied installed dynamic product is
an optional positional argument for focused reuse. The leaf retains the
source/object hashes, link artifacts, all 67 ordinary parsing records, raw
stdout/stderr/status files, and the separate guard-page observations. It
checks case-insensitive names, range failures and partial writes, numeric and
whole-date widths, signed/relative years and century ordering, composite
formats, ignored epoch/week fields, offsets, unsupported directives, suffix
positions, errno, untouched fields, and surrounding storage guards.

This component does not change AArch64 parsing, the frozen default x86 archive,
the locale profile, or the full libc-test and native POSIX aggregate gates.
