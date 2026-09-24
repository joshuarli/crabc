# Owned C filename patterns

`owned_fnmatch.rs` and `owned_glob.rs` provide the public Linux/x86-64
`fnmatch`, `glob`, and `globfree` entries in the planned
`x86-owned-static-runtime` aggregate.
The frozen default static archive keeps its existing provider boundary. The
same aggregate is inherited by the materialized dynamic product; this is not a
claim that the broader pattern, locale, filesystem, account, or C-ABI family
is complete.

The translation is pinned to musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license.
`src/regex/fnmatch.c` maps to `owned_fnmatch.rs`; `src/regex/glob.c` maps to
`owned_glob.rs`; and `owned_pattern.rs` records that source boundary. The C
matcher deliberately does not call the Rust facade's byte-only matcher. It
uses the selected `locale_multibyte` and `wide_character` owners for musl's
`mbtowc`, case mapping, and POSIX wide character classes, including invalid
UTF-8 progression. It keeps the public `FNM_PATHNAME`, `FNM_NOESCAPE`,
`FNM_PERIOD`, `FNM_LEADING_DIR`, and `FNM_CASEFOLD` behavior at the C boundary.

`glob` preserves musl's `glob_t` layout and its flexible `struct match`
allocation convention: each returned pathname is one allocation whose prefix
is recovered by `globfree`. Its source-shaped walker uses the selected
allocator, directory-stream, Linux stat, environment, and process-identity
owners. Directory `d_type` is a private projection from the exact validated
record; `DT_UNKNOWN` remains unknown and takes the stat path, while symlinks
retain musl's target check for `GLOB_MARK`. Leading tilde handling follows
musl's `HOME`, `getpwnam_r`, and `getpwuid_r` calls. The standard passwd ABI is
owned separately, so this leaf neither parses `/etc/passwd` itself nor creates
an NSS/provider fallback.

Run `./scripts/dev-x86_64.sh owned-pattern` for the focused evidence. Its one
project-header C object first runs in an isolated chroot linked against pinned
musl, then runs against the owned static, static-PIE, dynamic-PIE, and
dynamic-non-PIE products. Dynamic applications execute through both kernel
interpreter resolution and direct `/lib/ld-crabc-x86_64.so.1` entry. The
fixture checks C, POSIX, and C.UTF-8 matching; wide classes, case folding and
malformed bytes; sorted and unsorted expansion; offsets, append, no-match,
repeated release, escapes, period handling, markers, trailing slashes, and
HOME/named-user tilde expansion. It finally drops from root to uid/gid 65534
inside the private root and verifies `errfunc` and `GLOB_ERR` behavior for an
unreadable directory. No workload can inspect a host directory or host account
file. The escaped-wildcard, nonmatching-range, nested-class, literal-prefix,
recursive-separator, and dangling-link marker/errno regressions each execute
in a separate timeout-contained chroot child before the full workload, so one
source-loop failure cannot conceal a later boundary.

The `fnmatch-corpus` and `glob-corpus` selectors then compare the owned
translation with pinned musl over a deterministic corpus. The fnmatch corpus
runs fixed and fixed-seed generated patterns (literals, wildcards, escapes,
bracket negation, ranges, classes, collating and equivalence spellings,
unterminated brackets, slashes, periods, UTF-8, and invalid bytes) against
fixed, generated, and pattern-derived subjects under all 32 combinations of
the five public flags in `C` and `C.UTF-8`. The glob corpus expands fixed and
generated patterns, absolute and relative, over the runner's `/corpus/outer/inner/tree`
(hidden, metacharacter, UTF-8, and invalid-byte names; nested directories;
directory, dangling, and looping links; a file used as a directory) under
mark, no-check, no-escape, period, error, no-sort, offset, and tilde flags,
with an error callback that continues or aborts. Each block prints one
FNV-1a digest of every result, so the transcript is judged by comparison with
musl; the `-trace` selector spellings print each observation.

Every candidate root also traces the `glob-corpus` workload and the
directory-free `fnmatch-escaped` baseline with `strace -f`, for pinned musl
and the candidate alike, and `owned_syscall_profile.py compare` subtracts each
baseline. The candidate must then make exactly musl's opens, `getdents64`,
`fcntl` and file-status calls and closes (net of musl's nscd sockets), and no
more `mmap`/`munmap`/`mremap` calls. Musl's `opendir` makes one `open` plus
`open`'s close-on-exec `fcntl` and allocates its `DIR` through `calloc`; the
owned stream follows it (`directory_streams.rs`). Before that, each owned
stream added an `fstat`, an `F_GETFL`, and an `mmap`/`munmap` pair: about
34.5k mapping pairs over the corpus against musl's roughly 2k.

One intentional difference is confined to input on which musl never returns.
With `FNM_PATHNAME`, fnmatch.c's component scan advances by `pat_next`'s step,
which is zero for an invalid multibyte pattern character, so musl loops
forever once the scan reaches one (for example `fnmatch("\377", "",
FNM_PATHNAME)` in `C.UTF-8`). `owned_fnmatch::fnmatch_with_mode` returns
`FNM_NOMATCH`, the answer `fnmatch_internal` gives for any component
containing that character. The corpus skips `FNM_PATHNAME` for patterns that
are invalid in the current locale; the `fnmatch-pathname-unmatchable` selector
runs five such calls in alarmed children, and the runner requires each musl
child to die of `SIGALRM` and each owned child to report `FNM_NOMATCH`.

Word-expansion preflight is covered by the separate installed `wordexp`
component. Its `nocmd-source` selector in `owned_wordexp_probe.c` checks the
owned evaluator's `WRDE_CMDSUB` result and musl's distinct `WRDE_BADCHAR`
observation for the ambiguous subshell input, plus the ordinary command
control. `owned_wordexp_evidence.py` requires each exact result; the filename
pattern fixture does not carry the retired whole-input scanner expectation.

The header provider catalog moves exactly `fnmatch`, `glob`, and `globfree`
from the deferred text/locale group into the planned owned-static provider
roster. The owned dynamic qualification catalog repeats the same installed
product workload for its installed, second-clean, and extracted products.
Neither record promotes platform support or substitutes for a broader POSIX
qualification.
