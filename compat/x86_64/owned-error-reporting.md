# Owned x86 C error reporting

`libc/src/c_abi/x86_64/owned_error_reporting.rs` translates musl 1.2.6
`src/stdio/perror.c` and `src/legacy/err.c`. `perror` obtains
`strerror(errno)` before taking the permanent `stderr` guard, writes the
source-shaped optional prefix and error string, then restores the stream's
orientation and captured wide locale while the guard remains held. The
`warn`/`err` family retains the source's public call sequence: `warn` and
`err` reach `vwarn`/`verr`; `vwarn` reaches `fprintf`, optional `vfprintf`,
`fputs`, and `perror`; `vwarnx` reaches `fprintf`, optional `vfprintf`, and
`putc`; terminating forms use ordinary `exit`.

`err.c` does not take one FILE lock around a whole warning record. Its public
stdio calls each have their own lock, so simultaneous warnings may interleave
between a prefix, formatted body, errno separator, and newline. This is
intentional source behavior. `perror` remains one locked transaction, as its
source requires. These functions are not async-signal-safe and use the fixed
selected error strings rather than a message catalog.

Run `./scripts/dev-x86_64.sh owned-error-reporting` for the focused evidence.
The same C probe runs first against pinned musl and then the installed static
ET_EXEC/static-PIE and dynamic PIE/non-PIE products. It checks exact normal
and worker output, null and empty prefixes/program names, `%m`, invalid errno,
stderr orientation restoration, normal `err`/`verr` exit with `atexit` flush,
and concurrent source-permitted warning fragments. Dynamic products run by
both kernel and direct interpreter entry.

The probe also records the real provider rules. Pinned musl's separate
`strerror.lo`, `perror.lo`, and `err.lo` archive members let an application's
strong `strerror` replace `perror`'s `strerror` edge and its strong `perror`
replace `warn`'s `perror` edge. The installed static archive emits one member
per Rust module (`scripts/build_x86_64_owned_sysroot.py`), and `strerror`
(`error_strings::strerror_source`), `perror`
(`owned_error_reporting::perror_source`), and the `err.c` family are separate
modules whose called providers are never inlined across those edges. Static
and static-PIE consumers of both replacement objects therefore link without a
duplicate definition and match musl's output. The same rule
holds for every libc function the installed archive gives its own member
(`static_archive_member!`, [owned-static-replacement.md](owned-static-replacement.md)):
replacement links where the provider owns its member, and reaches a libc
caller where that caller keeps a public call edge.
In a dynamic link, a provider DSO before `libc.so` resolves the consumer's
public `strerror` or `perror` reference, while musl's internal libc edges stay
local; the candidate is compared with that observed behavior in both dynamic
modes.

This is a contained private x86 runtime slice. It does not add general locale
catalogs, arbitrary FILE support, logging, asynchronous reporting, family
completion, or public x86 support.
