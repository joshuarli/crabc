# Native owned mount-table interfaces

Mount-table access is C ABI compatibility machinery over conventional text
files. The native owned runtime implements `setmntent`, `getmntent`,
`getmntent_r`, `addmntent`, and `endmntent` in
`libc/src/c_abi/x86_64/owned_mount_table.rs`. The independently qualified
`hasmntopt` leaf remains in `libc/src/c_abi/x86_64/hasmntopt.rs`. The new module
is selected only by `x86-owned-static-runtime`, also selected by the owned
dynamic feature. The frozen standalone `hasmntopt` archive contract and paused
AArch64 implementation are unchanged.

## Source and lifetime contract

The semantic source is musl 1.2.6, commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, `src/misc/mntent.c`, under the
upstream MIT `COPYRIGHT`. The release archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`;
`compat/upstreams.toml` owns the pin.

| Musl source | Rust owner |
| --- | --- |
| `setmntent`, `endmntent` | Corresponding exports using the existing owned `FILE` implementation |
| `unescape_ent` | `unescape`, retaining byte wrapping and literal zero escapes |
| `getmntent_r` | `getmntent_r` and `read_entry`, using the existing scanf grammar |
| `getmntent`, `internal_buf`, `internal_bufsize` | `getmntent`, `SHARED_ENTRY`, `SHARED_LINE`, `SHARED_CAPACITY` |
| `addmntent` | `addmntent`, retaining seek-before-output and literal field formatting |
| `hasmntopt` | Existing `hasmntopt.rs` leaf |

The source's private sentinel pointer becomes an explicit private `shared`
argument. No intentional observable differences from the named source are
introduced. There are no new dependencies, providers, mount caches, or
namespace policy. `setmntent` opens the caller's path with ordinary `fopen`
semantics. `endmntent` returns one even for NULL and close errors.

`getmntent_r` returns strings within caller-owned storage; overwriting that
storage invalidates them. It accepts missing trailing fields and uses musl's
scanf whitespace and integer behavior. Blank and comment lines are skipped;
integer fields parsed from skipped comments retain the source's effect on the
next record. Escapes decode in place: two backslashes become one; up to three
octal digits produce an unsigned byte, and a zero-valued escape stays literal.
An overlong bounded line is drained and returns NULL with `ERANGE`. FILE EOF
and error flags take precedence, so an unterminated final line is not returned.

`getmntent` has process-global borrowed record and growable line storage that
survive stream close. Callers serialize calls and all use of their results.
`addmntent` seeks to EOF and writes literal tab-separated fields: it does not
escape whitespace supplied by its caller.

## Native evidence

`compat/x86_64/owned_mount_table_probe.c` is compiled once through the installed
dynamic driver by `compat/x86_64/run_owned_mount_table.sh`, after both fresh
products are built. The runner retains and verifies source/object hashes. Those same object bytes
link against pinned musl 1.2.6, owned static and static PIE products, and owned
dynamic PIE and non-PIE products. Both dynamic executable forms run through
kernel and direct-interpreter entry in a contained root. Every candidate's
stdout and stderr must equal the oracle's. The runner checks strong/default
function symbols in the oracle, static archive, static executables, and shared
provider.

The probe checks record layout and returned pointer ownership, skipped blank
and comment lines, malformed and missing fields, octal and backslash escapes,
integer parse errors, unterminated EOF, bounded buffers with surrounding
canaries and cursor recovery, shared allocation growth beyond 8 KiB, append
position and literal output, successful and missing-path opens, NULL close,
read-only append, bad-descriptor read/close, non-seekable append, and
`hasmntopt` boundaries.

The regression passed pinned musl before implementation and failed the
installed static driver's final link with the five absent symbols. After
implementation, the complete matrix passed in the pinned native image. The
optional runner argument reuses a supplied dynamic product and executes the
four dynamic entries; it does not claim fresh static-product evidence.

This is a focused family proof. It does not complete the native runtime
campaign or promote x86-64 to public support.
