# Owned wide calendar formatting

The native owned runtime supplies `wcsftime`, source-specific
`__wcsftime_l`, and weak public `wcsftime_l` from
`libc/src/c_abi/x86_64/owned_wcsftime.rs`. The leaf is selected only by
`x86-owned-static-runtime`, which the owned dynamic product inherits. It is
C ABI calendar-formatting machinery for the existing C/POSIX/C.UTF-8 locale
profile. It does not add a locale database, an encoding, an allocator, a Rust
facade API, or public x86 platform support.

## Source and ownership

The semantic source is MIT-licensed musl 1.2.6, release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`. Its release archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`;
`compat/upstreams.toml` owns the pin and upstream `COPYRIGHT` owns the
license.

| Musl source | Owned Rust target |
| --- | --- |
| `src/time/wcsftime.c::__wcsftime_l` | `owned_wcsftime::format` and `__wcsftime_l` |
| `src/time/wcsftime.c::wcsftime` | `owned_wcsftime::wcsftime` |
| `src/time/wcsftime.c::weak_alias(__wcsftime_l, wcsftime_l)` | same-address weak `wcsftime_l` assembler alias of `__wcsftime_l` |
| `src/time/strftime.c::__strftime_fmt_1` | existing `owned_strftime::format_directive` shared directive seam |

The wide loop retains musl's 100-byte directive scratch, 100-wide-character
conversion scratch, wide `wcstoul` width parsing, optional `E`/`O` modifier,
sign/leading-zero treatment, capacity boundary, conversion failure, and final
NUL/truncation behavior. A non-ASCII wide conversion is rejected before it can
be narrowed into a different ASCII directive. Literal wide characters remain
wide and copy directly, as in the source loop.

`owned_strftime::format_directive` now states its shared contract: a successful
pointer is NUL-terminated and either borrows its supplied 100-byte scratch or
immutable locale/timezone data. `%n`, `%t`, and `%%` use NUL-terminated C
literals to meet that contract before `mbstowcs` reads them. Their byte
`strftime` result lengths and contents remain unchanged. Callers copy the
returned text before reusing scratch, releasing a locale, or mutating the
borrowed `struct tm`/timezone state.

The existing owned `mbstowcs` provider performs the byte-to-wide conversion
under the calling CTYPE, and the existing `wmemcpy` provider copies its result.
This preserves musl's distinction: `_l` selects LC_TIME data for the
directive, while `mbstowcs` still follows the active multibyte locale. The
`_l` entry accepts only a live C/POSIX/C.UTF-8 locale object admitted by this
runtime; `LC_GLOBAL_LOCALE` is not valid. Output names `capacity` writable
`wchar_t` values (and can be null only at zero capacity), while format and
`struct tm` input are readable, terminated/live as applicable, and do not
overlap output. Zone-name borrows retain the timezone owner's lifetime and
callers serialize timezone mutation.

## Focused evidence

`./scripts/dev-x86_64.sh owned-wcsftime [DYNAMIC_SYSROOT]` dispatches
`compat/x86_64/run_owned_wcsftime.sh`, which builds fresh static and dynamic products,
then compiles `compat/x86_64/owned_wcsftime_probe.c` once through the installed
dynamic driver. The unchanged object links against pinned musl 1.2.6, the
owned static and static-PIE products, and owned dynamic PIE/non-PIE products;
each dynamic executable runs through both kernel and direct-interpreter entry.
Source/object hashes, symbol tables, binaries, stdout, and stderr are retained.
The runner requires one strong `wcsftime`, one strong `__wcsftime_l`, and one
weak `wcsftime_l` provider at the same ELF address as `__wcsftime_l` in each
applicable artifact, and every candidate output must equal musl. Supplying an
existing dynamic product runs only the four dynamic entries and makes no new
static-evidence claim.

The single installed-header object takes addresses of both public declarations,
binds the musl private entry explicitly, proves the two locale entry addresses
are equal, and checks LP64 `wchar_t` ABI. It
exercises all three entries with zero capacity, normal calendar directives,
the byte-to-wide `%n`/`%t`/`%%` bridge, exact truncation, expanded years and
the `+` width rule, invalid directives, literal non-ASCII wide characters, and
non-ASCII conversion rejection. It records errno and a complete output
checksum while canaries prove that every capacity leaves adjacent and unused
wide storage unchanged. This is focused native evidence, not complete C ABI or
runtime qualification and not a public x86 support claim.

The owned dynamic qualification catalog requires `wide-calendar` for each of
its installed, relocated, and second products. This binds the focused runner
to the aggregate product and source closure; registration alone is not a
qualification pass.
