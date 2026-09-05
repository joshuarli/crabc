# Owned fixed-profile monetary formatting

The native owned runtime has a private source-faithful implementation of
`strfmon` and `strfmon_l` in
`libc/src/c_abi/x86_64/owned_strfmon.rs`. It is selected only when the root
adds that module under `x86-owned-static-runtime`; the owned dynamic product
inherits that feature. This is a small C ABI compatibility leaf for the
existing C/POSIX/C.UTF-8 profile. It does not add localized monetary data, a
locale database, locale-token validation, an allocator, a numeric formatting
engine, a Rust facade API, or public x86 platform support.

## Source and ownership

The semantic source is MIT-licensed musl 1.2.6, release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`. Its release archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`; the
exact `src/locale/strfmon.c` source SHA-256 is
`394f52a2eaafe8bfbf9f5f7333d5fa04064df26821cc3f8dfac7c1fc0e48a169`.
`compat/upstreams.toml` owns the release pin and musl's upstream `COPYRIGHT`
owns the license provenance.

| Musl source | Owned Rust target |
| --- | --- |
| `src/locale/strfmon.c::vstrfmon_l` | `owned_strfmon::format` |
| `src/locale/strfmon.c::strfmon_l` | `owned_strfmon::strfmon_l` |
| `src/locale/strfmon.c::strfmon` | `owned_strfmon::strfmon` |
| `src/locale/strfmon.c::snprintf` call | existing `stdio_format_scan::snprintf` owned binary64 `%f` path |

The source accepts `=`, `^`, `(`, `+`, `!`, and `-`, field width, `#` left
precision, `.` right precision, and the optional `i` marker. As in musl, all
of the locale-sensitive parsed fields are inert in this implementation; each
conversion extracts one promoted `double` and formats it through
`snprintf("%*.*f", ...)`. Source capacity and literal behavior are retained,
including its literal-only unterminated-output path and the `E2BIG` result
when `snprintf`'s converted length reaches the remaining capacity.

Musl passes `CURRENT_LOCALE` to `vstrfmon_l`, but that parameter is never
read. The owned `strfmon` therefore does not read selected-thread locale state,
and `strfmon_l` carries its `locale_t` only as an opaque, unvalidated,
unretained ABI token. Valid C and C.UTF-8 tokens produce the same fixed-profile
behavior. This is the source's no-data boundary, not a fallback or a claim of
localized monetary formatting.

Musl defines two independent strong functions. There is no `__strfmon_l`
entry and no weak alias, so the owned artifact must contain exactly one strong
`strfmon` and one strong `strfmon_l`; address equality is neither required nor
claimed.

## Focused evidence

`compat/x86_64/run_owned_strfmon.sh [DYNAMIC_SYSROOT]` is the focused runner.
The normal command is `./scripts/dev-x86_64.sh owned-strfmon [DYNAMIC_SYSROOT]`.
The runner first compiles C11 and C++17 project-first and pinned-musl header
witnesses from `owned_strfmon_header_abi_probe.c` and
`owned_strfmon_header_abi_probe.cpp`. They prove the LP64 `ssize_t` and opaque
`locale_t` shape, both variadic declarations, and unmangled C++ references to
both symbols.

It then compiles `owned_strfmon_probe.c` exactly once through the installed
dynamic driver. That same object links against pinned static musl, owned
static, owned static-PIE, and owned dynamic PIE/non-PIE products. Each dynamic
binary runs once through the kernel-selected interpreter and once through the
direct `/lib/ld-crabc-x86_64.so.1` entry, producing six candidate executions.
When supplied a dynamic product, it checks its four dynamic entries; the
mandatory `monetary` qualification case applies that check to each installed
and extracted product.
The runner records header and common-object hashes, symbol reports, final
binaries, stdout, and stderr; every candidate byte stream must equal musl.

The one C object takes both installed function addresses and exercises zero
capacity, valid opaque C and C.UTF-8 locale tokens, multiple variadic `double`
arguments, every source parser flag, width and precision, literal-percent and
full-capacity literal behavior, conversion truncation/E2BIG, and complete
output-buffer canaries. Symbol checks require strong independent providers in
the archive, each static final executable, and the shared object. This is
focused evidence for the two entries only; it does not close a monetary,
locale, formatting, runtime, or public x86-support family.
