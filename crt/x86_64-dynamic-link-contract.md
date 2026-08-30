# Native x86-64 private dynamic-PIE CRT link contract

`./scripts/dev-x86_64.sh crt-dynamic-link-contract` is a second, narrow
private artifact inside the still-planned `crt.dynamic-startup` family. It
does not replace the existing `crt-dynamic-startup` entry/lifecycle evidence.
Where that artifact compares the Rust entry path with the pinned-musl launch
and separately invokes the candidate callback bridge, this one audits the
final dynamic-PIE link boundary itself.

The runner builds `Scrt1.o`, `crti.o`, and `crtn.o` with
`crt/build_x86_64.py`, compiles the existing tiny constructor/main/destructor
fixture with the pinned musl 1.2.6 compiler profile, and links exactly those
four object inputs under `-nostdlib -nostartfiles`. The only dynamic runtime
input is the pinned musl `libc.so`; the only interpreter is the pinned musl
`ld-musl-x86_64.so.1`. A generated linker map is part of the evidence: it
must name each Rust CRT object and the fixture, and it rejects ambient
`Scrt1.o`, `crtbegin`/`crtend`, libgcc, sanitizers, and compiler-runtime
inputs.

The resulting image must be an x86-64 `ET_DYN` PIE with exactly one
`PT_INTERP` and one `PT_DYNAMIC`, exactly `DT_NEEDED=libc.so`, and the
`DT_INIT`, `DT_FINI`, `DT_INIT_ARRAY`, and `DT_FINI_ARRAY` lifecycle tags.
Its ELF entry has to be the Rust-produced global `_start`; global `_init` and
`_fini` must remain the `crti.o`/`crtn.o` boundaries; and the direct
`__crabc_x86_64_dynamic_start` helper must be defined in the executable. The
only permitted unresolved runtime boundary symbols are musl
`__libc_start_main`, `write`, `_exit`, and the intentionally weak private
owned-CRT record. Compiler-runtime helpers such as `__stack_chk_fail` or
`_Unwind_Resume` fail the artifact.

The launched fixture emits `IMF`, which is musl-owned
constructor/main/destructor behavior. This is not evidence that a candidate
loader consumes the owned note or record, nor evidence for candidate libc,
loader TLS, static-link helper closure, installed CRT/sysroot, a compiler
driver, full dynamic startup, family completion, or public x86-64 support.

Run it only through the native x86 dispatcher:

```bash
./scripts/dev-x86_64.sh crt-dynamic-link-contract
```
