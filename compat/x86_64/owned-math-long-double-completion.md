# Owned binary80 long-double completion consumer

`compat/x86_64/run_owned_math_long_double_completion.sh` is a supplied-product
consumer gate for `fdiml`, `exp10l`, and GNU's weak same-address `pow10l`.
It does not build a static or dynamic sysroot, change the default archive, or
promote a runtime family.

The input source is
`compat/x86_64/libc_math_long_double_completion_probe.c`. It is compiled once
through the supplied dynamic driver's installed headers, then that retained
object is linked unchanged to pinned musl, optional supplied static `ET_EXEC`
and static-PIE products, and supplied dynamic PIE/non-PIE products. Dynamic
executions run both through the kernel-selected interpreter and direct
`/lib/ld-crabc-x86_64.so.1` inside independent copied product roots. The runner
validates each sealed product and link receipt, and hashes every copied runtime
payload plus consumer before and after execution.

The probe and
`compat/x86_64/validate_libc_math_long_double_completion.py` retain the narrow
musl 1.2.6 record contract: SysV AMD64 binary80 typed calls and storage,
positive zero from `fdiml`, NaN and infinity paths, finite/table/fallback
`exp10l` boundaries, the weak `pow10l` alias, overflow/underflow/inexact flags,
and all four x87/MXCSR rounding modes with complete control restoration. Every
successful static or dynamic output must be byte-identical to the separately
run pinned-musl output and have an empty stderr stream.

The installed runtime enables `x86-math-long-double-completion` through
`x86-owned-static-runtime`. The provider remains the checked assembly inclusion at
`libc/src/c_abi/x86_64/math_long_double_completion.rs`, generated from pinned
musl `src/math/fdiml.c` and `src/math/exp10l.c`. Its only public additions are
strong `fdiml`/`exp10l` and weak same-address `pow10l`; `__fpclassifyl`,
`modfl`, `exp2l`, and `powl` remain their existing x87 owners. This consumer
adds no C target provider, dependency, general libm claim, AArch64 change, or
x86 support/promotion claim.

`compat/x86_64/run_libc_math_long_double_completion.sh` proves the isolated
static archive feature build. Pass `--retain-output DIR` to keep its baseline
and feature archives, source-runtime graphs, consumer, raw streams, and
inspection output under checkout `.work`. The default run uses scratch under
`.work/x86_64/tmp` and removes it on success.

Pass that retained directory to
`owned_math_fenv_all_entry_receipt.validate_binary80_feature_work(root, work)`
to derive its finite feature account. The returned fields identify the empty
baseline selection, enabled feature, three additions and their bindings,
archive paths, and the concrete symbol rows from the archive and final
consumer. Archive alias rows include member occurrence and name, section, and
value, so duplicate archive member names at different positions remain
distinct. The
helper replays the retained source-runtime graphs, archive inspections, raw
argv, oracle/candidate streams, and final ELF checks. Use the existing
`validate_report` separately for an installed math product pair; neither
reader adds a qualification claim.
