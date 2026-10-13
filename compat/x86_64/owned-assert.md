# Owned C assertion failure

An enabled `assert` in the installed `<assert.h>` calls `__assert_fail`.
The owned runtime supplies that entry through `owned_assert.rs`, using
the existing FILE engine and abort signal transition. The frozen private
archive and paused AArch64 implementation remain unchanged.

The translation maps musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, `src/exit/assert.c`, to
`libc/src/c_abi/x86_64/owned_assert.rs::__assert_fail`. Its source license is
musl's MIT license in `COPYRIGHT`. The diagnostic format, argument order,
`fprintf(stderr, ...)`, and subsequent `abort()` follow that source. Default
stderr is unbuffered; the assertion entry does not introduce an extra flush
or ordinary exit callbacks.

`./scripts/dev-x86_64.sh owned-assert` compiles one installed-header workload
object and compares pinned musl with static, static PIE, dynamic PIE, and
dynamic non-PIE products, including kernel and direct interpreter entry.
Contained children prove exact diagnostic bytes and SIGABRT from the main
task and a created worker. They also reject ordinary exit callbacks. Header
reinclusion proves `NDEBUG` suppresses expression evaluation and enabled
successful assertions evaluate once. The dynamic qualification catalog runs
this same workload on each of its three products.

The six-entry matrix is a focused component check; the expanded dynamic
catalog still requires complete qualification, and family completion and
public x86 support remain open.
