# Owned system-cancellation evidence

`run_owned_system_cancellation.sh` tests the source-defined distinction between
`system(3)` and `pclose(3)` waits. The consumer holds a controlled `/bin/sh`
child at a pipe boundary, observes cancellation, pending cancellation,
cancellation-disabled behavior, and an ordinary signal, then verifies the
child state that each source path leaves behind. Its supervisor owns injected
failure and timeout cleanup: it retains the tester process-group identity,
removes that group, and reaps every descendant before reporting the raw result.
The fixed child source also checks its argv, environment, signal dispositions,
signal mask, and descriptor lifecycle, so the test does not treat an ambient
shell as the protocol target.

The runner creates two distinct installed-header objects, one for the consumer
and one for the child. It compiles each once through the installed dynamic
driver with `--dynamic-pie`, `-std=c11`, `-fno-builtin`, and
`-fno-stack-protector`, then records the actual installed-driver command,
installed helper and compiler identities, clean compiler environment, exact
compiler/header dependency closure, source and object hashes, and relocations
in `compile.json`. The driver's effective code-generation flag is `-fPIE`; it
does not assume that `-fPIC` is a universal application-object policy. The
runner checks both source roles, every installed header hash, and both immutable
objects before the musl links, after those links, and after every link matrix.
Native linking and execution prove that each unchanged object serves pinned
musl, static/static-PIE, and dynamic PIE/non-PIE. The latter runs through both
kernel and direct interpreter entry, while the fixed child continues to enter
through its owned interpreter.

Each static link requests a static receipt. The runner's local two-role audit
binds the selected consumer or child object to its source receipt, the current
product manifest, runtime inputs, trace, ELF form, and static receipt. The
dynamic audit makes the corresponding dynamic receipt and trace checks without
using the single-workload shared validator. `musl-links.json` binds the same
two object identities to the pinned musl outputs. Every normal, injected
failure, and timeout run retains and compares raw stdout, stderr, and status.

The runner accepts
`[--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`. With no products it
builds both disposable products. A positional dynamic product retains the
dynamic-only replay. `--static-sysroot` selects the static/static-PIE product;
when it is supplied alone the runner builds its default dynamic product to own
the two installed-header translations and dynamic entries. Supplying both
products invokes neither producer. Supplied paths must resolve to physical
directories under this checkout's `.work` tree. This is a bounded evidence and
replay interface, not a product-family completion or public x86-64 support
claim.
