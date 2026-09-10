# Owned x86 C word expansion

`wordexp` and `wordfree` are private entries of the selected
`x86-owned-static-runtime` aggregate. They do not complete the broader text,
process, shell, dynamic-product, or public x86 support boundary.

The implementation is mapped to musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, licensed under musl's MIT
license. The pinned `src/misc/wordexp.c` has SHA-256
`018c97c999cb60966a0376b71f2c8c187179ef31cf5ddde47b959e8f440e08f8`.
`src/misc/wordexp.c::{do_wordexp,wordexp,wordfree}` maps to
`libc/src/c_abi/x86_64/owned_wordexp.rs`; its source `WRDE_NOCMD` loop at
lines 43-83 is the source mapping for
`libc/src/c_abi/x86_64/owned_wordexp_nocmd.rs`. The source's `sq`, `dq`, and
`np` state continues to determine ordinary literal, `WRDE_BADCHAR`, and
`WRDE_CMDSUB` behavior, including the arithmetic source control below. The
generic hardened `libc/src/wordexp_nocmd.rs` remains an AArch64 implementation
artifact and is deliberately not reused as an x86 musl oracle.

There are two explicit x86 POSIX corrections to that fixed source data. For a
call without `WRDE_SHOWERR`, `owned_wordexp.rs` selects a script beginning
`exec 2>/dev/null;` before the otherwise byte-identical musl `eval` body and
its `$1` input / `$2` redirection argv protocol. This suppresses a shell
parser diagnostic before the source's trailing `$2` can become a redirection.

`owned_wordexp_nocmd.rs` is still a lexical preflight, rather than a shell
evaluator. It now uses movable parameter, arithmetic, and shell frames with
local quote state. A parameter WORD carries inherited double-quote state; a
`#`, `##`, `%`, or `%%` pattern has its own quote state; nested arithmetic has
its own `))` count; and dollar-single text finds only its own unescaped closing
apostrophe. Physical backslash-newline pairs are joined before the scanner
recognizes `${`, `$(`, `$((`, or `))`, except inside single and dollar-single
quotes. This prevents a child parameter or arithmetic token from consuming a
parent delimiter, while preserving literal escaped/quoted `${...}` and
rejecting naked unquoted braces and controls. The frame stack spills through
the selected C allocator, returns `WRDE_NOSPACE` through the source record
boundary, and has no fixed nesting limit.

These are bounded conformance corrections against the `WRDE_SHOWERR` and
`WRDE_NOCMD` obligations in [POSIX.1-2024 `wordexp`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/wordexp.html)
and its [Shell Command Language quoting and expansion clauses](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html).
They do not add `WRDE_UNDEF` evaluation, a shell parser, or a shell sandbox.

In particular, musl classifies
`$((case $A in a) echo x ;; *) echo y ;; esac))` with `WRDE_NOCMD` as
`WRDE_BADCHAR`: its arithmetic-parenthesis count reaches zero at the inner
`*)`, and the following semicolon is then forbidden. A direct `$(echo x)`
remains `WRDE_CMDSUB`. Both decisions happen before `wordexp` starts
`/bin/sh`.

The same installed-header C object also includes
`compat/x86_64/owned_wordexp_posix_probe.c`. Its quiet cell passes `(` through
the public API while capturing fd 2 and records the pinned source's nonempty
diagnostic as `SOURCE-RED`; it does not compare diagnostic wording, because
the sealed `/bin/sh` fixture controls that wording. Its NOCMD cell proves
`${FOO}`, `${X} ${Y}`, nested defaults, arithmetic parameter expansions,
quoted defaults, pattern-local quoting, arithmetic operators, and
dollar-single quoting. A nine-level parameter default crosses the scanner's
inline frame storage and proves its selected-allocator spill path without
setting a private nesting cap. It keeps naked-brace and malformed-arithmetic controls.
Its marker cases prove that prohibited substitutions do not run through real
parameter nesting, escaped braces, arithmetic single-quote text, a
substring-pattern operand, a nested parameter in arithmetic, a joined
backslash-newline `$(`, or dollar-single quoting.

Pinned musl records the standard parameter form as
`SOURCE-RED parameter-brace-rejected`; the arithmetic parameter form retains
that same source RED. The stale arithmetic-delimiter, joined-continuation, and
dollar-single cases retain `SOURCE-RED command-marker-created`. Escaped-brace
and pattern controls remain ordinary source-match cells. A separate
`WRDE_UNDEF` cell is explicitly a non-qualifying fixed-source observation:
this batch does not add `set -u`, status remapping, or an evaluator/parser for
that unresolved error classification.

Run `./scripts/dev-x86_64.sh libc-owned-wordexp` for the focused static
evidence. Alongside the existing isolated shell-present and shell-unavailable
cases, the runner translates one project-header C object with the installed
static-PIE compiler contract. It links those exact bytes to a pinned-musl
static ET_EXEC oracle and to the owned static ET_EXEC and static-PIE products.
It retains raw status/stdout/stderr for the source scanner control, both POSIX
cells, and the non-qualifying UNDEF observation. The ordinary workload still
runs its source controls; for its quiet malformed input, pinned-musl stderr is
a named source RED and the candidate must be empty. The controlled shell
fixture remains a separately recorded execution input; this receipt does not
claim general shell compatibility or waive an oracle shell failure.

`./scripts/dev-x86_64.sh owned-wordexp` dispatches
`compat/x86_64/run_owned_wordexp.sh` as the separate installed-product
component receipt. The canonical `wordexp` qualification case requires it for
each installed, second-build and extracted dynamic product.  With no arguments it materializes the selected dynamic
and static products, translates the ordinary `owned_wordexp_probe.c` once
through the installed dynamic headers, and links that unchanged object to the
pinned-musl static ET_EXEC oracle, owned static ET_EXEC/static-PIE, and owned
dynamic PIE/non-PIE products.  With a supplied dynamic product it does not
rebuild it; `--static-sysroot` adds the two static modes.  Dynamic PIE and
non-PIE run through both the kernel interpreter and the installed loader's
direct entry, making six product modes when both products are selected.

For every mode and each controlled shell state (`normal`, `missing`,
`inaccessible`, and `invalid`), the receipt retains command argv/status/stdout/stderr
for the ordinary source workload and explicit source scanner control. Its
normal-shell POSIX cells add the quiet diagnostic, parameter-word, frame and
continuation controls, and non-qualifying UNDEF observation. Ordinary and
source-control cells compare with the separately linked pinned-musl oracle.
The POSIX correction cells retain their exact pinned failures as named source
RED observations and require the candidate's positive transcript; the UNDEF
cell remains a source observation rather than a pass claim. It seals the
installed headers, one workload object, link receipts and ELF validation,
products, compiler/linker inputs, and every declared regular file, alias, and
fixture device in each actual execution root. The source, selected products, fixed compiler/linker
and shell tools, shared pinned-musl qualification inputs, and retained shell
fixture are frozen before compilation and required unchanged after all cells;
the linker is resolved before the first product link. Those roots contain the exact copied product files,
the relevant consumer and oracle, and a copied `/bin/sh` loader closure plus a
private Linux character `/dev/null` (type `char-device`, major `1`, minor `3`,
mode `0666`). The device is sealed by type, device numbers, and mode; it has no
content hash and the evidence reader never opens it. The shell closure is
explicitly an external fixture, not an owned runtime provider or a
shell-semantics claim. In the dynamic roots,
the fixture's pinned-musl `/lib/ld-musl-x86_64.so.1` replaces only the
product's unused compatibility alias of that same name.  The required
`/lib/ld-crabc-x86_64.so.1` entry remains the copied product loader for both
candidate entries; the receipt records this exceptional external alias path
and rejects every other alias change.  Successful and failed
runs remain under `.work/x86_64` for replay.

Run `python3 -B compat/x86_64/owned_wordexp_evidence.py capture-expected-inputs DYNAMIC_SYSROOT` in the pinned native image, adding `--static-sysroot STATIC_SYSROOT` when both product modes are selected. It retains a separate expected native tool/oracle seal; supplied products are validated but never rebuilt. A host replay must provide that independently captured file:
`python3 -B compat/x86_64/owned_wordexp_evidence.py validate --report REPORT
--expected-inputs EXPECTED_INPUTS`. It reconstructs a retained receipt on the
host and requires the fixed
`/workspace` source-mount translation, current source/product/header/object
identities, sealed retained pinned-musl inputs, exact retained link receipts
and ELF observations, and exact execution-tree bytes, modes, aliases, raw
results, and expected transcripts.  This proves only the bounded
installed-product component; it does not qualify a family or public support.

The separate expected-input seal compares the native compiler, linker, oracle
compiler, shell, timeout, chroot, and `ldd` identities with both retained
before/after input maps. It also compares the full pinned-musl oracle identity,
including the qualified loader and static archive. Product drivers remain bound
to the selected product internally. The caller checkout still checks the
oracle wrapper against `docker/x86_64-musl-oracle-gcc`; the fixture's `/bin/sh`
and `/lib/ld-musl-x86_64.so.1` closure remain bound to the sealed shell tool,
actual `ldd` output, and qualified pinned-musl runtime.
