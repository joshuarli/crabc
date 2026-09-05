# Owned x86 C word expansion

`wordexp` and `wordfree` are private entries of the selected
`x86-owned-static-runtime` aggregate. They do not complete the broader text,
process, shell, dynamic-product, or public x86 support boundary.

The implementation is mapped to musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, licensed under musl's MIT
license. `src/misc/wordexp.c::{do_wordexp,wordexp,wordfree}` maps to
`libc/src/c_abi/x86_64/owned_wordexp.rs`. Its `WRDE_NOCMD` loop at source
lines 43-83 maps literally to
`libc/src/c_abi/x86_64/owned_wordexp_nocmd.rs`: the source's `sq`, `dq`, and
`np` state determine whether a byte is literal, `WRDE_BADCHAR`, or
`WRDE_CMDSUB`. The generic hardened
`libc/src/wordexp_nocmd.rs` remains an AArch64 implementation artifact and
is deliberately not reused as an x86 musl oracle.

In particular, musl classifies
`$((case $A in a) echo x ;; *) echo y ;; esac))` with `WRDE_NOCMD` as
`WRDE_BADCHAR`: its arithmetic-parenthesis count reaches zero at the inner
`*)`, and the following semicolon is then forbidden. A direct `$(echo x)`
remains `WRDE_CMDSUB`. Both decisions happen before `wordexp` starts
`/bin/sh`.

Run `./scripts/dev-x86_64.sh libc-owned-wordexp` for the focused static
evidence. Alongside the existing isolated shell-present and shell-unavailable
cases, the runner translates one project-header C object with the installed
static-PIE compiler contract. It links those exact bytes to a pinned-musl
static ET_EXEC oracle and to the owned static ET_EXEC and static-PIE products,
then checks the two pre-shell scanner results and receipt object identities.
The ordinary workload also runs these checks, so the existing dynamic catalog
retains the regression in each installed and extracted replay.
The controlled shell fixture remains a separately recorded execution input;
this scanner receipt does not claim general shell compatibility or waive an
oracle shell failure.
