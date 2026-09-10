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
The ordinary wordexp workload also runs these checks. The existing dynamic
catalog's pattern workload repeats them in each installed and extracted replay,
including the error code, unchanged errno, and empty word-vector ownership.
The controlled shell fixture remains a separately recorded execution input;
this scanner receipt does not claim general shell compatibility or waive an
oracle shell failure.

`compat/x86_64/run_owned_wordexp.sh` is the separate installed-product
component receipt.  With no arguments it materializes the selected dynamic
and static products, translates the ordinary `owned_wordexp_probe.c` once
through the installed dynamic headers, and links that unchanged object to the
pinned-musl static ET_EXEC oracle, owned static ET_EXEC/static-PIE, and owned
dynamic PIE/non-PIE products.  With a supplied dynamic product it does not
rebuild it; `--static-sysroot` adds the two static modes.  Dynamic PIE and
non-PIE run through both the kernel interpreter and the installed loader's
direct entry, making six product modes when both products are selected.

For every mode and each controlled shell state (`normal`, `missing`,
`inaccessible`, and `invalid`), the receipt retains command argv/status/stdout/stderr,
requires a zero result and the exact probe transcript, and compares
both executables with the separately linked pinned-musl oracle.  It seals the
installed headers, one workload object, link receipts and ELF validation,
products, compiler/linker inputs, and every regular file and alias in each
actual execution root.  Those roots contain the exact copied product files,
the relevant consumer and oracle, and a copied `/bin/sh` loader closure plus
private `/dev/null`; the shell closure is explicitly an external fixture, not
an owned runtime provider or a shell-semantics claim.  In the dynamic roots,
the fixture's pinned-musl `/lib/ld-musl-x86_64.so.1` replaces only the
product's unused compatibility alias of that same name.  The required
`/lib/ld-crabc-x86_64.so.1` entry remains the copied product loader for both
candidate entries; the receipt records this exceptional external alias path
and rejects every other alias change.  Successful and failed
runs remain under `.work/x86_64` for replay.

`python3 -B compat/x86_64/owned_wordexp_evidence.py validate --report REPORT`
reconstructs a retained receipt on the host.  It requires the fixed
`/workspace` source-mount translation, current source/product/header/object
identities, sealed retained pinned-musl inputs, exact retained link receipts
and ELF observations, and exact execution-tree bytes, modes, aliases, raw
results, and expected transcripts.  This proves only the bounded
installed-product component; it does not qualify a family or public support.
