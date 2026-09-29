# Owned `nftw` and `ftw` relative traversal differential

`./scripts/dev-x86_64.sh owned-nftw-relative-base [DYNAMIC_SYSROOT]` checks
the relative-path metadata contract exposed by the retained os-test
`basic/ftw/nftw.c` fixture. `owned_nftw_relative_base_probe.c` first runs
`nftw(".", ..., FTW_DEPTH)` after it enters a fresh `/work` that contains only
`./ftw/nftw`. It requires the callback records `./ftw/nftw` with `base == 6`
and `level == 2`, `./ftw` with `base == 2` and `level == 1`, and `.` with
`base == 0` and `level == 0`; each base must point at that callback path's
basename. The probe deliberately preserves those relative callback spellings.
Its controlled process CWD and empty `/work` fixture rule out an ambient harness
root or an unrelated directory entry as the source of a result.

A separate `/cases` tree supplies a regular file, file symlink, dangling
symlink, directory symlink cycle, and inaccessible directory. The process drops
to a non-root uid before traversal. The probe checks callback basename and
level, physical and following classifications, depth-first order, permission
callback order, legacy `ftw` physical behavior, zero and positive descriptor
budgets, missing paths, and callback abort with `errno` preservation. A compact
callback transcript includes order, type, base, level, and callback-visible
`errno`; the runner compares the same installed object against pinned musl
through every owned dynamic entry mode. A candidate-only `FTW_CHDIR` pass
checks callback-visible CWD, repair after callbacks change it, and restoration
on normal and callback-abort exits, because pinned musl ignores that selected
profile option.

Pinned musl 1.2.6 `src/misc/nftw.c` distinguishes the current callback's
`lev.base` from `new.base`, the position passed to the next child through its
`history` record. `filesystem_traversal.rs` follows that protocol in `walk`:
the root callback derives its own base, while a child reads the prior frame's
next-child base. Collapsing those values makes every descendant inherit the
root base and violates `path + ftw->base`. Musl also returns immediately when
the descriptor budget is nonpositive, before it reads either path or callback.
The x86 entry points follow that ordering and leave `errno` unchanged.

The runner first compiles one object with the installed dynamic driver and
uses that unchanged object for a pinned-musl static oracle and an audited owned
dynamic PIE/non-PIE link. Each owned executable runs by kernel interpreter and
direct `/lib/ld-crabc-x86_64.so.1` entry in a separately copied product root;
stdout, stderr, and process status must all match the oracle for ordinary
options. This is a focused installed traversal regression for
`libc/src/c_abi/x86_64/filesystem_traversal.rs`.
