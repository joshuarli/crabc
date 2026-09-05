# Owned `nftw` relative `FTW.base` regression

`./scripts/dev-x86_64.sh owned-nftw-relative-base [DYNAMIC_SYSROOT]` checks
the exact relative-path metadata contract exposed by the retained os-test
`basic/ftw/nftw.c` fixture. `owned_nftw_relative_base_probe.c` runs
`nftw(".", ..., FTW_DEPTH)` after it enters a fresh `/work` that contains only
`./ftw/nftw`. It requires the callback records `./ftw/nftw` with `base == 6`
and `level == 2`, `./ftw` with `base == 2` and `level == 1`, and `.` with
`base == 0` and `level == 0`; each base must point at that callback path's
basename. The probe deliberately preserves those relative callback spellings.
Its controlled process CWD and empty fixture root rule out an ambient harness
root or an unrelated directory entry as the source of a result.

Pinned musl 1.2.6 `src/misc/nftw.c` distinguishes the current callback's
`lev.base` from `new.base`, the position passed to the next child through its
`history` record. `filesystem_traversal.rs` follows that protocol in `walk`:
the root callback derives its own base, while a child reads the prior frame's
next-child base. Collapsing those values makes every descendant inherit the
root base and violates `path + ftw->base`.

The runner first compiles one object with the installed dynamic driver and
uses that unchanged object for a pinned-musl static oracle and an audited owned
dynamic PIE/non-PIE link. Each owned executable runs by kernel interpreter and
direct `/lib/ld-crabc-x86_64.so.1` entry in a separately copied product root;
stdout, stderr, and process status must all match the oracle. It is a focused
regression for `libc/src/c_abi/x86_64/filesystem_traversal.rs`, not a general
filesystem or runtime-qualification claim.
