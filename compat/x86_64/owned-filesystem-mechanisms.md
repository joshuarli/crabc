# Owned filesystem mechanisms

`owned_filesystem_mechanisms.rs` supplies an installed
`x86-owned-static-runtime` C ABI block for `fchmodat`, `fchown`, `fchownat`,
`mknod`, `mknodat`, `renameat`, `symlinkat`, `statx`, `fallocate`, `lockf`,
`preadv2`, and `pwritev2`. It also replaces that product's default fixed-result
`lchmod` leaf with the source-faithful `fchmodat(AT_SYMLINK_NOFOLLOW)` path.
The frozen default static archive retains its existing unsupported `lchmod`
contract.

The source mapping is pinned musl 1.2.6: `src/stat/fchmodat.c` and
`src/stat/lchmod.c`; `src/unistd/fchown.c`, `fchownat.c`, `renameat.c`, and
`symlinkat.c`; `src/stat/mknod.c` and `mknodat.c`; `src/linux/statx.c`,
`fallocate.c`, `preadv2.c`, and `pwritev2.c`; and `src/misc/lockf.c` map to
`owned_filesystem_mechanisms.rs`. `statx` intentionally diverges from its
source only by omitting musl's old-kernel `ENOSYS` fallback under the Linux 5.10
baseline. The module keeps the shared x86 `struct stat` layout in
`stat_compat.rs` and the musl `/proc/self/fd/<fd>` spelling in
`pathname_lifecycle.rs`; it does not add another public record or a pathname
policy layer.

On the Linux 5.10 baseline, `fchmodat2` is unavailable. The selected
`fchmodat`/`lchmod` path therefore exercises musl's no-follow metadata,
`O_PATH`, and procfd fallback, rejecting a final symlink with `EOPNOTSUPP`.
`fchown` likewise retries a live `O_PATH` descriptor through procfd. `statx`
uses its direct Linux 5.10 syscall; musl's old-kernel `ENOSYS` fallback to
basic `fstatat` metadata is intentionally omitted because the baseline
guarantees `statx`. `lockf` and the positioned vector calls retain the owned
cancellation boundary used by their source paths.

Run `./scripts/dev-x86_64.sh owned-filesystem-mechanisms` for the focused
installed evidence. The runner compiles one workload object with installed
headers, compares it with a pinned-musl static reference, and executes owned
static, static-PIE, dynamic PIE, and dynamic non-PIE applications in separate
chroots. Dynamic applications run through both kernel interpreter resolution and
direct interpreter entry. A read-only proc mount is confined to each disposable
root so the source fallbacks are exercised without granting the workload host
filesystem access. The workload covers relative dirfds, symlink rejection,
`O_PATH` ownership retry, special-node creation, namespace changes, statx
layout/results, range allocation, process-conflicting locks, and current-offset
and positioned vector transfer behavior.

The header provider catalog records the twelve direct names as planned
`x86-owned-static-runtime` additions and `lchmod` as its replacement variant.
The owned dynamic qualification catalog repeats this workload for its installed,
second-clean, and extracted products. Neither catalog entry is family completion,
public x86 support, a Rust facade, general filesystem authority policy, or a
claim that all filesystem APIs are provided.
