# Owned POSIX filesystem composition

The installed native x86 owned products compose existing source-mapped C
providers for `__xstat`, `__lxstat`, `__fxstat`, `__fxstatat`, `alphasort`,
`ftw`, `nftw`, `readdir_r`, `scandir`, `telldir`, `versionsort`, `mktemp`,
`name_to_handle_at`, `open_by_handle_at`, `tempnam`, `tmpnam`, and `lchmod`.
`x86-owned-static-runtime` selects the already verified `x86-file-handles` and
`x86-temporary-names` leaves alongside its existing directory and traversal
features. The default selected-static archive retains its prior provider
boundary.

| Pinned musl 1.2.6 source | Installed owner and C entries |
| --- | --- |
| `src/stat/__xstat.c` | `compat_exports.rs`: historical `__xstat`, `__lxstat`, `__fxstat`, and `__fxstatat` aliases; their version word is ignored as in musl. |
| `src/dirent/alphasort.c`, `readdir_r.c`, `telldir.c`, `versionsort.c`, and `scandir.c` | `directory_streams.rs`: directory cursor, comparator, and allocated result-list entries. |
| `src/legacy/ftw.c` and `src/misc/nftw.c` | `filesystem_traversal.rs`: callback walk and its installed disable/walk/restore cancellation-state interval. |
| `src/temp/mktemp.c` and `src/temp/__randname.c` | `mktemp.rs` and `temp_name_random.rs`: mutable trailing-`X` absent-name observation. |
| `src/linux/name_to_handle_at.c` and `src/linux/open_by_handle_at.c` | `file_handles.rs`: raw Linux 5.10 calls over caller-owned variable-sized `struct file_handle` storage. |
| `src/stdio/tmpnam.c` and `src/stdio/tempnam.c` | `temporary_names.rs`: static or caller buffer `tmpnam`, and allocator-owned `tempnam` output. |
| `src/stat/lchmod.c` | `owned_filesystem_mechanisms.rs`: the existing `fchmodat(AT_SYMLINK_NOFOLLOW)` source path selected for installed products. |

Run `./scripts/dev-x86_64.sh owned-posix-filesystem` for the focused matrix.
One object is compiled with an installed dynamic driver, linked unchanged by
pinned musl, owned static, owned static-PIE, owned dynamic PIE, and owned
dynamic non-PIE drivers. Dynamic runs use both kernel interpreter resolution
and direct `/lib/ld-crabc-x86_64.so.1` entry. Archive, final static, and shared
ELF tables must each contain one strong global/default provider for every
selected spelling. Static links retain sealed-driver receipts; dynamic links
retain ordinary driver receipts. The receipt audit validates each static or
dynamic product's complete manifest payload before trusting it, binds the
single workload object and hash, exact selected runtime records and linker
trace, output, mode, and ELF boundary, and rejects application DSOs or runtime
imports. A supplied extracted dynamic product receives that full payload check
before the runner creates mutable evidence.

The workload proves arbitrary stat-version aliases and ordinary kernel errors;
directory end/cursor behavior, C-byte and version comparison, selector-owned
`scandir` allocation and failure output; valid-directory-fd relative
`__fxstatat` and `AT_SYMLINK_NOFOLLOW`; and a deterministic four-node
`ftw`/`nftw` callback transcript. The traversal oracle permits the two raw
root-sibling orders exposed by `readdir`, while requiring pre-order root,
parent-before-descendant, complete subtree-before-next-sibling, callback kind,
and `nftw` level invariants. It also proves abort, zero-descriptor-limit
behavior, and deferred cancellation after restoring the source cancellation
state. It checks malformed and absent-name legacy temporary paths, `tmpnam`
buffer ownership, `tempnam` allocation and length rejection, and the inherited
`lchmod` symlink result.

File handles run only inside each disposable chroot. The fixture creates one
regular file below `/work` and uses a readable pathname plus caller-owned,
non-null variable-sized storage on every call. A successful handle is
validated against the reopened file when authority permits it. The matched
oracle/product transcript retains each raw return and `errno` for the source,
missing-path, and invalid-directory-fd calls, and for actual-handle reopen
calls when a handle exists; filesystem support or authority therefore cannot
mask a difference. The workload never uses a returned temporary pathname or
file handle to mutate a host path.

`posix-filesystem` is a required owned dynamic qualification case for installed,
second-clean, and extracted products. Its inclusion records source-bound
product evidence only. It does not promote a runtime family, public x86
support, a Rust facade, general temporary-file policy, handle allocation, or
filesystem authority policy.
