# Owned local group database

The installed Linux/x86-64 products provide `getgrnam`, `getgrgid`,
`getgrnam_r`, `getgrgid_r`, `getgrent`, `setgrent`, `endgrent`, `fgetgrent`,
`putgrent`, `getgrouplist`, and `initgroups` through
`libc/src/c_abi/x86_64/owned_group.rs`. This is a conventional local
`/etc/group` C ABI leaf. It does not widen the frozen private archive, select
the AArch64 baseline, or alter the Rust facade's snapshot database contract.

The source oracle is musl 1.2.6, release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license. The
pinned release SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`; its
repository provenance is in `compat/upstreams.toml`.

| musl source | Owned definition |
| --- | --- |
| `src/passwd/getgrent_a.c`: `atou`, `__getgrent_a` | `unsigned_decimal`, `next_record` |
| `src/passwd/getgr_a.c`: local-file part of `__getgr_a` | `lookup` |
| `src/passwd/getgr_r.c`: `getgr_r`, public wrappers | `lookup_reentrant`, `getgrnam_r`, `getgrgid_r` |
| `src/passwd/getgrent.c`: globals and public entries | `ENUMERATION`, `SHARED_*`, `getgrent`, `setgrent`, `getgrnam`, `getgrgid`; weak same-address `endgrent` alias |
| `src/passwd/fgetgrent.c` | `STREAM_*`, `fgetgrent` |
| `src/passwd/putgrent.c` | `putgrent` |
| `src/passwd/getgrouplist.c`: local record scan | `getgrouplist` |
| `src/misc/initgroups.c` | `initgroups` |

The profile deliberately removes musl's nscd query routes. `getgr_a.c` can
query nscd after a local miss or qualifying local-path error; `getgrouplist.c`
can query it before scanning the local file. This leaf never opens an nscd
socket, starts NSS, loads a provider, retains an identity cache, or falls
through to another source. A local `getgr*` lookup miss returns the ordinary
zero/null result. The local-file branch of `getgrouplist` retains musl's special
`ENOENT`/`ENOTDIR` result: it returns the primary gid and count while leaving
`fopen`'s errno observable. Other local open and all local read errors return
`-1` with their local errno. Reachable nscd behavior is intentionally not
claimed. An isolated seccomp child kills socket attempts: pinned musl takes its
source-defined query route while the owned local-only result completes without
a socket syscall.

The parser keeps musl's C-byte behavior. It skips malformed records
individually and chooses the first valid duplicate name or gid. Empty numeric
fields become zero; unsigned decimal gid accumulation wraps at 32 bits; signs
and spaces stop numeric parsing. No UTF-8 validation, comment convention,
delimiter escaping, or whole-file snapshot policy is added. The source removes
the final byte returned by `getline`, so an unterminated final record loses its
last byte; CRLF leaves the carriage return in the final member. Member vectors
preserve empty members and source order.

The reentrant lookups own their FILE, line, and member-vector allocation state.
They preserve musl's ERANGE calculation: the caller needs the whole current
`getline` capacity, aligned member pointers, the terminating member pointer,
and the source's 32-byte reserve. On ERANGE, `*result` is null and the caller
buffer remains unmodified. Returned pointers borrow the caller buffer only on
success. Allocation and local read errors set their positive error result and
errno.

Enumeration and non-reentrant lookup share one record, line, and member-vector
allocation. A lookup opens its own local FILE without moving the enumeration
cursor. `setgrent` and weak same-address `endgrent` close that cursor without
freeing shared result storage; the next `getgrent` opens a new close-on-exec
FILE. `fgetgrent` has a separate global result. Callers serialize each
shared-result group and all uses of its borrowed pointers; a later lookup,
EOF, or error can replace or free the prior backing bytes. Independent `_r`
calls and `getgrouplist` use call-local parsing state.

`getgrouplist` starts with the supplied primary gid, then appends every local
matching group in file order, including duplicates. If its output array is too
small it returns `-1`, writes the required count, writes the available prefix,
and leaves errno unchanged. `initgroups` retains musl's 32-gid stack attempt
and 50% retry growth, then delegates the final transition to the selected
`credentials::setgroups` boundary. That transition is process-sensitive:
qualification calls it only in a disposable chroot child and does not claim
musl's all-thread credential rendezvous.

The module uses the existing owned `StandardStream` FILE engine and its stream
locks, cancellation exclusions, and fork registry. It does not introduce a
second parser framework, FILE representation, account lock, allocator, or
dependency. Cancellation is disabled around the source-defined record,
allocation, and shared-storage intervals and restored afterward. The existing
FILE/fork owner remains responsible for inherited buffering and shared kernel
file position; the cursor is not a snapshot.

Run `./scripts/dev-x86_64.sh owned-group [DYNAMIC_SYSROOT]`. The runner compiles
one installed-header application object, then links and executes those same
bytes with pinned musl, owned static, static-PIE, and dynamic PIE/non-PIE
products. Dynamic programs run by normal kernel entry and direct owned
interpreter entry. Every workload executes in a checkout `.work` chroot with a
synthetic writable `/etc/group`; it never reads host account data. The optional
product argument supports the `group` dynamic-qualification case for each
installed product.

The matrix checks byte parsing, duplicate first-match lookup, raw bytes, CRLF,
unterminated records, exact ERANGE capacity, static record/weak-alias identity,
cursor reset and close-on-exec, caller-owned FILE EOF/read errors, literal
`putgrent` output, group-list ordering and capacity, the source-defined
`getgrouplist` missing/nondirectory primary-gid result, other local open/read
failures, the socket omission, concurrent `_r` calls, forked cursors, pending
cancellation, allocation cleanup and recovery, and isolated `initgroups`.
It verifies the eleven providers in static archives/final images and in the
dynamic provider, then compares stdout and stderr for every same-object
scenario.

Provider accounting assigns all eleven names to the planned
`x86-owned-static-runtime` roster in `compat/x86_64/parity.toml`, removes them
from the deferred C ABI group, and regenerates the checked inventory,
disposition, visibility, and AArch64-derived inventory views. That accounting
does not qualify a live dynamic product, complete the users/C ABI family, or
promote native x86-64 support.
