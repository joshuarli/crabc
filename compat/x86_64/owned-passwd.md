# Owned local passwd database

The installed Linux/x86-64 products provide `getpwnam`, `getpwuid`,
`getpwnam_r`, `getpwuid_r`, `getpwent`, `setpwent`, `endpwent`, `fgetpwent`,
and `putpwent` from the required `users.databases` C roster. Lookup uses only
conventional `/etc/passwd`. Group, shadow, login, utmp, and other account APIs
remain separate work. This slice does not change the frozen private archives,
the AArch64 baseline, or the Rust facade's immutable UTF-8 snapshot contract.

The source oracle is musl 1.2.6, release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT license. The pinned
source archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`;
`compat/upstreams.toml` records repository provenance. The implementation is
`libc/src/c_abi/x86_64/owned_passwd.rs`, selected only by the owned runtime.

| Musl source/function | Owned definition |
| --- | --- |
| `src/passwd/getpwent_a.c`: `atou`, `__getpwent_a` | `unsigned_decimal`, `next_record` |
| `src/passwd/getpw_a.c`: local-file part of `__getpw_a` | `lookup` |
| `src/passwd/getpw_r.c`: `getpw_r`, public wrappers | `lookup_reentrant`, `getpwnam_r`, `getpwuid_r` |
| `src/passwd/getpwent.c`: globals and public functions | `SHARED_*`, `ENUMERATION`, `getpwent`, `setpwent`, `getpwnam`, `getpwuid`; weak same-address `endpwent` alias |
| `src/passwd/fgetpwent.c` | `STREAM_*`, `fgetpwent` |
| `src/passwd/putpwent.c` | `putpwent` |

The deliberate source difference is removal of the entire nscd query branch
following local lookup. NSS, nscd, sockets, caches, plugins, and provider
protocols are outside the profile. An ordinary local miss returns zero and a
null result; a failure to open `/etc/passwd` retains its positive error and
errno. Musl's behavior with a reachable nscd provider is not claimed. The
fixture proves this boundary by killing any attempted socket syscall in an
isolated child: owned lookup completes the local miss, while the pinned musl
child attempts its source-defined provider query and receives SIGSYS.

Parsing retains the source's byte-level behavior. Malformed records are
skipped individually, duplicate lookup keys select their first valid record,
empty numeric fields become zero, and unsigned decimal accumulation wraps at
32 bits. Signs and spaces in numeric fields are rejected. No UTF-8 validation,
comment policy, delimiter escaping, or whole-file snapshot validation is
added. Extra colons remain part of the shell field; CRLF retains the carriage
return. The source unconditionally removes the final getline byte, so an
unterminated final record loses its last byte. Embedded NUL bytes participate
in the source's ordinary C-string scans rather than a new text policy.

The reentrant functions own independent FILE and temporary allocation state.
They preserve musl's use of the entire getline allocation capacity for ERANGE
and copying, including capacity grown for an earlier nonmatching record.
Returned string pointers lie in the caller buffer only when the result is
non-null. ERANGE leaves that buffer untouched; the partially written record
is not promised unchanged and must not be inspected as a successful result.
Clean EOF and read/allocation errors free the temporary line. No new allocator,
stdio buffering algorithm, lock, or dependency is introduced.

Enumeration and non-reentrant lookups share one record and line allocation;
a lookup opens its own FILE and preserves the enumeration cursor. `setpwent`
and its weak alias `endpwent` close that cursor without freeing the shared
line. The next enumeration opens a fresh close-on-exec FILE. `fgetpwent` has a
separate shared record and line and resets its local capacity to zero for each
call, as the source does. Callers serialize each static-record group and all
uses of borrowed results. Subsequent calls, including failures or EOF, can
replace or free string storage. Independent `_r` calls need no account lock.

Cancellation is disabled around source-defined lookup, parsing, allocation,
and cleanup intervals and restored afterward. Pending deferred cancellation
is delivered at a later cancellation point. Existing FILE and fork owners
retain their responsibilities. After fork, FILE buffering is copied while
its underlying open file description can retain a shared kernel position;
this is not an immutable database snapshot or an atomic multi-call cursor.

`putpwent` makes one ordinary owned `fprintf` call with seven fields, unsigned
uid/gid formatting, and a newline, returning zero or minus one. Field colons
and newlines are written literally, as in musl; it supplies no record validation
or escaping. The existing formatter and FILE owner retain buffering, locking,
orientation, error, and cancellation behavior.

Run `./scripts/dev-x86_64.sh owned-passwd [DYNAMIC_SYSROOT]`. The runner builds
one ordinary installed-header application object and links that same object
against pinned musl, owned static, static-PIE, dynamic PIE, and dynamic non-PIE.
Both dynamic modes run through kernel and direct interpreter entry. All
programs run in a checkout `.work` chroot with an isolated writable `/etc`;
no host account files or provider services are used. No mounts or additional
SYS_ADMIN authority are requested. The optional product argument and registered
`passwd` qualification case support every dynamic product independently.

The fifteen isolated cases cover byte parsing and duplicates; exact allocation
capacity and ERANGE; static record identity, weak alias identity, close-on-exec
cursor descriptors, cursor preservation and rewind; caller-owned FILE EOF and
errors; literal output and EBADF; ENOENT, ENOTDIR, EISDIR, injected open/read
errors; the local-only provider boundary; concurrent `_r` calls; inherited
buffered fork cursors; pending cancellation; and allocation failure with
unchanged caller storage, descriptor cleanup and successful recovery. ELF
checks retain all nine defined function providers and the weak `endpwent`
binding, shared address, size and section in oracle/static outputs and the
dynamic provider. Paired stdout/stderr, ordinary driver receipts, and symbol
tables stay in the reported evidence directory.

Provider accounting adds these nine callables and the weak cursor alias to
`x86-owned-static-runtime` in `parity.toml`, removes them from the deferred
owner group, and regenerates callable inventory, disposition, visibility and
the AArch64-derived inventory digest. This is provider accounting only; it
does not promote the still-unqualified owned feature archive or execute any
AArch64 qualification.

The initial regression passed all fourteen original musl scenarios and failed
the owned static link on all nine missing providers. The completed fifteen-case
matrix passes all installed entry modes. Focused dispatcher authority/argument
forwarding and dynamic product/qualification contract tests also pass. This
leaf does not qualify the entire users family, exhaust all underlying FILE or
allocator failures, or establish a live three-product publication receipt.
