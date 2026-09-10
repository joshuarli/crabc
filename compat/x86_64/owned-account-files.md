# Owned account-file C ABI

The owned Linux/x86-64 runtime selects thirteen conventional-account-file C
ABI entries: `cuserid`; `getusershell`, `setusershell`, and `endusershell`;
and `endspent`, `setspent`, `getspent`, `fgetspent`, `getspnam`,
`getspnam_r`, `putspent`, `lckpwdf`, and `ulckpwdf`. The implementations are
`libc/src/c_abi/x86_64/owned_cuserid.rs`, `owned_usershell.rs`, and
`owned_shadow.rs`; they are selected only with `x86-owned-static-runtime`.
They do not alter the frozen default archive, the AArch64 baseline, or the
Rust facade.

This is local C ABI compatibility machinery over `/etc/passwd`, `/etc/shadow`,
`/etc/tcb/NAME/shadow`, and `/etc/shells`. It is not an authentication service.
Password-hash fields are copied as opaque bytes. It adds no password hashing,
PRNG, provider/NSS lookup, cache, plugin, policy, account mutation, or new
dependency.

## Source provenance and mapping

The source oracle is musl 1.2.6 release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, licensed under musl's MIT
license (`COPYRIGHT`). The pinned archive is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`
(SHA-256); repository provenance is in `compat/upstreams.toml`.

| Source file and SHA-256 | Owned mapping |
| --- | --- |
| `src/legacy/cuserid.c` — `2b535e75996253ab9eb43d77690fb7487538b0c5516722c43a4fd688f365ff40` | `owned_cuserid.rs`: `cuserid`, with the existing owned local `getpwuid_r` provider |
| `src/legacy/getusershell.c` — `cc9db6faa24725cfc696c9b2cf1d46ca3f936435af6bdc03bc743cce7371d8fa` | `owned_usershell.rs`: `getusershell`, `setusershell`, `endusershell` |
| `src/passwd/getspent.c` — `ff51e025d46e18d362ff37ba68c5025cd18437d4f08e499db2b8e48af3e01f99` | `owned_shadow.rs`: `setspent`, `endspent`, `getspent` |
| `src/passwd/fgetspent.c` — `0e81db6aebfa337e30d478d10a933044d7960a1fd8b8e952a6d250d33b8b504a` | `owned_shadow.rs`: `FGETSPENT_*`, `fgetspent` |
| `src/passwd/getspnam.c` — `dbc13dbbd8fcc7698801cb82845adc1196e5aaa280356fccf5678a7f4fed1466` | `owned_shadow.rs`: `GETSPNAM_*`, `getspnam` |
| `src/passwd/getspnam_r.c` — `f40349a00c75b2d2a8075fdc6a80e54daa9ddc9b162b89cd358a5bc93bd5d884` | `owned_shadow.rs`: `spent_decimal`, `parse_spent`, `close_stream`, `getspnam_r` |
| `src/passwd/putspent.c` — `39cbd6f3f9a82830a7c7772ca1760ab31a92f3d354450d2e332857e22988531b` | `owned_shadow.rs`: `putspent` |
| `src/passwd/lckpwdf.c` — `744d2f5a8b33aabec44f36b31f58ab3b5d845c10b88ede2fa86fce397b06a7a6` | `owned_shadow.rs`: `lckpwdf`, `ulckpwdf` |
| `src/passwd/pwf.h` — `61df7ac8807db4a8f838ca67f96072cc0c62d2be3a114ee06fea77bdc94a523a` | `Shadow` ABI layout and the selected owned stdio, errno, and cancellation boundary |

There are no algorithmic source differences in this slice. The only boundary
choice is already established by the owned runtime: source `malloc` in
`getspnam` crosses an opaque public allocator call edge so same-crate Rust
knowledge cannot fold an ordinary C allocation client into a known allocator
provider. The source allocation remains process-lifetime storage.

## Contract

`getspnam_r` keeps the source's C-byte parser. Empty numeric fields are `-1`,
decimal accumulation uses target-width `long` wrapping, and the final flag
gets the source's conversion to `unsigned long`. A selected matching line must
end in newline; a matching oversized fragment produces `ERANGE`; malformed
matching lines are skipped. The caller result pointer is set null before name
and range validation. Clean scan exhaustion restores entry errno, while source
open and range failures publish their own errno.

The bounded TCB probe opens `/etc/tcb/NAME/shadow` with `O_NOFOLLOW`,
`O_NONBLOCK`, and `O_CLOEXEC`, requires a regular file, and falls back to
`/etc/shadow` only after `ENOENT` or `ENOTDIR`. Symlinks, a reachable
nonregular TCB object, or another TCB error do not become a fallback. The
scan has the source cleanup node around `fgets`; closing on the ordinary and
selected cancellation paths uses the existing FILE/cancellation owner.

`getspnam` retains one static record and one public-allocated fixed 256-byte
line. `fgetspent` retains separate static record and line storage but starts
each call with a local zero capacity. Callers serialize either non-reentrant
API and all use of its returned pointers. Independent caller-buffered
`getspnam_r` calls may run concurrently, subject to its documented C pointer,
range, and non-overlap obligations.

`getspent` returns null and `setspent`, `endspent`, `lckpwdf`, and `ulckpwdf`
are intentional source no-ops. They do not create enumeration, lock-file, or
authentication state. `putspent` writes the source's literal `fprintf` form:
null strings are empty and each signed or unsigned `-1` field becomes empty.
It neither validates nor escapes field bytes.

`getusershell` lazily reads `/etc/shells` in the source's `rbe` mode, or an
in-memory `/bin/sh\n/bin/csh\n` fallback. It skips only lines whose first byte
is `#` or newline, removes only a final newline, and does not rewind an open
stream in `setusershell`. Its shared stream and line have caller serialization
and borrowed-result lifetime requirements. `cuserid` uses the effective UID
through the existing local `getpwuid_r` provider and the source's
`L_cuserid == 20` bound; its null-buffer result is shared storage while a
supplied buffer stays caller-owned.

## Evidence

`compat/x86_64/run_owned_account_files.sh` follows the sealed installed-product
pattern. It compiles one C workload through the installed dynamic driver,
records its installed-header dependency receipt, and links those unchanged
bytes against pinned musl, static, static-PIE, dynamic PIE/kernel, dynamic
PIE/direct-interpreter, dynamic non-PIE/kernel, and dynamic
non-PIE/direct-interpreter paths. Static and dynamic product payloads and
link receipts are validated by `owned_posix_product_evidence.py`; raw status,
stdout, stderr, source-and-installed-header witness objects, symbol tables,
and retained link identities stay in its evidence directory. It accepts
supplied static and dynamic products for replay.

The C and C++ witnesses compile the pinned musl oracle headers, repository
`include/` source headers, and the installed product headers. They assert each
header surface's `struct spwd` LP64 layout, `L_cuserid`, all thirteen function
signatures, and unmangled C linkage. The common C workload is separately
compiled through the installed dynamic driver; its installed-header dependency
receipt binds the exact headers consumed by that linked workload. The
private-chroot probe creates every `/etc` fixture inside the disposable root;
it never reads a host account file. Its cases cover parser fields, malformed
and unterminated records, empty `-1` fields, unsigned flag conversion,
pointer relocation, early errno/result behavior, missing/denied/nonregular/
symlink TCB paths and allowed fallback, static-record lifetime, input/output
errors, source no-ops, reentrant workers, pending cancellation plus the
post-join descriptor count, usershell reset/fallback/EOF/comments/no-final
newline, and effective-UID `cuserid` bounds and storage.

The original absent-provider red check used the same installed-header C
object, ran it against pinned musl, then showed all thirteen unresolved owned
providers in static, static-PIE, dynamic PIE, and dynamic non-PIE links. Its
retained evidence is `.work/x86_64/tmp/owned-account-files.im2VMw`. The runner
keeps that baseline as `--expect-missing` for a source tree before these
providers are selected.

The completed disposable six-path matrix passed at
`.work/x86_64/tmp/owned-account-files.7Q2Inq`; a supplied static-plus-dynamic
product replay passed at `.work/x86_64/tmp/owned-account-files.XF5bL7`. Run
the current matrix with:

```bash
CRABC_X86_64_WORK_DIR="$PWD/.work/x86_64" \
TMPDIR="$PWD/.work/x86_64/tmp" \
./scripts/dev-x86_64.sh owned-account-files
```

This component does not close the broader users/account C ABI family or claim
native x86-64 family completion. It does not qualify general authentication,
NSS, shadow mutation, all FILE/allocator failure paths, or any AArch64 work.
