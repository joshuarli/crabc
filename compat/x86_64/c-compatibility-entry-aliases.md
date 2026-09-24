# C compatibility-entry aliases

`run_c_compatibility_entry_aliases.sh` is a bounded native x86-64 installed-product
proof for fourteen musl 1.2.6 compatibility spellings that appeared as missing
public-dynamic inventory rows. It is neither a header expansion, a general stdio
or integer-parser qualification, a filesystem policy, a family completion, nor a
promotion or public-support result.

The source mapping is fixed to musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417` (musl MIT license):

| Pinned source | Native owner | Shape retained by the proof |
| --- | --- | --- |
| `src/stdio/{scanf,fscanf,sscanf,vscanf,vfscanf,vsscanf}.c`, `src/stdio/vfscanf.c` | `libc/src/c_abi/x86_64/stdio_format_scan.rs` | Each `__isoc99_*` spelling is a weak, same-address alias of the existing strong scanning entry. |
| `src/stdlib/strtol.c` | `libc/src/c_abi/x86_64/integer_parse.rs` | Each `__strto*_internal` spelling is a weak, same-address alias of its existing strong `strto*` entry. |
| `src/stat/__xstat.c` | `libc/src/c_abi/x86_64/owned_filesystem_mechanisms.rs` | `__xmknod` and `__xmknodat` are strong wrappers: they ignore `ver`, read the caller `dev_t *`, then call the selected `mknod` or `mknodat` entry. |

`__xmknod` and `__xmknodat` retain that ordinary compatibility behavior: they
ignore `ver`, read the caller `dev_t *` before delegation, and leave the
selected `mknod`/`mknodat` path to supply its normal result and `errno`.
They remain strong `GLOBAL` function definitions in the installed static and
shared artifacts. This does not make the normal direct call an application
interposition guarantee. The installed static archive has one member per
Rust module; [owned-error-reporting.md](owned-error-reporting.md) records the
rule that member extraction lets an application definition replace an
internal reference only where the provider has its own member and the caller
keeps a public call edge. Pinned
musl's separate `__xstat.lo` public-call relocation remains source-oracle
observation. An application-supplied strong `mknod` or `mknodat` is outside
this component's static contract, and this clarification does not alter the
separate shared-libc dynamic-list policy.

The aliases use `.weak` plus `.set`; a Rust forwarding wrapper would make a
second definition and break the source-required ELF address relation. The
historical `__strto*_internal` declarations used by external callers commonly
have a fourth `group` argument. Musl aliases those names to its ordinary
three-argument `strto*` implementation, so the x86-64 ABI accepts that extra
argument and the source target does not inspect it. The probe records both a
zero and nonzero group call without inventing grouping behavior.

The C fixture compiles one object through the selected dynamic product's
installed headers. Its fourteen private declarations are local to the probe;
no public header changes are implied. It links that exact object separately to
pinned musl and supplied candidate static/dynamic products. It executes musl
static ET_EXEC and candidate static ET_EXEC/static PIE, then each dynamic PIE
and non-PIE candidate application through kernel and direct loader entry
against the matching musl dynamic executable, ELF type, and entry mode. The workload
checks direct and `va_list` scan aliases, integer conversion/end pointers,
ignored source version values, unprivileged FIFO creation through both xstat
wrappers, and the invalid-dirfd `EBADF` path.

The runner retains command argv/stdout/stderr/status, source and product hashes,
ELF headers, archive `.symtab`, shared `.dynsym`, and full shared `.symtab`.
`c_compatibility_entry_alias_symbols.py` parses only the requested table at a
time, accounts for every declared index (including index zero), retains archive
member attribution, and rejects missing, duplicate, weakened, or different
address/section/size alias definitions. It does not compare function sizes
between musl and the candidate. The wrappers are checked as strong global
functions, without making a code-size claim.

Run the proof inside the pinned native environment with fresh matching products:

```sh
TMPDIR="$PWD/.work/x86_64/tmp" \
  ./compat/x86_64/run_c_compatibility_entry_aliases.sh \
  --static-sysroot .work/x86_64/c-compatibility-entry-aliases/static \
  .work/x86_64/c-compatibility-entry-aliases/dynamic
```

The default static surface gains the eight aliases already selected by its
existing scanner/integer owners: `__isoc99_{sscanf,vsscanf}` and all six
`__strto*_internal` names. The existing
`x86-stdio-permanent-format-scan` feature archive already selects the next
four aliases, `__isoc99_{scanf,vscanf,fscanf,vfscanf}`; they are inherited by
the owned aggregate and must be accounted as aliases of that feature rather
than as a new aggregate delta. The only new owned-static/runtime providers in
this component are the two strong `__xmknod*` wrappers. Export-roster and
ledger accounting remain a separate integration action; this component does
not modify them.
