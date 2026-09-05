# Installed ELF symbol scope and interpreter alias evidence

ELF symbol lookup follows object search order for both weak and strong
exported definitions. A later strong definition does not displace an earlier
weak definition. A protected definition remains externally visible while
references inside its defining DSO bind locally. Hidden definitions are not
exported; an unresolved weak function reference remains null.

The source oracle is pinned musl 1.2.6 `ldso/dynlink.c:find_sym2` (accepted
bindings and first matching definition), `do_relocs` (unresolved weak
references), and `do_dlsym` (handle and global scope). Installed compiler and
linker output supplies ordinary ELF protected/hidden visibility. This gate
checks the resulting dynamic symbol attributes before executing applications.
It complements the local/global promotion and caller `RTLD_NEXT` cases in
`run_general_dynamic_dlopen.sh`.

`general_dynamic_elf_scope.c` and `run_general_dynamic_elf_scope.sh` compare
initial dependency and runtime `RTLD_GLOBAL` load ordering, both provider
orders, PIE, and non-PIE against the separate pinned musl runtime: eight cases
per arm. Assertions distinguish global search, DSO handle lookup, internal
protected binding, hidden lookup, and absent weak relocation. The candidate
root contains only its installed runtime and the owned-driver-built fixtures.

Each candidate also executes `/lib/ld-musl-x86_64.so.1` directly, and executes
a derived application whose sole byte change is the padded `PT_INTERP`
pathname selecting that compatibility alias. The original owned-driver
artifact and receipt remain untouched. The harness parses the ELF program
headers and verifies the original canonical pathname before creating this
fixture; it neither relaxes driver policy nor supplies foreign runtime code.
The alias must resolve to `ld-crabc-x86_64.so.1`. These sixteen additional
entries compare against the same musl observable result.

The leaf accepts one installed product path and covers both executable modes
itself. Run it for each clean installation and the extracted package:
`bash compat/x86_64/run_general_dynamic_elf_scope.sh "$product"`.
