# Selected string and temporary weak aliases

`run_owned_string_temporary_alias_contract.sh` checks the selected x86-64
same-definition aliases for `stpcpy`, `stpncpy`, `strchrnul`, `memrchr`, and
`mkostemps`. Run it inside the exact pinned native container owned by
`scripts/dev-x86_64.sh`:

```sh
bash /workspace/compat/x86_64/run_owned_string_temporary_alias_contract.sh \
    [STATIC_SYSROOT DYNAMIC_SYSROOT]
```

With no arguments it builds disposable products below `.work/x86_64`; supplied
products must be physical sealed owned products below that same checkout tree.
The component remains standalone so this focused proof does not add a
dispatcher command.

Pinned musl 1.2.6 maps `src/string/stpcpy.c`, `stpncpy.c`, `strchrnul.c`, and
`memrchr.c` to `libc/src/c_abi/x86_64/string_copy.rs`, `byte_strings.rs`, and
`memory_search.rs`. `src/temp/mkostemps.c` maps to
`libc/src/c_abi/x86_64/temporary_objects.rs`. Each Rust item emits the hidden
`__*` provider and its public weak same-address spelling; `strcpy`, `strncpy`,
`strchr`, `strrchr`, and the `mkostemp` wrappers call the provider body.

One project-header object links unchanged to pinned musl static and shared
entries and to the owned static/static-PIE and dynamic PIE/non-PIE entries.
The runner retains archive/shared ELF rows, actual executable ELF types,
kernel/direct-loader transcripts, public strong overrides, and fixed
temporary-file observations. It proves only these five alias and immediate
wrapper boundaries. It does not qualify the surrounding string, temporary
object, static, dynamic, ABI, or public-support families.
