# Pthread timed probe dynamic byte relation

`owned_pthread_timed_dynamic_authority.require_pthread_timed_probe_functions`
proves that one admitted `contract.o` supplies the eleven behavioral functions
in an ordinary owned dynamic PIE or non-PIE executable. It reads two absolute
physical file paths, starts no process, and raises
`PthreadTimedDynamicAuthorityError` on a mismatch.

The component reader must first admit the probe source/compile command, object,
selected product, tool, owned link receipt, executable mode and execution root.
It calls this function separately for `dynamic-pie-contract` and
`dynamic-non-pie-contract`. Static and static-PIE outputs continue through
`owned_static_link_authority.require_static_functions`, with component-owned
contracts for all eleven probe functions as well as its CRT and provider
roster. This module does not change the shared static proof.

The physical-file API itself does not admit the source object. Before calling
it, the caller must authenticate that exact `contract.o` as the output named
by its admitted Git C source, actual compile argv, environment and tool
provenance, then bind the same object identity to every dynamic link receipt.
This is the established source/command/tool provenance boundary; it is not an
offline C-to-object semantic proof or cryptographic execution attestation.
Consistent changes to an independently admitted object and its correctly
relocated final image can preserve the relation this module proves.

The eleven definitions are `main` and ten local helpers: `deadline_after`,
`wait_ready`, `mutex_holder`, `test_mutex_timedlock`,
`first_spurious_timedwait`, `signaler`, `test_condition_timedwait`, `target`,
`cancelable_joiner`, and `test_join_modes`. Their source functions exactly
cover one `.text` contribution. Each final definition must keep its source
type, binding, visibility, size and relative placement. All bytes outside
relocation fields compare literally, including already-resolved calls between
helpers. The twelve local `.bss` objects retain their source metadata and
relative layout in zero-initialized writable memory. The source transcript
constant must have exactly one aligned occurrence in read-only output memory.

The actual source object contains 49 `R_X86_64_PC32` references to those data
objects or the string, and 52 `R_X86_64_PLT32` calls. PC32 fields are derived as
`S + A - P` from the independently checked final data placement. PLT32 fields
are derived as `L + A - P` from the named import's actual PLT entry. The proof
checks the complete ordinary LLD PLT encoding, its ordinal, its GOT target,
the corresponding `R_X86_64_JUMP_SLOT` symbol and the GOT's initial value. PIE
has the nineteen probe imports; non-PIE adds the CRT's `__libc_start_main` PLT
entry. Dynamic table pointers must select those same retained tables. The
loaded bytes and permissions must agree with section placement, and dynamic
relocations cannot overwrite the proven code, data or PLT/GOT. No displacement
is copied from the final executable into an expected-byte mask.

This is a finite contract for the observed compiler/linker form. Other
function/data rosters, source relocation forms, PLT encodings or dynamic table
forms fail and need separate review. It does not attest compiler execution or
qualify the entire pthread family, loader, CRT or platform.

## Regression

The control that motivated this relation replaces the final
`test_condition_timedwait` prefix `554889` with `31c0c3` (`xor eax,eax; ret`),
skipping that operation while leaving the source object and every other
function byte unchanged. The relation must reject it.

`tests/test_owned_pthread_timed_dynamic_authority.py` takes the original
`contract.o` and the `dynamic-pie-contract` and `dynamic-non-pie-contract`
executables from a directory named by `CRABC_PTHREAD_DYNAMIC_AUTHORITY_FIXTURE`.
Tests admit both original modes without processes and reject helper no-ops,
every actual PC32/PLT32 field change, PLT/GOT/import substitutions, all local
data placement changes, constant corruption, dynamic relocation/table
redirection and mapped byte/permission substitutions. Test scratch stays
beneath checkout `.work`.
