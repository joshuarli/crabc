# Native direct interpreter entry

Direct execution of the installed interpreter is part of the native dynamic
runtime contract. The executable pathname is opened directly; it is not
searched through `PATH`. Both owned PIE (`ET_DYN`) and non-PIE (`ET_EXEC`)
consumers use the existing dependency, relocation, TLS, and CRT transaction.

The compatibility oracle is musl 1.2.6, revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, `ldso/dynlink.c`'s `__dls3`
direct-entry branch (MIT license). Its command surface is `--list`,
`--library-path PATH`, `--preload LIST`, `--argv0 STRING`, and `--`;
value-taking options also accept `--option=value`. Repeated options use their
last value, and an invocation name ending in `ldd` selects listing. Invalid options, missing
values, and absent executable operands fail before executing application code.
Invalid command/executable admission exits 1; dependency or relocation failure
exits 127. Listing loads and validates the dependency graph but runs neither
constructors nor the application. Its lines report the interpreter followed
by the original dependency request names, resolved pathnames and load addresses.
A pathname preload or pathname `DT_NEEDED` retains its slashes on the left of
`=>`, even if later short-name lookup discovers the same inode. The owned libc is
a separate `/usr/lib/libc.so`; musl reports its combined loader/libc image.
The differential checks the application dependency and absence of callbacks
without treating those different runtime layouts as an output mismatch.

Executable role and mapping ownership are independent. A kernel-provided
main image is borrowed. A directly opened main image is owned by the admission
transaction and is rollback-eligible until commit. Both have main-image symbol,
COPY-relocation, lifecycle, and runtime-registry semantics. Non-PIE reservation
must reject address collisions rather than overwrite unrelated mappings.

Self relocation must work when Linux supplies `AT_BASE=0`. Direct entry
reconstructs the application argument vector and the executable auxiliary
vector fields before the unchanged owned CRT receives control. Main `$ORIGIN`
uses the admitted executable pathname, while ordinary `PT_INTERP` entry keeps
its existing `/proc/self/exe` discovery contract. Command-line search and preload
values override the corresponding environment values. The conventional system
path file uses the prefix derived from the second-last slash in an absolute
interpreter invocation name. Relative names use the root prefix. Listing uses
the executable's `PT_INTERP` name for this purpose, matching musl.

`x86_64_initial_graph.rs::_start` owns the relocation-free self-base lookup.
`x86_64_direct_entry.rs::prepare` follows `__dls3` for command parsing and
main admission, while `map_elf_for_role` extends the existing checked mapper
with musl `map_library`'s fixed-address executable requirement. Linux 5.10
`MAP_FIXED_NOREPLACE` enforces that requirement without replacing a live map.
`ObjectRole` selects executable/COPY/lifecycle semantics;
`ObjectMapProvenance` and `GeneralInitialLoaderState::rollback` own release.
The kernel-provided main remains impossible to unmap through rollback; an
owned main is released after its dependencies, once. Main admission retains
the existing reserved identity, as musl's direct-entry branch does not assign
the library-deduplication file identity to the executable.

The argv compaction removes only leading pointer slots. Environment pointers,
auxv storage, strings, random bytes, and the initial stack mapping remain
at their original addresses. `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_BASE`,
`AT_ENTRY`, and `AT_EXECFN` identify the admitted application and interpreter
before the existing owned CRT/libc startup consumes them. The candidate
checks the program-header fields against `dl_iterate_phdr`, validates the
entry against the main executable's executable LOAD, and checks the executable
pathname independently of `--argv0`.

Existing initial graph limits, 512-byte admitted pathname storage, and
4096-byte option/search/preload bounds remain explicit selected limits;
this slice does not claim to remove them.

Evidence uses separate installed candidate and pinned-musl roots. Candidate
execution contains only the materialized owned runtime and explicitly built
application inputs. It never invokes musl, host libc, or a host loader as a
fallback. `run_general_dynamic_cli.sh` runs 46 process cases per arm across PIE and
non-PIE: ordinary entry, `--`, separated/equal/repeated options, command path
over environment, preloading, listing and `ldd`, relocated prefix discovery,
invalid options/operands/files and missing dependencies. Listing comparisons
preserve both sides of `=>` for short names, pathname preloads, pathname
`DT_NEEDED`, and a preload later found by a short-name alias. The pathname
`DT_NEEDED` fixture explicitly replaces one same-length dynamic string in an
owned executable; the sealed driver's rejection of pathname dependencies is
unchanged. Every successful
application checks main and DSO constructors, main/worker TLS isolation,
COPY-visible data, `dlopen(NULL)`/`dlsym` main scope, argv and preserved
environment. Main ORIGIN resolves without a proc mount. The aggregate runs
this matrix against both installed and reproducibly extracted products.

The original ordinary musl invocation passed while the installed candidate
segfaulted with `AT_BASE=0`, exit 139. The direct-main rollback test then failed
because only the dependency was released; the fixed owner releases main last.
The relocated-prefix regression failed at graph admission before interpreter
prefix selection was implemented. The source suite additionally reserves a
real mapping, attempts colliding non-PIE admission, and checks that the
original mapping and contents survived.

The first listing comparison exposed basename-only output where musl prints
the original pathname request. All three pathname/alias cases failed before
`initial_load_name_is_short` preserved the first admission's name form,
independently of the later mutable short-name search alias. The focused runner
can select one case with `CRABC_GENERAL_DYNAMIC_CLI_CASE`; the aggregate always
runs the full matrix.
