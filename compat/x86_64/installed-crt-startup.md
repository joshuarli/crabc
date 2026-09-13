# Installed process entry and lifecycle evidence

`installed_crt_startup_evidence.py` observes one finite installed boundary:
CRT entry → initial process/TLS state → executable initialization → main →
ordinary process finalization. The contract names twelve identities: six
linker arrays and `_GLOBAL_OFFSET_TABLE_`, hidden static bootstrap, owned
handoff, main attachment/accessor, and the conventional-libc startup wire.
It neither adds public symbols nor qualifies the CRT, libc or loader family.

`collect` accepts `--static-preparation`, `--static-product`,
`--dynamic-product`, `--historical-facts` and fresh `--output`, all physical
checkout `.work` paths. It uses supplied products without building a runtime.
`validate-report --report PATH` and `validate_report(root, path)` reconstruct
retained inputs, command plan, complete ELF facts, exact link receipts,
private execution roots and outputs on the host without compiler execution.
All duplicate/abbreviated options reject. The source is clean and sealed;
selected runtime files must match their historical producer revision while
collector/probe files bind the current collector. Historical complete facts
only correlate input bytes: fresh raw facts observe them independently.

The normal installed-header probe object is compiled once with PIC and
initial-exec TLS and linked unchanged through eleven explicit runtime/CRT
modes. Four owned modes also use the same separate object with empty
application arrays. Static libc still contributes its exact source-owned init
and fini entries from `allocator_mimalloc_lifecycle.rs`; the reader joins their
archive slots, final ranges and link-map contributions without evaluating
allocator bodies. Dynamic main empty-array cases have genuinely empty ranges.
Static ET_EXEC/static PIE use their installed driver; owned dynamic PIE and
non-PIE use the installed dynamic driver and its actual receipts. Ordinary
conventional entry explicitly links retained pinned-musl crt1/Scrt1 with the
selected candidate shared libc and loader. The static product's default
Scrt1 is separately exercised with pinned musl and its weak-null handoff.
The musl references consume retained explicit CRT/libc inputs with the same
pinned linker, with no ambient target runtime search.

The reader requires the actual `__stack_chk_guard` compiler-protocol object
import, which selects musl static archive's real guard initializer. The pinned
freestanding GCC specs suppress generated stack protection; no compiler-canary
execution claim is made. The lifecycle probe verifies initialized TLS and
TBSS, errno, environment,
and the masked AT_RANDOM guard before application initialization. It retains
preinit, legacy init, init-array, main, atexit, reverse fini-array and legacy
fini observations. Musl omits main preinit; the owned-only P prefix stays an
explicit difference. At main, `dl_iterate_phdr` observes exact weak OBJECT
GLOB_DAT slots: owned handoff non-null/conventional slot null, conventional
snapshot non-null/no owned handoff, default CRT weak-null, oracle neither.
The borrowed record is read but private callbacks are not called by the probe.
The 32-byte owned carrier and separate 88-byte conventional snapshot preserve
source-defined roles. Schema v3 adds a separate private descriptor-handoff
account: `dynamic-crabc-dynamic-attach.o` has exactly one weak, undefined
`NOTYPE` GOTPCREL descriptor reference, and each owned PIE/non-PIE normal and
empty final main image has exactly one weak undefined `GLOB_DAT` slot. Static,
conventional, default, and oracle final images have no such slot. In owned
mode the probe reads that one main-image slot and verifies 72-byte/8-aligned
geometry, magic/version, dynamic mode, loader owner, acquire-READY,
generation, and FS TP/DTV coordinates. This is private main-image transport,
not a shared-libc consumer or a loader ELF provider definition.

The reader retains complete tables, local/hidden/undefined records and archive
member occurrences. It joins the actual bootstrap and GOT-containing member
extraction, each CRT import, the shared canonical receiver's relocation,
main handoff relocation, and final empty/nonempty linker-array ranges.
`artifact_relocations` also requires the exact caller relations in six owned
CRT objects: static bootstrap, weak handoff transport, dynamic attachment,
and the attach object's defined hidden record callback. Each relation retains
its PLT32 or GOTPCREL kind, PC-relative addend, binding, visibility, and
defined-versus-undefined symbol status. Missing, duplicate, or changed relations
fail reconstruction; merely listing a symbol does not prove its caller uses it.
The six address-returning assembly bridges are distinct from their linker
boundary names. Function code size is not selected metadata.

Schema v3 makes the finite descriptor-admission control part of the same
`installed_crt_startup_evidence.py` transaction. After it links the normal
owned PIE probe, the collector derives four single-field ELF copies from that
one authenticated final main: `OBJECT` instead of `NOTYPE`, global instead of
weak binding, `JUMP_SLOT` instead of `GLOB_DAT`, and addend one instead of
zero. It also compiles `installed_crt_startup_descriptor_dso.c` through the
selected dynamic driver to one retained PIC object. That object has exactly
one weak undefined `NOTYPE` `R_X86_64_REX_GOTPCRELX` request with addend
minus four. A separate selected-driver shared link consumes that object and
seals the DSO's no-interpreter/`SONAME`/`DT_NEEDED libc.so` role. A second
selected-driver PIE link consumes the unchanged normal probe object and that
exact DSO, sealing its owned interpreter and exact
`DT_NEEDED descriptor-rogue-dso.so, libc.so` order. The ordinary positive
matrix remains unchanged. The collector
copies each finite input into its existing `candidate-root`, whose loader and
manifest are exact sealed dynamic-product inputs; it never builds, substitutes,
or self-authenticates an interpreter.

The DSO and endpoint role reader takes `DT_NEEDED` and `DT_SONAME` only from
the one `PT_DYNAMIC` virtual range mapped by one `PT_LOAD`; SHT_DYNAMIC cannot
replace loader-visible facts. Its retained SHT_DYNAMIC, SHT_DYNSYM, and
SHT_RELA offsets must also agree with `PT_DYNAMIC`, `DT_STRTAB`, `DT_SYMTAB`,
and `DT_RELA` respectively. This preserves byte offsets for the four finite
main mutations without allowing stale section headers to describe a different
loader request.

For both kernel and direct entry, the five malformed inputs must exit 127,
write no stdout, and write only `reloc` to stderr before probe `main` can
produce its normal transcript. Replay rebuilds the command plan from the
current source, retained tools, selected product cohort, and source-generated
mutation policy; it independently rechecks the copied candidate-root tree,
mutation bytes, DSO and endpoint wire shape, raw commands, statuses, and
streams. It also reconstructs the two finite schema-2 link receipts: source
object, selected runtime and linker identities, direct DSO input, exact command
and trace, output, and manifest. The general ordinary-link reader intentionally
does not admit application DSOs; this component owns only this one named direct
DSO relation. A previous source/product cohort that admits a malformed wire cannot
produce a schema-v3 receipt. It remains an observed development failure, not
a waiver or a qualified green result.

The earlier rebuilt-interpreter twelve-cell development matrix and its source
tests remain author evidence under ignored `.work/x86_64` only. This reader
does not consume or reseal that matrix: a component receipt can use only its
selected installed dynamic product, finite linked inputs, and canonical plan.

The component does not requalify prepared-worker/72-byte descriptor lifetime,
release-READY publication ordering, first-bootstrap failure transitions, or
the full process-exit family. The admission account does not establish release order,
pointer lifetime, generation transitions, or fork ownership. Those limits
remain explicit in both reports. Existing source contracts in `static_tls.rs`, `x86_64_general_relocation.rs`,
`conventional_startup_v1.rs` and their owner tests remain authoritative; a
successful ordinary consumer is not a replacement for their negative proofs.
No current-source receipt is transferred to a later product or collector.

Collection requires the pinned native core image identity in
`CRABC_X86_PUBLIC_DATA_IMAGE_ID`, `LC_ALL=C`, root plus SYS_CHROOT, network
none, source/products read-only, and fresh output/scratch writable. Use the
retained actual Docker launcher beside evidence. No ptrace is required: the
application observes its own admitted initial graph. Private execution copies
preserve runtime bytes and executable interpreter permissions; input products
are sealed before/after. `family_completion`, `runtime_qualification`,
`selection_closure` and `public_support` stay false.
