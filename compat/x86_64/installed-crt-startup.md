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
modes. Four owned modes also use the same separate empty-array object.
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
source-defined roles; no alias or public descriptor is inferred from a name.

The reader retains complete tables, local/hidden/undefined records and archive
member occurrences. It joins the actual bootstrap and GOT-containing member
extraction, each CRT import, the shared canonical receiver's relocation,
main handoff relocation, and final empty/nonempty linker-array ranges.
The six address-returning assembly bridges are distinct from their linker
boundary names. Function code size is not selected metadata.

The component does not requalify prepared-worker/72-byte descriptor lifetime,
first-bootstrap failure transitions, malformed loader admission, or the full
process-exit family. Those limits remain explicit in the report. Existing
source contracts in `static_tls.rs`, `x86_64_general_relocation.rs`,
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
