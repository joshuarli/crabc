# Stage 16 LTO measurement harness

`run.py` is a bounded, dependency-free measurement prototype for the four
configurations in Stage 16 of `plan.md`:

| ID | Configuration | Build contract |
| --- | --- | --- |
| A | musl static | Controlled `fixtures/static.c` probe linked by `musl-gcc -static -no-pie` against pinned musl |
| B | crabc static | The same C object linked with explicit musl/GCC startup files and `target/debug/libc.a` in a recorded start-group |
| C | crabc build-std | pinned, unmodified Rust sources through `-Z build-std=std,panic_abort`, dynamic crabc runtime |
| D | crabc build-std fat/linker-plugin LTO | `-Z build-std=std,panic_abort`, `lto=fat`, `codegen-units=1`, embedded bitcode, `linker-plugin-lto`, and clang/lld musl target flags |

The Rust fixture has no Cargo dependencies. It allocates and performs
deterministic arithmetic, starts one thread through `std`, and makes explicit
`getpid` and `write` calls through the C ABI. A separate minimal C fixture is
used for A/B so explicit static archive selection and startup remain measurable
without making allocator compatibility a prerequisite. Each fixture's output
is deterministic; the C and Rust lanes deliberately are not treated as a
byte-for-byte workload comparison.

Run from the repository root inside the pinned native Linux/AArch64 image:

```bash
python3 compat/lto/run.py
```

The runner expects Rust `nightly-2026-07-24`, musl `1.2.6` under
`/opt/musl-1.2.6`, and the already-built `target/debug/{libc.a,libc.so,libldso.so}`.
`MUSL_ROOT` or `--musl-root`, `--target-dir`, `--timeout`, and `--report` can
override those paths without changing the pinned version contract. The report
is written atomically to `compat/reports/lto/latest.json` by default (the
repository-wide reports directory is ignored by git).

Every attempted build records the exact Cargo argv, working directory, linker,
RUSTFLAGS, selected environment (and its hash), compiler output hashes and
previews, fixture/toolchain/input hashes, and result status. Statuses are
deliberately distinct:

* `built` means an executable was produced and its ELF contract was inspected;
* `unsupported` means a required host/tool/linker capability is unavailable;
* `unbuildable` means the requested command ran but compiler or linker output
  rejected the configuration;
* `runtime-failed` means the requested executable was produced and inspected,
  but its measured run exited or could not start successfully;
* `invalid` means output was produced but violated the requested ELF shape or
  the no-glibc boundary.

`built` does not silently become an optimization claim. B records the exact
startup/support files, the candidate archive's `llvm-nm` output, and a bounded
link-map snapshot/hash. Selection requires the candidate's exact path or a
member anchor derived from that archive, while the map separately records
whether the pinned musl `libc.a` was selected; musl startup paths are retained
as expected CRT evidence. A missing candidate anchor, a selected musl libc,
a byte-identical result, or a nonzero run prevents B from being counted as a
usable crabc-static measurement. Asking the linker for `libc.a` alone does not
prove that no default archive was also used. D records the requested LTO/linker-plugin flags,
the rebuilt bitcode-bearing archive, and both absolute-path and archive-member
map anchors. If LLD instead selects Rust's self-contained musl archive, or no
candidate anchor appears, D is `invalid`; `whole_program_lto_proven` stays
false until cross-boundary selection is observed.

For the build-std lanes, the report also bounds inspection of intermediate
`*.rlib` files and counts `.llvmbc` section bytes with `llvm-readelf` when
available. D additionally
rebuilds `crabc-libc` in an isolated target directory with embedded bitcode and
records its archive hash, `llvm-nm` output, and bitcode markers. This is positive
provenance for the Rust application/std build and, for D, the candidate crabc
archive only; it is not proof that LLD selected that archive. The final ELF is
expected not to retain those sections, and the external crabc `libc.so` remains
opaque; the report therefore keeps `whole_program_lto_proven` false.

For each built executable the report uses `llvm-nm`, `readelf` (or
`llvm-readelf`), and `objdump` (or `llvm-objdump`) and records symbol counts and
hashes, disassembly/file evidence, `.text` bytes, full file bytes, and a copy
stripped with `llvm-strip`/`strip`. It also records a raw runtime result with
wall time and Linux `ru_maxrss`; the latter is explicitly marked as a
cumulative `RUSAGE_CHILDREN` delta rather than a benchmark-quality isolated
peak-RSS result. `strace -f -c` syscall counts are included when `strace`
exists, otherwise the syscall measurement is explicitly `unsupported`.
The report separately marks whether the fixture's named `mix`, `workload`, and
`libc_probe` helpers remain in the inspected symbol/disassembly text, and
whether direct `getpid`, `write`, `malloc`, and `free` mentions remain. These
are bounded observations, not proxy claims for cross-boundary LTO.

The macOS Apple-Silicon development host is not a valid measurement target.
Running the harness there writes a report in which all four configurations are
`unsupported` with the host/toolchain reasons. That is setup evidence, not an
invented Linux result. The runner exits zero after writing either a complete or
partial evidence report and exits non-zero only for harness setup errors.

Pure host tests do not require Rust, musl, LLVM, Docker, or glibc:

```bash
python3 -m unittest discover -s compat/lto/tests -p 'test_*.py'
```

## Milestone 12 native `crabc-rs` proof

`m12_run.py` is a separate, bounded representative-application harness. It
does not change the Stage 16 A/B/C/D matrix above. In the pinned native
Linux/AArch64 Docker image, run:

```bash
python3 compat/lto/m12_run.py
```

The default application manifest is
`compat/lto/m12-crabc-rs-fixture/Cargo.toml`; `--manifest` selects another
M12 manifest without assuming a source filename. The stock-`std` comparison
uses `--stock-std-manifest`, defaulting to
`compat/lto/m12-std-fixture/Cargo.toml`. Both manifests carry checked-in lock
files and path-pin `crabc-rs`/`crabc-core` to this repository.

The report records three lanes:

* `control-o3`: the custom no-std application with LTO off;
* `fat-lto`: the same application with fat LTO and embedded bitcode;
* `stock-std-fat`: a build-std `std` application run once with pinned musl and
  once with the staged crabc loader/libc.

For each native lane the verifier extracts the named witness function and
accepts instruction spelling variations (`w8`/`x8`, decimal/hex immediates)
while requiring Linux/AArch64 `getpid` syscall 172 followed by `svc #0`. It
also checks the representative `write` syscall 64 path, records global
undefined-symbol mentions as context, and rejects branch/PLT edges within the
witness to public `getpid`, `write`, or TLS `__errno_location`. This is
semantic assembly/symbol evidence, not a compiler-byte comparison. Rust
`.rlib` `.llvmbc` markers for `crabc-rs` and `crabc-core` are retained as
provenance; they do not prove unique inlining.
`strace -f -c` output is retained as corroboration when available.

The stock-`std` lane compares status and raw stdout/stderr with no
normalization. It explicitly records `lto_into_dynamic_libc_proven: false`:
fat LTO evidence for the Rust application does not establish optimization
inside the dynamically loaded C `libc.so`.
