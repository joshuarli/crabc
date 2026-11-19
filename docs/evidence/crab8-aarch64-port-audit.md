# CRAB-8 aarch64 port audit (2026-11-18)

Independent read-only audit of `crab8/integration` at `337e6022`: every
aarch64-selected branch compared with its x86 counterpart under the port rule
(an x86-only guard is replaced by an architecture-aware check of equal
strength; x86 behavior unchanged). Entries are closed by the commit that fixes
them; this file is the work list for A4/A5, not evidence of a pass.

Root cause: the aarch64 builders skip x86 audits (`build_x86_64_owned_dynamic_sysroot.py`
prints an "aarch64: skipped" list) and many validators short-circuit on the aarch64
product formats even where the aarch64 builder writes the evidence x86 checks.
Fix order: x86 behavior changes (59-64), product defects (33-39), builder evidence
(21-24, 30), validators (1-8, 12, 13, 16, 25-28), driver (2, 18), probes and scripts
(14, 15, 17, 19, 20, 29, 31, 32), tests (40-53), development paths (10, 54-58).

Item 11 is kept by decision: the ledger's family rows are architecture-independent
capabilities; on aarch64 the candidate maps their `.work/x86_64/` receipt roots to
`.work/aarch64/`, and every attached receipt is still produced and validated by the
aarch64 run itself.

## A. Qualification harness (`compat/x86_64/*.py`)

1. **`owned_dynamic_qualification.py:231-262`**
   - x86: reads `dynamic-product-state.json` and `libc-shared.provenance.json` and checks:
     - the schema, the payload binding and `status`;
     - the contract digests;
     - the allocator backend against provenance, plus the audit and promotion flags;
     - the `runtime_v1_published`, `public_support` and `campaign_complete` flags;
     - the modes, profile and qualification fields.
   - aarch64: both aarch64 formats return `manifest, None, None`. Identity is then just `manifest.source_sha256` plus a digest.
   - Weaker: the files exist (written at `build_x86_64_owned_dynamic_sysroot.py:1127-1140`) and are ignored. This feeds `product_identity`, package extraction, Lua admission and the loader-debug reports.
   - Qualifying-path.

2. **`crabc_cc_aarch64_dynamic.py`**, the installed `bin/crabc-cc-dynamic` and a sealed product file, is a reimplementation of the x86 driver with fewer checks:
   - (a) `:23-24` does not call `validate_installation(root)` before compiling or linking. The x86 `execute` does this first, so the installed payload hashes are never verified when the driver runs.
   - (b) There is no final ELF inspection (`owned_dynamic_elf.inspect`/`require_expected`), no inspection sidecar and no link map. Instead `:288-291` does substring checks on readelf output.
   - (c) With direct DSOs only (`if transitive_inputs:` at `:155`), it has neither the undeclared-transitive-`DT_NEEDED` check nor the unresolved-runtime-imports check (x86 `:903-918`).
   - (d) In the closure path it never checks that the linked output's `DT_NEEDED` equals the declared direct roots (x86 `:956-961`).
   - (e) `-static`, `-static-pie` and `--static-et-exec` are not rejected (x86 `:772-773`). They reach `shared.parse_invocation`, which sets a mode the dynamic driver ignores, so the result is silently a dynamic PIE.
   - (f) No dynamic mode is required; it defaults to PIE, where x86 `:777` rejects.
   - Qualifying-path.

3. **`crabc_cc_owned_dynamic.py:220-272`**
   - x86: `validate_loader_provenance`.
   - aarch64: an ELF header check plus `samefile(libc.so, loader)`. The `required` roster drops loader provenance and the receipt/ELF modules.
   - Weaker: the shipped `loader.provenance.json` is never validated by the driver.
   - Qualifying-path.

4. **`owned_posix_product_evidence.py`**
   - Static, `:670-698`: drops `validate_native_compiler_tool_records(producer_tools)`, the `installed` record and the sealed-driver format/path/status/modes checks.
   - Dynamic, `:749-755`: delegates to `driver.validate` only. It loses the producer-tools, physical-path, `_validate_product_tree`, loader-provenance and link-input-mode checks.
   - `validate_dynamic_product_source`, `:882-885`: checks only the manifest source, not the materialization state.
   - Qualifying-path.

5. **`owned_posix_static_products.py:184, 198-208`**
   - aarch64 hardcodes `allocator_backend = "accepted-c" if arm` instead of reading the manifest.
   - It drops the per-product backend-agreement check.
   - It replaces `producer_tools` with a hash of `crt.commands.json`.
   - Qualifying-path.

6. **`crabc_cc_static.py:1235-1290` (`execute_aarch64`)**
   - A standalone aarch64 static product gets no `validate_crt_provenance`.
   - It gets none of the `static_product_payload_files` semantics (source-seal syntax, sealed-driver binding, status and modes) and no `usr/include` or `REQUIRED_RUNTIME_PATHS` checks. On x86 these are in `validate_installed_runtime` at `:451-469`.
   - The combined path uses bare `payload_hashes` (`:376-388`).
   - Qualifying-path.

7. **`owned_static_sysroot_package.py` — closed**
   - The aarch64 reader checks the architecture-specific package identity, installed-file record and sealed-driver format and path, alongside the source seal and payload hashes.

8. **`consumer_rust_std_lto.py:215-235`**
   - x86: compiler tool hashes are bound to the source-pinned `owned_resolver_alias_image_inputs.json` (`_validate_compiler_records_against_source`).
   - aarch64: hashes the live tools and compares the receipt against the live image.
   - Qualifying-path.

9. **`consumer_rust_std_lto.py:587-588`**
   - The expected link argv is taken from the receipt being validated: the command is accepted with or without `--fix-cortex-a53-843419`.
   - Qualifying-path, low.

10. **`consumer_rust_std_lto.py:1522-1528`**
    - On aarch64, a non-qualifying run over a subset of sections returns 0 with "PASS (development only)". x86 returns 1 in the same case.
    - Development-only.

11. **`qualification_candidate.py:559-561`**
    - On aarch64, x86 `parity.toml` rows naming `.work/x86_64/...` are rewritten and counted as "attached" to aarch64 receipts.
    - Weaker: the x86 ledger stands in for an aarch64 attachment.
    - Qualifying-path.

12. **`owned_crypt_profile.py:397-440` (`aarch64_link_identity`)** replaces `validate_link` and `validate_retained_link`. Callers: `run_owned_crypt_runtime.sh:401-406`, `owned_crypt_runtime_evidence.py:468-472, 528-531` and `owned_wordexp_evidence.py:890, 1675`.
    - It drops `_validate_static_link_mode` and the `_dynamic_profile` check that rejects hardened non-PIE.
    - It builds the expected static receipt with the producer's own `receipt_input_records` and `owned_link_plan`, rather than an independent roster.
    - Qualifying-path.

13. **Any builtins archive member is accepted** at three sites: `static_product_contract.py:495`, `run_owned_static_sysroot.sh:526-528` and `crt/x86_64_owned_dynamic_startup.py:416-422`.
    - x86 requires `libcrabc-builtins.a(crabc-builtins.o)`. The aarch64 producer declares the same member (`builtins/build.py:34`).
    - Qualifying-path, low.

## B. Shell scripts, C probes, tests

14. **Closed (f8bbc0ea9). `run_owned_posix_filesystem.sh:204-233`**
    - x86: static and static-PIE, dynamic PIE and non-PIE, kernel and direct-loader entry, receipt and symbol audits, one shared workload object.
    - aarch64: runs one default-mode dynamic binary through the kernel only, prints PASS and does `exit 0`.
    - This is a qualification case (`owned_dynamic_qualification.py:121`), so the exit 0 counts as a pass.
    - On arm64, the shared product and link readers now validate the same installed object across static, static-PIE, dynamic PIE and non-PIE, with kernel and direct-loader dynamic entry. The supplied-product run passed all six modes.

15. **`run_owned_static_sysroot.sh:1787-1792`**
    - x86 runs the builder tests `scripts.tests.test_build_x86_64_owned_sysroot`.
    - aarch64 substitutes `crt.tests.test_x86_64_dynamic_modes`, an unrelated CRT suite.
    - Qualifying-path.

16. **`run_owned_static_sysroot.sh:188-197`, delegating to `static_product_contract.py:307-334`**
    - aarch64 returns before the x86 manifest assertions: scope phrases, `not_selected`, sealed-driver path/status/modes, and coverage disclaimers.
    - For a combined product, the nested static manifest gets only a source comparison.
    - Qualifying-path.

17. **`run_owned_crypt_runtime.sh:104-108`**
    - x86 runs `run_musl_oracle.sh`: compile and run a probe, check `-dumpmachine`, and check that libc identifies itself.
    - aarch64 does file-identity checks only, although `run_musl_oracle.sh` was ported in this same branch.
    - Qualifying-path.

18. **`run_hardened_entry.sh:42-64`**
    - aarch64 does not use `--transitive-application-dso`. It links the provider as a direct DSO, then patches `DT_NEEDED` out of the binary in Python.
    - The driver's transitive path is never exercised, and the binary no longer matches its receipt.
    - Qualifying-path.

19. **`loader_crt_lifecycle_probe.c:19-24, 35-40`**
    - x86 requires `phase == 1`.
    - aarch64 accepts `phase` 0 or 1 and prints ok when the legacy hooks did not run, so it passes either way, in every mode and both lanes.
    - Qualifying-path.

20. **`libc_crt_static_tls_probe.c:190-198`**
    - x86 checks the `%fs:0` self-pointer.
    - On aarch64 `fs_self()` returns `tp` whenever `*(tp-8)` is non-zero, so the comparison becomes `tp == tp`. An equal-strength check (`*(tp-8) == tp`, per `static_tls.rs:684`) was available.
    - Qualifying-path.

## C. Builders, scripts, Lua, corpus, CRT, unwinder

Builder lane evidence (incomplete): the native C allocator object defines
`_mi_cpu_movsb_max` and `_mi_cpu_stosb_max` in addition to the x86 reviewed
list. The AArch64 link policy makes both local; a `readelf --dyn-syms` check
on the compatibility build found neither in its dynamic exports. The native
static and dynamic builders completed with the current partial audits, but
both still report skipped checks and do not close items 21–24.

The builder evidence and CRT entry are closed by `82215a948`, `208112188`,
`25bc87bd1`, `e8ca28be4`, `23529590d` and `bc9e714d2`. On the native
AArch64 image the static, dynamic and hardened builders passed; their
manifest fields and CRT and loader provenance validated. The dynamic export
set matched the native musl names adjusted by the reviewed x86 export delta
(1,658 names; no extras or omissions). The combined product and dynamic
package validated, all nine product-reader checks passed, and static,
static-PIE, dynamic PIE, dynamic non-PIE and hardened hello programs ran.
The 34-case corpus passed. The libc-test run recorded 428 passed and six
runtime failures and exited 1; its aggregate remains incomplete.

21. **Closed — static builder evidence.** The native build applies the shared
    archive classification, symbol and duplicate-binding checks, allocator
    lifecycle and hidden-symbol checks, CRT inspection, pinned UAPI install and
    reproducible builtins. Its manifest carries the x86 field set with native
    identities.

22. **Closed — dynamic builder evidence.** The native build audits both
    shared ELF views and unresolved symbols, applies the reviewed allocator,
    errno and compiler-helper visibility policies and validates the installed
    driver. Its loader and libc are one image and replacement is guarded.

23. **Closed — loader flags.** The native producer binds the selected flags to
    loader provenance, and the native loader inventory reader validated that
    provenance.

24. **Closed — CRT object inspection.** All five native objects pass the
    shared section, symbol, stack and owned-note inspection; the three entry
    objects differ and their entry handoffs and relocation contracts are
    checked.

25. **`compat/lua/source_build_admission.py:305-317`**
    - aarch64 does `backends.add("accepted-c")` unconditionally and never reads the state file.
    - The test at `tests/test_source_build_admission.py:129` removes the backend field and still expects admission.
    - Qualifying-path.

26. **`compat/lua/run.py:1244-1255`**
    - On aarch64 the manifest no longer binds the sealed static driver identity.
    - Qualifying-path.

27. **`scripts/build_x86_64_owned_combined_sysroot.py:137-141, 199-203, 355-357, 376, 404-410`**
    - aarch64 skips the dynamic state's schema and source checks and the allocator, profile and audit cross-checks.
    - Qualifying-path.

28. **`unwinder/owned_rust_link.py:740-761`**
    - On aarch64, `_read_product` uses a local reader (schema, format, target and the payload map) instead of the shared `_validate_static_product`, which already has an aarch64 branch.
    - Qualifying-path.

29. **`unwinder/owned_rust_link.py:55-56, 477, 939-941`**
    - On aarch64 `-static` is silently accepted.
    - `-no-pie` followed by `-static-pie` is allowed, and ELF type is not checked.
    - Qualifying-path.

30. **Partially closed — builder and named product readers.** The builders
    and the assigned corpus, Lua, dynamic package and libc-test readers use
    the native compatibility aliases. The broader audit item remains open for
    any other consumers not covered by this lane.

31. **`compat/corpus/run_x86.py:474`**
    - aarch64 skips any `.SIGN.*` file instead of the named key. `apk verify` still runs.
    - Qualifying-path, low.

32. **Closed — conventional entry handoff.** The AArch64 entry forwards its
    finalizer register to the shared startup owner. Native static fixtures
    with a register but no handoff and with a handoff but no register each
    exited 127 before application entry.

## D. ldso / libc

Follow-up on `lane/a4-product-fixes`:

- 33: The proposed defect is disproved for direct entry. Pinned musl 1.2.6
  `ldso/dynlink.c:1813,1860-1920` decodes auxv into a private array and
  updates its private `AT_ENTRY`; it does not rewrite the initial-stack
  `AT_EXECFN`. The native oracle fixture in `ff2ef2f28` observes the loader
  pathname for both products. Consequently there is no failing-first test for
  this claim. The existing x86 difference is documented in `parity.toml`.
- 34: Fixed in `d29938707`; a synthetic auxiliary vector proves the mask even
  when the test host does not advertise SME. The native oracle fixture checks
  the exposed HWCAP values.
- 35: Fixed in `4025b27e2`, with additional boundary cases in `e6667c701`.
  The native fixture compares value bits and exception flags against musl in
  all four rounding modes.
- 36: Fixed in `d3c73cbaa`; the arm64 loader test rejects an out-of-range ID.
- 37: Fixed in `ff71a1151`; the arm64 loader test checks that an earlier
  target remains untouched when later RELA entries duplicate a target.
- 38: Fixed in `b9b9c0028` and tested further in `63d42b791`; the loader test checks classification, with
  end-to-end `dlerror` verification still outstanding.
- 39: Fixed in `55cfab435`; the arm64 loader test checks the resolver and
  retained module/offset record. The returned descriptor storage must outlive
  the relocated objects and users of those descriptors.

These notes do not claim campaign acceptance; the required aggregate and
x86-selected-diff evidence must still be checked on the final source.
The native libc-test aggregate on the built dynamic product reported 428
passed and six runtime failures: `functional/crypt`, `functional/strptime`,
`functional/wordexp`, `math/pow`, `math/powf`, and `regression/statvfs`.
The pinned-musl side also failed for strptime, wordexp, powf and statvfs;
crypt and pow need separate investigation outside this item set.

The loader source tests were built with the `rustc --test` flags in
`compat/x86_64/owned_dynamic_qualification.py:341-345`. On native arm64,
the new tests for 34, 36, 37, 38 and 39 each exited 101 before its fix and
0 after; the complete suite exited 0 with 153 passed. The product oracle was
run with `scripts/lanes/orb-vm-run.sh scripts/lanes/rust-check.sh bash
tests/fixtures/aarch64_product_oracle.sh .work/aarch64/product-fixes-sysroot
.work/aarch64/product-oracle-3` and exited 0. Before the math fix, the
same fixture's musl and candidate rounding output differed and `diff` exited
1. The x86 loader and static/dynamic libc cargo checks passed with the
cross-target flags documented in CRAB-8.

33. **`ldso/src/x86_64_direct_entry.rs:106-107`**
    - The AT_EXECFN rewrite is now `#[cfg(target_arch = "x86_64")]` only. The two architectures diverge against one shared oracle, so one of them is wrong.
    - Qualifying-path.

34. **`ldso/src/x86_64_initial_graph.rs:2304-2306`**
    - aarch64 dynamic startup lacks musl's HWCAP/HWCAP2 SME masking, which the aarch64 static path does (`static_tls.rs:954-978`).
    - Qualifying-path.

35. **Closed (1893d7e07, 88b7f88fb). `fenv_rounding.rs` and `elementary_sqrt.rs`**
    - Native binary128 rounding uses the caller's mode and raises the required flags. The pinned-musl differential covers all four modes, subnormals, exact and inexact results; a separate signaling-NaN probe verifies `sqrtl` quieting, payload and sign preservation, and `FE_INVALID`.

36. **`ldso/src/aarch64_initial_tls.rs:69-76`**
    - The per-object `tls_module_id < dtv_words` re-check (x86 `:2482`) is missing.
    - Qualifying-path, low.

37. **`ldso/src/aarch64_bootstrap.rs:119-133`**
    - Duplicate RELA entries are detected per entry during apply, not in a preflight before any write. Both paths exit 127.
    - Qualifying-path, negligible.

38. **`ldso/src/x86_64_deferred_relocations.rs:134, 150-153`**
    - dlopen diagnostics don't know `R_AARCH64_TLSDESC`, so `dlerror` reports UnsupportedType instead of the real cause.
    - Qualifying-path, low.

39. **`ldso/src/x86_64_general_relocation.rs:552-559, 837-845`**
    - A latent wrong TLSDESC descriptor (offset 0) on any path other than `relocate_new`.
    - Development-only.

## E. Test coverage

40. **Closed; original finding:** **`crabc-rs/src/fs.rs:2258-2287`**: the `Stat` size, alignment and offset assertions are x86-only, with no aarch64 values. Raw kernel writes depend on that layout. The layout is correct today by hand calculation.
41. **Closed; original finding:** **`crabc-rs/src/event.rs:270-279`**: the epoll `Event` layout assertions are x86-only. The aarch64 check compares two identical definitions, so it proves nothing.
42. **Closed; original finding:** **crabc-rs tests**: the x86-only suites were not ported (`x86_64_mm`, epoll, poll, pselect, statat, memfd, child_*, process_kill, thread_kill, clock_nanosleep and others). The merged code now runs on aarch64 untested.
43. **Closed; original finding:** **`ldso/src/x86_64_initial_graph.rs:4785` vs `:1241-1243`**: the self-relocation tests are x86-only, and the aarch64 bootstrap is never compiled under test.
44. **Closed; original finding:** **ldso relocation tests**: no aarch64 version of the PC32 commit-after-preflight test, and no tests of dynamic TLSDESC or hardened TLSDESC RELRO.
45. **Closed; original finding:** **`ldso/src/x86_64_initial_graph.rs:2523`**: the test lowers `tls_align` to 1 on aarch64.
46. **Closed; original finding:** **`libc/.../descriptor_entry.rs:217`**: the x86 `O_DIRECTORY` value is `O_DIRECT` on aarch64, so that test case never runs there.
47. **`compat/x86_64/tests/test_runner.py:8288-8317`**: the test of the "refuses emulation" branch was replaced with a Darwin case.
48. **`compat/x86_64/tests/test_core_image_dispatch.py:30, 227, 275`**: all negative image-pin tests are x86-only.
49. **`compat/x86_64/tests/test_aarch64_dynamic_non_pie.py:11, 33, 53`**: every test needs `CRABC_AARCH64_DYNAMIC_SYSROOT`, which nothing sets, so they always skip.
50. **`compat/x86_64/tests/test_consumer_rust_std_lto.py:341-351`**: fewer negative cases on aarch64.
51. **`unwinder/tests/provider_abi_frame.c:21-27`**: x24–x28 and d8–d15 are not kept live, so they are untested.
52. **`unwinder/tests/test_owned_cleanup.py:182, 600, 922` and `test_owned_rust_link.py:46`**: x86-only. The aarch64 `_host_link_output_matches` branch (`owned_cleanup.py:1608-1635`) is never exercised.
53. **`compat/x86_64/installed_crt_startup_evidence.py:387-393`**: the source-order check covers only the x86 attach branch. Low.

## F. Development-only

54. **`scripts/lanes/rust-check.sh:72-84`**: aarch64 checks only `crabc-core`.
55. **`scripts/lanes/prepare-worktree.sh:305-312`**: the aarch64 corpus fetch is always skipped with exit 0, although `fetch_x86.py --architecture aarch64` exists.
56. **`scripts/dev-x86_64.sh:6154-6157`**: aarch64 `--help` exits 0 (trivial).
57. **`scripts/dev-x86_64.sh:23-24, 3269-3275`**: `image` still builds `Dockerfile.x86_64` for arm64 (not ported).
58. **crabc-rs docs**: truncated doc comments and stale "Linux/x86-64" safety text, for example at `fs.rs:2709-2738` and `mm.rs:196`.

## x86 behavior changed (rule: x86 stays unchanged)

59. **Closed (83c615c83).** **`crabc-rs/src/process.rs:385`**: `PreparedExec::spawn` changed from `fork_raw()` to `fork()`. That runs atfork callbacks and blocks and restores the full signal mask around the clone, which contradicts `parity.toml:835, 839`.
60. **Closed (2f06af061).** **crabc-rs public API grew on x86**: public `fork`, `register_atfork`, `wait*`, `setsid` and others.
    - New unsafe `mmap_with_flags`, `mmap_anonymous_with_flags` and `mprotect_with_flags` (`mm.rs:628-655`) skip `checked_map_bits` and `checked_protection_bits`.
    - Also new: `renameat_whiteout`, `ResolveFlags::CACHED` (needs kernel 5.12) and `ioctl_tiocgptpeer`.
61. **Closed (9740ef25d).** **Legacy syscalls replaced on x86 too.** In libc and crabc-core, `poll`/`select`/`pause`/`access`/`open`/`chown`/`mkdir`/`pipe`/`dup2`/`fork` now go through the `*at`/`p*`/`dup3`/`clone` forms. musl x86_64 uses the legacy calls. `owned_spawn.rs:67-74` shows the cfg pattern that keeps them.
62. **Closed (aa728c8f4, 14145c4ec, 0902466a2, 778d388c4^):** test targets, function names, ledger paths and runner contracts match main; coverage.toml unchanged. **Renamed crabc-rs tests break the x86 harness**: 37 `--test x86_64_*` references in `dev-x86_64.sh` (for example `:4482, 4523`), assertions in `test_runner.py:1827/1905`, and `compat/crabc-rs/coverage.toml:2895-2977`. They fail loudly, but the x86 evidence commands are broken.
63. **Closed (main contract restored on both architectures; 9e5b84c80 additionally fixes a main defect):** main rejected a whole resolv.conf containing `search .` (systemd-resolved/OrbStack), so from_system failed; a root suffix is now skipped as musl does, IP-literal and other invalid suffixes are still rejected, and main's from_system tests are restored.rs:815-855`**: invalid search domains are now skipped instead of rejecting the file, on both architectures. This was intentional, but it goes beyond musl, which keeps IP-literal entries.
64. **Closed (0a7c7e68c).** **`compat/x86_64/loader_debug_abi_trace.c:94-104`**: the new path-stat fallback also applies on x86. Borderline.

## Equivalent or not findings
- **Equivalent translations**:
  - `aarch64_rcrt1.rs` matches the x86 rcrt1 step for step.
  - `Aarch64Reader` is a copy of `native.Reader`.
  - Using `-fno-pic` to force a COPY relocation is the right aarch64 spelling; the exact COPY-relocation check still runs.
  - `R_AARCH64_ABS32` (258) is the right counterpart of `R_X86_64_32`/`32S`.
  - The outline-atomics allowlist in `builtins/build.py` is stricter than before.
  - The two aarch64 oracle checks (wordexp and crypt) use the strong `pinned_musl_identity`.
  - The thread-pointer and TLS-offset translations are correct for the aarch64 layout.
- **Closed (`15c44b8b8`, `58e5615a5`, `231c19023`)**: `header_declaration_inventory` collects and validates native arm64 declarations; `owned_errno_storage_lifecycle` and `runtime_private_facades` pass on the converged products.
- **Closed (`be551fae7`, `8f6f97cdc`, `ac49f0855`)**: `owned_public_data_variable_runtime` collects and replays the native arm64 installed-product matrix.
- **Unported but fails closed**: `owned_dynamic_fork_evidence`, `consumer_static_pie_lto`, `consumer_native_facade_lto`, resolver-network and Lua dynamic dispatch.
- **Shipped but never linked**: `usr/lib/crabc-dynamic-attach.o` is built and installed on aarch64, but no aarch64 link uses it. aarch64 `Scrt1` attaches directly instead.
- **Forced static-PIE**: `consumer_rust_std_lto.py:416` forces static-PIE for the owned-static lane. That is probably equivalent, depending on rustc's default for the aarch64 musl target.
- **Not in this branch**: `signal.rs` `queue_thread` (x86-only) and the aarch64 `SigAction` mask and restorer loss were already on main. Dropping `PreparedExec::exec` on aarch64 aligns with x86 but needs an owner decision.

## Counts

| Severity | Count | Entries |
| --- | --- | --- |
| Qualifying-path | 37 | 1–9, 11–38 |
| Development-only | 7 | 10, 39, 54–58 |
| Test-coverage | 14 | 40–53 |
| x86 behavior changed | 6 | 59–64 |

## x86 harness tests after convergence (closed)

A full Mac run of `compat/x86_64/tests` under an x86 `uname` shim at
`a15041c68` has 54 failing test names that pass at `58eb7704d`: about 37
header source-form tests that still assert the deleted frozen-AArch64 header
branches or pre-convergence x86 source spelling (x86 preprocessed output is
byte-identical), and about 17 runner, receipt and parser tests touched by the
aarch64 runner ports. All arm64 checks pass at this commit (libc-test 428/434,
34-case corpus, 675 crabc-rs tests, 154 loader tests, x86 type-checks).

Closed at `9cb1f8d49`: the full Mac x86-shim run of `compat/x86_64/tests` has no
failing test name absent from the `58eb7704d` base (245 versus 251 at base).
Header source-form tests assert the converged shared bodies; every x86
exact-musl assertion is kept.

# Re-audit at 4f20155a5 (2026-11-19)

Independent read-only re-check of every item above not marked closed, plus new
weakening since `337e6022`. This section supersedes the per-item status above;
entries are closed by the commit that fixes them.

## A. Status of the open audit items

| # | Status | Evidence |
|---|---|---|
| 1 | partly fixed | `owned_dynamic_qualification.py:231-278` now reads state and provenance and runs every check on aarch64. The aarch64 combined path still goes through `combined.validate`, which has no CRT or loader provenance check (`build_x86_64_owned_combined_sysroot.py:373-403`). The x86 combined path runs `validate_combined`, which checks both (`crabc_cc_owned_dynamic.py:339-341`). |
| 2 | closed (20cedf91a) | The ARM driver validates its installed product through the shared reader, requires an explicit dynamic mode, rejects static modes, checks direct DSO closure and imports, and supplies the provider set to final ELF inspection. |
| 3 | fixed | `crabc_cc_owned_dynamic.py:223-231` (aarch64 required roster includes loader provenance and the receipt/ELF modules), `:262` (CRT provenance), `:275-276` (`validate_loader_provenance(architecture="aarch64")`). |
| 4 | closed (d8ffc3bd5) | The shared product reader validates the full product and compares producer tools against the architecture-specific source image manifest. |
| 5 | closed (373b8589b) | Static preparation reads each product’s allocator backend and producer tools from its manifest and checks backend agreement. |
| 6 | closed (a04b647dd) | Both native static drivers use the same installed-payload, required-path and CRT-provenance checks. The ARM builder suite passes all 47 tests. |
| 8 | closed (d8ffc3bd5) | The shared reader binds compiler identities to the architecture-specific source image manifest. |
| 9 | still open | `consumer_rust_std_lto.py:587-588`. |
| 10 | closed (58f2ddd16) | Incomplete development runs return failure on both architectures. |
| 11 | kept by owner decision (not a defect) | Audit file `:16-19`; code unchanged at `qualification_candidate.py:559-561`. |
| 12 | still open | `owned_crypt_profile.py:397-429` is unchanged: the expected receipt is built from the producer's own `receipt_input_records`/`owned_link_plan` (`:408-409`), with no `_validate_static_link_mode` and no `_dynamic_profile`. Callers are unchanged (`run_owned_crypt_runtime.sh:404-405`, `owned_crypt_runtime_evidence.py:470,529`, `owned_wordexp_evidence.py:892,1677`). The shared `validate_link` and `validate_retained_link` now accept aarch64 (`owned_posix_product_evidence.py:1477-1496, 1550-1571`). |
| 13 | still open | `static_product_contract.py:494-495`; `run_owned_static_sysroot.sh:526-527`; `crt/x86_64_owned_dynamic_startup.py:416-421`. |
| 14 | closed (6c7d0cdb8) | The shared filesystem producer runs the native static, static-PIE, dynamic PIE and non-PIE modes and both dynamic entry paths. |
| 15 | implementation added (4cc51d70a, 90b46ce83); acceptance waiting | The shared builder suite runs and passes on ARM. The static producer is waiting on positional-printf rounding in lane `a4-binary128` and process-shared robust-mutex lifecycle behavior in lane `a4-robust-mutex`; the producer remains red. |
| 16 | partly fixed | `static_product_contract.py:307-334` now checks the sealed driver's path, status and modes for standalone. The scope phrases, `not_selected` and `not_proven_by_this_seed` assertions are still x86-only (`run_owned_static_sysroot.sh:200-240`). The nested static manifest in a combined product gets no sealed-driver checks. |
| 17 | closed (415415ce2) | The crypt producer runs the native musl oracle probe on both architectures. |
| 18 | closed (d90065635) | The hardened entry test uses the driver’s transitive DSO option on both architectures. |
| 19 | still open | `loader_crt_lifecycle_probe.c:19-24, 35-41`. |
| 20 | closed (dc7c7d024, 8d8544d89) | The owned ARM TLS probe compares the word at TP-8 to TP; the musl reference uses its distinct DTV placement. |
| 25 | fixed | `compat/lua/source_build_admission.py:302-316` reads the state file. The test no longer removes `allocator_backend`. |
| 26 | fixed | `compat/lua/run.py:1244-1252`: the driver binding is now architecture-independent. |
| 27 | fixed | `build_x86_64_owned_combined_sysroot.py:124-174` (no aarch64 early return), `:193-197`, `:339-370`, `:397-398`. |
| 28 | fixed | `unwinder/owned_rust_link.py:733-745` uses the shared `_validate_static_product`/`_validate_dynamic_product`. |
| 29 | still open | `owned_rust_link.py:55-56` (`-static` admitted), `:917-918` (`-no-pie` then `-static-pie` allowed). Only the machine is checked (`:976`, `:1195`); ELF type is not. |
| 30 | partly fixed | The corpus, Lua, resolver-network and libc-test readers use `aliases_for_architecture`. `run_owned_posix_filesystem.sh:215` still passes `{}` aliases (part of item 14). |
| 31 | still open | `compat/corpus/run_x86.py:475`. |
| 33 | fixed (aarch64 adopts the x86 behavior) | Since `74b86437a`, `ldso/src/x86_64_direct_entry.rs:106` applies the AT_EXECFN rewrite on both architectures, and `run_general_dynamic_cli.sh` checks it in both modes. The audit's follow-up note ("disproved") is now stale. |
| 34 | fixed | `ldso/src/aarch64_auxv.rs`, called from `x86_64_initial_graph.rs:1258-1267` and `static_tls.rs:33-34,963`; test at `:1283-1292`. |
| 35 | fixed | `fenv_rounding.rs:147-172` (explicit rounding mode and inexact flag); `elementary_sqrt.rs:114-121, 155-169`. |
| 36 | fixed | `aarch64_initial_tls.rs:71`; test at `:98-104`. |
| 37 | fixed | Preflight at `aarch64_bootstrap.rs:117-127`; test at `:240-251`. |
| 38 | fixed (classification only) | `x86_64_deferred_relocations.rs:135-136, 158-164`; test at `x86_64_general_relocation_tests.rs:1434-1450`. End-to-end `dlerror` checking is still outstanding. |
| 39 | fixed | The production dlopen path `deferred::relocate_new` (`x86_64_runtime_registry.rs:1011`; `x86_64_deferred_relocations.rs:70-88`) writes `tlsdesc_dynamic` with a retained record. The new aarch64 `relocate_runtime_objects` (`x86_64_general_relocation.rs:1117-1168`) is called only from tests. |
| 40 | fixed | `crabc-rs/src/fs.rs:2256` asserts the AArch64 kernel record against musl generic `bits/stat.h`. |
| 41 | fixed | `crabc-rs/src/event.rs:271` asserts the native unpacked 16-byte record against musl `sys/epoll.h`. |
| 42 | fixed | The original test targets run on AArch64 with native constants; the full `crabc-rs` test command passed. The formerly disabled `x86_64_mm` target alone adds 25 passing tests. |
| 43 | fixed | `ldso/src/x86_64_initial_graph.rs:5105` exercises AArch64 bootstrap self-relocation in the loader test suite. |
| 44 | fixed | `ldso/src/x86_64_general_relocation_tests.rs:1397` covers static and dynamic TLSDESC; `:1466` covers runtime preflight and `:1480` checks hardened RELRO pages. The focused hardened check passed; it is not an end-to-end hardened TLS fixture. |
| 45 | fixed | `ldso/src/x86_64_initial_graph.rs:2548` uses 16-byte aligned images and variant-I placements. |
| 46 | fixed | `libc/src/c_abi/x86_64/descriptor_entry.rs:270` selects the native AArch64 `O_DIRECTORY` value. |
| 47 | still open | `test_runner.py:8284-8312` tests a Darwin host. The emulation-refusal branch at `dev-x86_64.sh:3264-3267` is untested; main's version of this test used Linux/aarch64. |
| 48 | fixed (d84f8ba79) | The arm64 image test rejects a missing pin, inspection errors and an incorrect image architecture without running or building. |
| 49 | fixed (b6236c919) | The native image builds a temporary aarch64 sysroot when none is supplied; all five original tests passed in the VM. |
| 50 | fixed (48ce246c7) | The aarch64 route has forbidden-symbol, missing-witness, missing-syscall and instruction-spelling cases. |
| 51 | fixed (9dd0450c3) | The aarch64 frame keeps x24–x28 and d8–d15 live and checks their values; the fixture compiled in the native image. |
| 52 | partly fixed (9dd0450c3, 23c7b342d) | The arm64 launcher reader has a positive and negative ELF test, and the Rust linker materialization test passed natively. The two cleanup routines behind x86-only guards still require aarch64 producer support. |
| 53 | test coverage added (dee553461) | A test uses the existing source-order checker on the aarch64 attach branch and rejects missing or reordered operations. The production receipt checker still checks only the x86 branch. |
| 54 | implementation added (d84f8ba79) | The arm64 path now lists the full x86 crate and feature profiles with its native target. Native execution passed six profiles and failed the two frozen native-shadow profiles and `crabc-mimalloc --all-targets` on unresolved allocator source modules. |
| 55 | implementation added (d84f8ba79) | The arm64 path invokes the corpus fetcher with `--architecture aarch64`; the existing prepare-worktree test fixture does not supply `native_arch.py`. |
| 56 | fixed (d84f8ba79) | Native arm64 help is exercised without Docker in the image-dispatch test. |
| 57 | fixed (d84f8ba79) | Native arm64 selects `Dockerfile.aarch64` and an aarch64 tag; the test captures build arguments without building an image. |
| 58 | still open | `event.rs:1, 56, 257, 703-705` say "Linux/x86-64" in shared code; `fs.rs:2669` documents statx as "syscall 332". |

The follow-up note's commit hashes for items 34–39 (`d29938707`, `4025b27e2`, `e6667c701`, `d3c73cbaa`, `ff71a1151`, `b9b9c0028`, `63d42b791`, `55cfab435`, `ff2ef2f28`) are not ancestors of HEAD. The patch-identical commits that did land are `422a66733`, `1893d7e07`, `b40471590`, `b71489007`, `c86c7426d`, `f27f7c2e2`, `639e47fb5`, `86e33b818` and `1ce2c5579`.

### B. New weakening since 337e6022

### x86-change

1. **Closed (`b53febc2b`).** **`scripts/build_x86_64_owned_dynamic_sysroot.py:974-975`** (`90e68512b`). `build_debug_payload` builds the x86 debug product (reached from `:616`) but calls `audit_shared_elf(..., architecture="aarch64")` on x86 `libc.so` and the loader.
   - Before: the x86 debug product was checked for `R_X86_64_32/32S`.
   - After: it is checked for `R_AARCH64_ABS16/32` (`:93`), which never matches on x86.
   - The x86 debug path now passes `x86_64`; the AArch64 producer continues to pass `aarch64`.
2. **Closed (`55e593347`).** **`ldso/src/x86_64_general_relocation.rs:864, 871`** (`ffc9bc0f2`). There is no `cfg`: `interpreter_self` objects now skip RELATIVE relocations and the RELR table on x86 as well.
   - The skip is now AArch64-only; no x86 double-relocation defect was demonstrated.
3. **Closed in assigned paths (`24b8b435c`); external callers remain.** **`crabc-rs/src/process.rs:50`** adds `pub use crate::signal::{Pid, Signal}`; main exports only `Pid`. This is a public API addition left over from item 60.
4. **Closed (`24b8b435c`).** **`crabc-rs/src/process.rs:2332-2400`**. The private `register_atfork`/`fork` and the atfork registry are compiled on x86 with only test callers.
   - The AArch64 public atfork API and product-level `atfork_case` are restored; the registry is not compiled on x86.
5. **Closed (`c4cdd2af5`), main fixture defect fixed.** **`compat/x86_64/ldso_general_initial_tls_main.c:112, 115, 129`**. Thresholds in the x86-compiled block changed with no architecture guard (`<5`→`<4`, `<`→`<=`, `dtv[0]`→`dtv[0]+1`).
   - The layout records a module count at slot zero and allocates count plus one words (`ldso/src/x86_64_initial_graph.rs:2396,2491`); scanning through the count and using count plus one for an absent module strengthens the fixture. The masked result is now checked on x86.
6. **Closed (`e371a10e5`).** **`owned_system_cancellation_probe.c:33-34, 86, 150-154`** adds an unguarded wait loop and `CHECK(interrupt_seen)`. This changes the x86 workload; it strengthens the test rather than weakening it.

The facade correction leaves out-of-scope callers `crabc-rs/examples/ppoll_direct_probe.rs`, `crabc-rs/examples/signal_process_probe.rs`, and `compat/rustix/source/pause.rs` referring to `process::Signal`; they need the `signal::Signal` path.

### Qualifying-path

7. **`owned_dynamic_qualification.py:349-352`** (`0a6486c09`).
   - x86's `installed-driver` judge is `test_owned_dynamic_driver.py` (about 52 tests).
   - aarch64 substitutes `test_aarch64_dynamic_non_pie.py` (5 tests), and the `owned-crt` judge exercises only x86 CRT tables.
   - Both architectures record the same check labels (`:348, :376`), so the records cannot be told apart.
8. **Closed (d8ffc3bd5): producer-tool identities are checked against the architecture-specific source pin.**
   - The shared product and loader readers use the same source-pinned records.
9. **Closed (20cedf91a).** Final ELF inspection receives the shared dynamic-symbol provider set on ARM.
10. **`owned_posix_native_observations.py:299-301, 381-392`**.
    - x86 replays the retained sidecars with `validate_record`.
    - aarch64 inspects the live ELF and drops the sidecars from the exact file roster, although the driver now writes them.
11. **Four component receipts** (`owned_locale_component_receipt.py:181-191`, `owned_numeric_calendar_component_receipt.py:178`, `owned_regex_component_receipt.py:187`, `owned_stdio_component_receipt.py:339`).
    - aarch64 uses `validate_dynamic_product_source`, which drops the `status == "materialized-unqualified"` check.
    - It also admits debug products through `validate_debug_product_source`.
12. **`runtime_private_facades.py:313-314`**.
    - x86 runs `validate_materialized_dynamic_product`, which includes `validate_installation` and `product_identity`.
    - aarch64 runs only `validate_dynamic_product_source`.
    - Cause: `compiler_helper_evidence.py:1392` hardcodes `.work/x86_64`.
13. **Partly fixed (e752b2c37).** The shared record validator now rejects binary128 value and flag differences under the revised rounding decision. The ARM producer still needs the x86 structural checks and awaits the `a4-binary128` runtime fix.
    - x86 does a byte-exact `cmp` against musl and checks the export surface, bindings, closure, TLS, ambient dependencies and an aggregate.
    - aarch64 checks only machine, static-ness, symbol presence and alias address, and allowlists flag and rounding differences.
    - The binary128 difference itself is owner-decided (CRAB-8 RFC, about `:358`); the dropped structural checks are not.
14. **Open — archive producer dependency.** `builtins/build.py:838-847, 941-950` requires and emits one `crabc-builtins.o` followed by source-built `compiler_builtins-*.o` members; the requested shared aggregate contract requires exactly `crabc-builtins.o`. A native `mold -r --whole-archive` experiment produced one member and passed the helper fixture, but integrating that product-format change and its provenance with `a4-binary128` remains outstanding. The ARM aggregate also needs the shared structural checks and replayable aggregate report.
    - Dropped: the provenance checks (`members == ['crabc-builtins.o']`, reproducibility); the check that an archive-free link fails naming each helper; the checks that each helper definition is retained and called directly; and the aggregate report.
    - It also takes its tools directory from the ambient `rustc --print sysroot` (`:13`).
15. **Static export surface.**
    - `source_runtime_libc.sh:68-75` allowlists the application-namespace names `ioctl_word`, `ioctl_no_argument`, `semctl_word` and `semctl_no_argument`.
    - `native_abi_exports.py:152-160` accepts any `anon.*` symbol on aarch64, where x86 compares them exactly. The aarch64 delta is hardcoded in code (`:32-47`).
16. **`owned_static_link_authority.py:202`** admits nameless LOCAL undefined `.symtab` rows on aarch64. Its test fabricates the row (`test_owned_static_link_authority.py:631-656`).
    - `:514-573`: aarch64 merged-constant targets are not bound to the input's link-map contribution.
17. **Closed (6205287aa).** Both architectures compare the resolver receipt with the independent shared `_static_link_plan`.
18. **errno alias visibility, rule 2.** `libc/src/c_abi/x86_64/errno.rs:62-65` makes the alias HIDDEN on aarch64, where x86 deliberately keeps it DEFAULT. The validator branches to match (`owned_errno_storage_lifecycle.py:907`).
19. **`run_owned_ldso_lifecycle_cases.sh:84-87`**. On aarch64 the musl expectation strips the legacy init/fini letters. This divergence is not recorded in `parity.toml` (related to item 19).
20. **Closed (beac442c7, 71bc72983, 071098c93).** The ARM target is read from Cargo metadata, the builders receive the native architecture, and the provider audit checks ARM atomic and call instructions. The native `owned-rand` producer passed.

### Test-coverage

21. **Closed (2b5b4c94a):** The nine pinned musl hashes are enforced against the converged x86 forms. Previously `compat/x86_64/tests/test_fcntl_event_header_topology.py:66-101` failed at HEAD. It required the first line to be `#if defined(__x86_64__)`, so the hashes were not enforced by a passing test.
    - It already failed at base `58eb7704d`, so the audit's closure note missed it.
    - The x86 view of `bits/fcntl.h` is byte-identical to musl (sha256 `3526dbb8…`), so x86 itself is unchanged.
22. **Closed (2b5b4c94a):** `test_reboot_header_source_form.py` compares the complete macro block exactly.
23. **Closed (2b5b4c94a):** `test_pthread_header_source_form.py` checks the exact converged source coordinate.
24. **Closed (2b5b4c94a):** `test_owned_posix_timers.py` rejects every Python invocation while checking parser usage, including architecture setup.
25. **Closed (b6236c919):** The aarch64 dynamic suite invokes all four tests below; all nine suite cases passed in the native VM after preparing the locked offline vendor. Previously, nothing ran:
    - `compat/x86_64/tests/test_aarch64_errno_alias.sh`
    - `compat/x86_64/test_aarch64_dynamic_driver.py`
    - `compat/x86_64/test_aarch64_tls_trace.py`
    - `compat/x86_64/run_aarch64_default_runtime_regression.sh`
26. **`libc_bootstrap_primitives_probe.c:41-50`**. The aarch64 branch omits the `SIGUSR1`/`SIG_SETMASK` and `fenv_t` offset assertions.

**Header tests:** apart from 21–23, no x86 header assertion was lost; each rewritten assertion was checking the deleted aarch64 branch, or now covers the whole file. A preprocessing diff of all 108 headers before and after shows the x86 view is unchanged, except for comments and one `#error` wording change in `include/fenv.h:11`.

### Already on main, and not in the audit

- **Fixed (`c4cdd2af5`), x86 execution unverified:** `loader_libc_general_tls_runtime_v1_main.c:116-118` returned 1 on success, but `main` treats any nonzero result as an error (`:151-152`). So the x86 exact-DTV check can pass only when it fails.
- **Fixed (`c4cdd2af5`), x86 execution unverified:** `ldso_general_initial_tls_main.c:147`: the x86 product-layout checks were inert (same masking as B5).
- Both aarch64 drivers omit `-isystem usr/include/crabc-linux-uapi` (`crabc_cc_static.py:1279`, `crabc_cc_aarch64_dynamic.py:282-286`), although the aarch64 builder installs it. This fails closed.
- The aarch64 static driver silently strips `-no-pie` (`crabc_cc_static.py:1257-1259`); x86 rejects it (`:168`).

### Counts

| Severity | B entries | Count |
|---|---|---|
| x86-change | 1–6 (two of them fixture-only) | 6 |
| Qualifying-path | 7–20 | 14 |
| Test-coverage | 21–26 | 6 |
| Development-only | — | 0 |
| **Total** | | **26** |

Correction to re-audit B3: main defines `pub struct Signal` in `crabc-rs/src/process.rs`, so `process::Signal` is main's public API; the converged `pub use crate::signal::{Pid, Signal}` preserves it and stays (main's `compat/rustix/source/pause.rs` and example probes use it). Not a defect.
