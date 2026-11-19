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

7. **`owned_static_sysroot_package.py:198-201`**
   - aarch64 drops the package contract, the `installed` record and the sealed-driver record checks. Only schema, build profile and symlinks remain.
   - Qualifying-path.

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

14. **`run_owned_posix_filesystem.sh:204-233`**
    - x86: static and static-PIE, dynamic PIE and non-PIE, kernel and direct-loader entry, receipt and symbol audits, one shared workload object.
    - aarch64: runs one default-mode dynamic binary through the kernel only, prints PASS and does `exit 0`.
    - This is a qualification case (`owned_dynamic_qualification.py:121`), so the exit 0 counts as a pass.
    - Qualifying-path.

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

21. **`scripts/build_x86_64_owned_sysroot.py:1520-1585`** (static builder)
    - It skips: libc member classification and the required-symbol contract, the allocator hidden-symbol and lifecycle audit, CRT profile validation, the pinned UAPI header install (it copies `include/` raw instead), reproducible builtins, and the `allocator_backend`, `installed` and `sealed_static_driver` manifest fields.
    - Qualifying-path.

22. **`scripts/build_x86_64_owned_dynamic_sysroot.py:1011-1155`** (dynamic builder)
    - There is no `audit_shared_elf` and no unexpected-undefined check.
    - The libc.so link has none of x86's hidden mimalloc/errno version scripts, `--exclude-libs` or pack-relative-relocs. The reviewer inferred from the link command that mimalloc and builtins definitions are left global.
    - The driver is never validated, and an existing output is removed with `rmtree`.
    - Qualifying-path.

23. **`build_x86_64_owned_dynamic_sysroot.py:465`**
    - `architecture == "x86_64" and rustflags != ...` skips the loader rustflags binding on aarch64.
    - `owned_loader_inventory.py:217-225` then expects `rustflags == ""` and a hardcoded argv.
    - Qualifying-path.

24. **`crt/build_x86_64.py:883-922`**
    - On aarch64, the only per-object check left is `(ET_REL, 183)`.
    - All of `inspect_object` is gone: GNU-stack, `.rustc`, the `_start` and undefined-symbol boundaries, the owned-CRT note, and the requirement that crt1, rcrt1 and Scrt1 differ.
    - Qualifying-path.

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

30. **The musl compatibility alias is hardcoded to `{}`.** Sites: `compat/corpus/run_x86.py:55`, `compat/lua/run_x86_dynamic.py:93, 1083, 1106, 1119`, `owned_dynamic_package.py:30`, `owned_libc_test.py` (`validate_product`) and the builders.
    - x86 derives `profile.aliases`.
    - Qualifying-path, moderate.

31. **`compat/corpus/run_x86.py:474`**
    - aarch64 skips any `.SIGN.*` file instead of the named key. `apk verify` still runs.
    - Qualifying-path, low.

32. **`crt/src/x86_64_crt1.rs:176-193`**
    - The aarch64 static `_start` branches straight to static-PIE start.
    - It loses x86's check that rejects a finalizer register without a handoff, or a handoff without the register.
    - Qualifying-path, low.

## D. ldso / libc

33. **`ldso/src/x86_64_direct_entry.rs:106-107`**
    - The AT_EXECFN rewrite is now `#[cfg(target_arch = "x86_64")]` only. The two architectures diverge against one shared oracle, so one of them is wrong.
    - Qualifying-path.

34. **`ldso/src/x86_64_initial_graph.rs:2304-2306`**
    - aarch64 dynamic startup lacks musl's HWCAP/HWCAP2 SME masking, which the aarch64 static path does (`static_tls.rs:954-978`).
    - Qualifying-path.

35. **`fenv_rounding.rs:147-158, 282-290` and `elementary_sqrt.rs:79-158`** (unconfirmed)
    - aarch64 `rintl`, `nearbyintl` and `sqrtl` likely ignore the rounding mode and the inexact flag, because they go through soft-float compiler_builtins.
    - Quick check: after `fesetround(FE_UPWARD)`, `rintl(2.5L)` should return 3 and raise `FE_INEXACT`.
    - Qualifying-path.

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

40. **`crabc-rs/src/fs.rs:2258-2287`**: the `Stat` size, alignment and offset assertions are x86-only, with no aarch64 values. Raw kernel writes depend on that layout. The layout is correct today by hand calculation.
41. **`crabc-rs/src/event.rs:270-279`**: the epoll `Event` layout assertions are x86-only. The aarch64 check compares two identical definitions, so it proves nothing.
42. **crabc-rs tests**: the x86-only suites were not ported (`x86_64_mm`, epoll, poll, pselect, statat, memfd, child_*, process_kill, thread_kill, clock_nanosleep and others). The merged code now runs on aarch64 untested.
43. **`ldso/src/x86_64_initial_graph.rs:4785` vs `:1241-1243`**: the self-relocation tests are x86-only, and the aarch64 bootstrap is never compiled under test.
44. **ldso relocation tests**: no aarch64 version of the PC32 commit-after-preflight test, and no tests of dynamic TLSDESC or hardened TLSDESC RELRO.
45. **`ldso/src/x86_64_initial_graph.rs:2523`**: the test lowers `tls_align` to 1 on aarch64.
46. **`libc/.../descriptor_entry.rs:217`**: the x86 `O_DIRECTORY` value is `O_DIRECT` on aarch64, so that test case never runs there.
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

59. **`crabc-rs/src/process.rs:385`**: `PreparedExec::spawn` changed from `fork_raw()` to `fork()`. That runs atfork callbacks and blocks and restores the full signal mask around the clone, which contradicts `parity.toml:835, 839`.
60. **crabc-rs public API grew on x86**: public `fork`, `register_atfork`, `wait*`, `setsid` and others.
    - New unsafe `mmap_with_flags`, `mmap_anonymous_with_flags` and `mprotect_with_flags` (`mm.rs:628-655`) skip `checked_map_bits` and `checked_protection_bits`.
    - Also new: `renameat_whiteout`, `ResolveFlags::CACHED` (needs kernel 5.12) and `ioctl_tiocgptpeer`.
61. **Legacy syscalls replaced on x86 too.** In libc and crabc-core, `poll`/`select`/`pause`/`access`/`open`/`chown`/`mkdir`/`pipe`/`dup2`/`fork` now go through the `*at`/`p*`/`dup3`/`clone` forms. musl x86_64 uses the legacy calls. `owned_spawn.rs:67-74` shows the cfg pattern that keeps them.
62. **Renamed crabc-rs tests break the x86 harness**: 37 `--test x86_64_*` references in `dev-x86_64.sh` (for example `:4482, 4523`), assertions in `test_runner.py:1827/1905`, and `compat/crabc-rs/coverage.toml:2895-2977`. They fail loudly, but the x86 evidence commands are broken.
63. **`crabc-rs/src/resolver.rs:815-855`**: invalid search domains are now skipped instead of rejecting the file, on both architectures. This was intentional, but it goes beyond musl, which keeps IP-literal entries.
64. **`compat/x86_64/loader_debug_abi_trace.c:94-104`**: the new path-stat fallback also applies on x86. Borderline.

## Equivalent or not findings
- **Equivalent translations**:
  - `aarch64_rcrt1.rs` matches the x86 rcrt1 step for step.
  - `Aarch64Reader` is a copy of `native.Reader`.
  - Using `-fno-pic` to force a COPY relocation is the right aarch64 spelling; the exact COPY-relocation check still runs.
  - `R_AARCH64_ABS32` (258) is the right counterpart of `R_X86_64_32`/`32S`.
  - The outline-atomics allowlist in `builtins/build.py` is stricter than before.
  - The two aarch64 oracle checks (wordexp and crypt) use the strong `pinned_musl_identity`.
  - The thread-pointer and TLS-offset translations are correct for the aarch64 layout.
- **Unported but fails closed**: `header_declaration_inventory`, `owned_dynamic_fork_evidence`, `owned_errno_storage_lifecycle`, `owned_public_data_variable_runtime`, `runtime_private_facades`, `consumer_static_pie_lto`, `consumer_native_facade_lto`, resolver-network and Lua dynamic dispatch. The candidate plan's `abi-declarations` step therefore cannot complete on aarch64.
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