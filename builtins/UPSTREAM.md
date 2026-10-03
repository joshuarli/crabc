# Compiler-helper source provenance

`libcrabc-builtins.a` is assembled from Rust source only. `build.py` records
the exact hashes of every selected upstream Rust file in its adjacent
provenance JSON; this document explains the durable source boundary.

| Surface | Source oracle | License | crabc production path | Intentional difference |
| --- | --- | --- | --- | --- |
| `__muldc3` | LLVM compiler-rt 22.1.3, `lib/builtins/muldc3.c` | Apache-2.0 WITH LLVM-exception | `src/lib.rs::multiply_complex_double` | Direct Rust translation preserves the four-product and NaN/infinity recovery sequence; Rust `f64` classification methods replace C macros. |
| x86 `__divdc3` | LLVM compiler-rt 22.1.3, `lib/builtins/divdc3.c` and the binary64 `logb`, `scalbn`, and `fmax` helpers in `lib/builtins/fp_lib.h` | Apache-2.0 WITH LLVM-exception | `src/lib.rs::{divide_complex_double,complex_division_normalize,complex_division_logb,complex_division_scalbn}` | Direct Rust translation preserves divisor scaling and the zero/NaN/infinity recovery order. Bit representations replace C unions; x86 quiet floating classifications preserve the source macros' observable denormal-operand flags and ordered NaN comparison effects. Scaling uses floating-point products for rounding and underflow, without libc or libm calls. The export is x86-only. |
| x86 private `math.complex` `__mulsc3`/`__muldc3`/`__mulxc3` support | LLVM compiler-rt 22.1.3, `lib/builtins/{mulsc3,muldc3,mulxc3}.c` | Apache-2.0 WITH LLVM-exception | `compat/x86_64/complex_mul_support.c` is translated into local symbols in `libc/src/c_abi/x86_64/math_complex_complete_musl_x86_64.S` | Direct C source translation retains the four-product and NaN/infinity recovery sequence. The generated symbols are local implementation details of the x86 static `math.complex` leaf; this does not link a compiler-runtime archive or add a production dependency. |
| x86 binary64/integer128 conversions | `compiler_builtins` 0.1.160 from pinned `nightly-2026-09-15` rust-src, `compiler-builtins/src/float/conv.rs` (SHA-256 `1ec3627f95be4a4e6b0e25c0ecaff9040e4ef68222a4df7398a422fb55a61ac8`) | MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0) | `src/lib.rs::{uint128_to_binary64_bits,binary64_to_uint128}` and the four x86-only cast entries | Faithful specialization of `int_to_float::u128_to_f64_bits`, `signed`, and `float_to_int_inner` with `Uint128` shifts and limbs replacing native 128-bit operations. Nearest-even rounding, truncation, saturation, sign handling, and NaN-to-zero source branches remain intact. No new package or prebuilt runtime is consumed. |
| x86 binary32/integer128 conversions | The same pinned `compiler_builtins` 0.1.160 `float/conv.rs` source and SHA-256 | MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0) | `src/lib.rs::{uint128_to_binary32_bits,binary32_to_uint128}` and `__fixsfti`, `__fixunssfti`, `__floattisf`, `__floatuntisf` | Faithful specialization of `int_to_float::u128_to_f32_bits`, `signed`, and `float_to_int_inner`. Two limbs replace native integer128 operations; the discarded-bit compression preserves direct 24-bit nearest-even rounding, including unsigned overflow to infinity. No intermediate binary64 conversion or new dependency is used. |
| x86 `__udivmodti4` optional remainder argument | `compiler_builtins` 0.1.160 from pinned `nightly-2026-09-15`, `compiler-builtins/src/int/udiv.rs` (SHA-256 `1e00dbc9721832469cef87465124b51f8856074344ad1fee120b276e5b2b1dab`) | MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0) | `src/lib.rs::__udivmodti4` | The x86 entry accepts a null slot for quotient-only calls, matching the source `Option<&mut u128>` ABI. Non-null slots still receive the remainder. Signed `__divmodti4` keeps the mandatory slot required by pinned `int/sdiv.rs`. Arithmetic remains the owned two-limb implementation; paused AArch64 behavior is unchanged. |
| Existing `__int128`, byte, and bit helpers | narrow crabc-owned Rust implementations in `src/lib.rs` | MIT OR Apache-2.0 | direct `rustc --emit=obj` object | These preserve the pre-existing explicit AAPCS64 two-word representation and do not use a prebuilt compiler runtime. |
| AArch64 binary128 arithmetic, comparison, and conversion helpers | Historical source attribution: `compiler_builtins` 0.1.160 from the `nightly-2026-07-24` rust-src component: `compiler-builtins/src/float/{add,cmp,conv,div,extend,mul,pow,sub,trunc}.rs` and their Rust support modules | MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0) | fresh `-Zbuild-std=core,compiler_builtins` source build, then only `compiler_builtins-*.o` members are installed | No C fallback is selected. The `c` and `mem` features are rejected, as are native build commands and a prebuilt target `compiler_builtins` archive. |

The upstream package still declares `links = "compiler-rt"` because Rust can
optionally build compiler-rt C fallbacks. In this sysroot that metadata is an
audited exception, not authority to compile or link native runtime code:
`build.py` requires `c` to be absent, records an empty native-build-command
set, and proves the final archive closure has no external runtime undefined
symbols.

The source build is Cargo `--locked`; its record binds the pinned Rust
library lock plus both `compiler-builtins/build.rs` and its imported
`libm/configure.rs`. Those build-script inputs select Rust cfgs, so they are
part of the provenance rather than an implicit toolchain detail. The selected
Rust math sources may use established AArch64 inline assembly, but this path
never selects a C, C++, or external `.S` target input.

The source-built `core` lane is compiler context for `compiler_builtins`; no
`core` object member is copied into `libcrabc-builtins.a`. The archive's own
member list, ELF inspection, symbol inventory, and LLD whole-archive closure
are the installed-artifact evidence.

The adjacent command record is part of that evidence: it records the sealed
Cargo source build, extraction of only `compiler_builtins-*.o`, deterministic
`llvm-ar rcsD` construction, and archive-surface audit. The provenance file
stores the command record's exact filename and SHA-256, so an assembler cannot
declare a substituted archive verified by presenting only a feature summary.

The double-complex division oracle is retained byte-for-byte under
`fixtures/llvm22_divdc3`, including its headers, license, and SHA-256 input
roster. It is the LLVM `llvmorg-22.1.3` source snapshot:
`divdc3.c` SHA-256 `f6ebfa99e5a208078e998cf87e539f25a92d86e4e316fe983f4031f1745d938a`
and `fp_lib.h` SHA-256 `cf3a5301c95986a9b392edba32dfe7ac27d3352d266e284e528a09413f84f6cc`.
These C files are test-only inputs, excluded from the production archive.
`run_x86_64_divdc3.sh` proves a compiler-emitted call in a closed freestanding
image and compares output components and floating-point exception flags against
the renamed C oracle under all four rounding modes. NaN payload selection is
not compared; finite values, infinity signs, and signed zeros are bit-exact.

`run_x86_64_binary32_casts.sh` retains the exact pinned conversion source and
its Rust support sources as test-only inputs, compiles them with mangled names,
and compares all four helpers in a closed freestanding image. The production
archive never contains this oracle. The separate compiler-emitted C caller
uses only defined float-to-integer inputs and in-range integer-to-float values;
direct helper calls exercise NaNs, infinities, saturation, and integer-to-float
overflow outside that C conversion domain.

The source algorithm rounds integer-to-binary32 conversions to nearest with
ties to even independently of the hardware rounding mode. Float-to-integer
conversions truncate in-range values, saturate overflow and infinities, and
return zero for NaNs and negative unsigned inputs. These total helper branches
do not define otherwise undefined C casts. The test compiles C with `-O2`,
`-ffp-contract=off`, and `-frounding-math`, checks the native binary32 and
integer128 compiler macros, and compares raw results and MXCSR exception flags
under all four SSE rounding controls with gradual underflow enabled. The
bit-based helpers preserve zero exception flags, including for signaling NaNs;
they do not promise to follow the current floating-point rounding direction.
The x86 System V ABI carries integer128 values in low/high register words,
binary32 arguments in XMM0, and binary32 results in XMM0.

The multiplication oracle is retained byte-for-byte as
`fixtures/llvm22_muldc3/muldc3.c` from the same LLVM `llvmorg-22.1.3`
snapshot, with its license and SHA-256 roster. Its unchanged includes use the
matching headers retained in `fixtures/llvm22_divdc3`; the C kernel is test-only.
`fixtures/x86_64_muldc3_differential.c` compares both complex result components
and exception flags under all four rounding modes. Signed zeros and all
non-NaN representations compare exactly; NaN payload selection is excluded.
The aggregate C fixture additionally performs ordinary complex multiplication,
and its assembly entry checks the four XMM argument registers, the two XMM
result registers, stack restoration, and all six callee-saved integer registers.
