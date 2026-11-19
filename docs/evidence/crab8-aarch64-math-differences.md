# CRAB-8 AArch64 math differences from pinned musl

`compat/x86_64/validate_owned_math_fenv_all_entry_aarch64.py` compares every
arm64 math/fenv all-entry record from each candidate entry mode with pinned
musl. A record passes only when it equals the musl record, or when it
satisfies one named contract in `CONTRACTS`. Agreement with the owned-helper
reference never accepts a record by itself. This file is the reference for
those contracts: their bounds, their independent justification and the counts
observed on the real products.

## Comparison inputs

`compat/x86_64/run_owned_math_fenv_all_entry.sh` links one installed-header
workload three ways.

| Stream | Link | Role |
| --- | --- | --- |
| `oracle-run` | Pinned musl `libc.a` and the image's libgcc | The oracle: the `[musl_native]` snapshot `7813e9119eb5` in `compat/upstreams.toml` |
| `reference-run` | Pinned musl `libc.a`, the candidate `libcrabc-builtins.a` as the only compiler runtime, and the candidate `sqrtl`, `rintl` and `nearbyintl` members | Composition model only |
| six candidate runs | The candidate static, static-PIE and dynamic products | The records under test |

The reference answers one question: does musl's own code, composed with the
candidate binary128 helpers, reproduce a candidate record? Contracts use that
answer only to attribute a difference. No contract accepts a record because
the reference agrees with it.

### Reference composition

`owned_math_fenv_aarch64_reference.py` extracts exactly `sqrtl`, `rintl` and
`nearbyintl` from the candidate `libc.a`. They stay in the reference because
their own correctness is checked against pristine musl, not against the
reference:

- The validator's protected set (stage 7 function 32, stage 10 functions 32,
  44, 50, 51 and 52) requires the reference record to equal the musl record.
  No contract names these functions, so the candidate record must equal musl
  too.
- `owned_sqrtl_snan_probe.c` runs inside stage 10 of the oracle, the reference
  and every candidate. A failure makes the stage status nonzero, and `read`
  rejects the stream.

`acoshl` is not in the reference. Its correction departs from musl, so a
reference that carried it would agree with the candidate and hide the
departure. The `acoshl-domain-flags` contract requires the reference record to
equal musl, so re-adding `acoshl` to the reference fails every corrected
`acoshl` record.

The candidate `libcrabc-builtins.a` stays because it is the composition that
`cpowl-nan-propagation` attributes its difference to.

## Contract `acoshl-domain-flags`

| Field | Bound |
| --- | --- |
| Operation | `acoshl`: stage 7 function 1 (record kind 1) and stage 10 function 1 (kind 3, `KIND_LONG_DOUBLE`) |
| Input class | x is not a NaN and x < 1: every negative value including -0 and -infinity, and 0 <= x < 1. Stage 10 reads x from the record operand. Stage 7 reads it from `ELEMENTARY_OPERANDS`, the `l_values` table of `libc_math_elementary_long_double_probe.c`, by case index. |
| Rounding | All four modes |
| musl result | A NaN, bit-identical to the candidate result |
| musl flags | `FE_INVALID`, plus only the flags that narrowing x to binary64 can raise: `FE_INEXACT` only when x is not exactly representable in binary64, `FE_OVERFLOW` only when \|x\| > `DBL_MAX`, `FE_UNDERFLOW` only when 0 < \|x\| < `DBL_MIN` and x is not exact (`narrowing_exceptions`) |
| Candidate flags | Exactly `FE_INVALID` |
| Other fields | Identical to musl: case, rounding, kind, FPCR, the FPSR upper half, errno, auxiliary, signgam and operand |
| Reference | Equal to musl |

**musl behavior.** The pinned snapshot's `src/math/acoshl.c` lines 27-32
implement binary128 `acoshl` as `return acosh(x);` under
`// TODO: broken implementation to make things compile`, so the conversion to
`double` happens before any domain check. Its `src/math/acosh.c` lines 20-22
return `(x-x)/(x-x)` for a negative binary64 argument, which raises only
`FE_INVALID`. For 0 <= x < 1, lines 14-16 take the square root of
`(x-1)*(x-1)+2*(x-1)`, which is negative and raises `FE_INVALID`. The contract
admits an extra musl flag only when narrowing x itself can raise it.

**Candidate behavior.** Commit `819c3e4aa` classifies the binary128 argument
before narrowing. For x < 1 it calls `feraiseexcept(FE_INVALID)` and returns
the quiet NaN `0x7fff8000...0`. `owned_acoshl_domain_probe.c` checks that
NaN-and-invalid result in all four modes.

**Justification.** ISO C17 F.10.3.1 specifies that "acosh(x) returns a NaN and
raises the "invalid" floating-point exception for x < 1". F.10 adds three
rules. "Whether or when library functions raise the "inexact" floating-point
exception is unspecified, unless explicitly specified otherwise." "Whether or
when library functions raise an undeserved "underflow" floating-point
exception is unspecified." Otherwise "the <math.h> functions do not raise
spurious floating-point exceptions (detectable by the user), other than the
"inexact" floating-point exception". The candidate's result and `FE_INVALID` meet F.10.3.1. Dropping
`FE_INEXACT` and the undeserved `FE_UNDERFLOW` is permitted. musl's
`FE_OVERFLOW` for a finite argument whose result is a NaN is a spurious
exception, so the candidate corrects it.

## Contract `cpowl-nan-propagation`

| Field | Bound |
| --- | --- |
| Operation | `cpowl`: stage 10 function 185, kind 9 (`KIND_LONG_DOUBLE_PAIR`) |
| Input class | Boundary phase only (case bit 15 clear). The case must be in `CPOWL_NAN_PRODUCT_CASES`: rows 0, 1, 4, 5 and 6 of the `l_complex` table in `libc_math_abi_boundary_probe.c` as z (cases `0x000`, `0x001`, `0x004`, `0x005`, `0x006`), and rows 4 and 5 as c (`0x104`, `0x105`). In each case the complex product `c * clogl(z)` has two NaN factors. |
| Rounding | All four modes |
| musl result | Each of the two binary128 components equals the candidate component, or both components are quiet NaNs. Only the NaN sign and payload may differ. |
| Flags | FPSR exception bits identical to musl |
| Other fields | Identical to musl: case, rounding, kind, FPCR, the FPSR upper half, errno, auxiliary, signgam and operand |
| Reference | Equal to the candidate |

**musl behavior.** The pinned snapshot's `src/complex/cpowl.c` line 11 is
`return cexpl(c * clogl(z));`. Its `src/complex/clogl.c` lines 10-17 build
`clogl(z)` from `cabsl`, `cargl` and `logl`, so a NaN component of z gives two
NaN factors. `src/complex/cexpl.c` line 6 is `return cexp(z);`, so the
propagated NaN keeps only the payload bits that survive binary64.

**Attribution.** The candidate `cpowl` in
`libc/src/c_abi/x86_64/math_complex_complete_musl_aarch64.S` is the
pinned-compiler translation of the same `cpowl.c`.
It calls `__multf3`, `__subtf3`, `__addtf3`, `__unordtf2` and, for a NaN
product, `__multc3` from `libcrabc-builtins.a`. musl's oracle gets those
helpers from libgcc. The reference keeps musl's own `cpowl` object and replaces
only the compiler runtime, and it reproduces all 20 candidate records bit for
bit. The NaN choice therefore comes from the selected binary128 helpers. Their
`__multc3` is the compiler-rt 22.1.3 `multc3.c` translation recorded in
`builtins/UPSTREAM.md`.

**Justification.** IEEE 754-2019 §6.3 states that "For all other operations,
this standard does not specify the sign bit of a NaN result, even when there is
only one input NaN, or when the NaN is produced from an invalid operation".
Only copy, negate, abs and copySign are excluded. §6.2.3 states that "If two
or more inputs are NaN, then the payload of the resulting NaN should be
identical to the payload of one of the input NaNs if representable in the
destination format. This standard does not specify which of the input NaNs
will provide the payload." C17 F.3 maps C `*`, `+` and `-` to these IEC 60559
operations. G.5.1 specifies the infinity properties of complex
multiplication, not the sign or payload of a NaN result. Every other field,
including all exception flags, must still equal musl.

## Observed counts

The run on the real arm64 products built from this branch reported the same
counts for all six candidate entry modes.

| Account | Records | Detail |
| --- | ---: | --- |
| `musl` | 74676 | Bit-identical to pinned musl |
| `acoshl-domain-flags` | 200 | Stage 7: 4 with musl flags 21 (`-LDBL_MAX`) and 12 with 25 (`-LDBL_TRUE_MIN`, `LDBL_TRUE_MIN`, `LDBL_MIN`). Stage 10: 128 with 17, 16 with 21 and 40 with 25. The candidate has flags 1 in all 200. |
| `cpowl-nan-propagation` | 20 | Cases `0x001` and `0x005`: sign only. Cases `0x004` and `0x104`: payload only. Case `0x105`: sign and payload. Four rounding modes each. |

The reference also differs from musl in 32 `cpow` and `cpowf` records (stage
10 functions 183 and 184). The candidate equals musl in all 32 because its
`cpow` and `cpowf` call private compiler-rt translations, not the archive
`__muldc3` and `__mulsc3`. They count as `musl` and need no contract.

## Regression tests

`compat/x86_64/tests/test_owned_math_fenv_all_entry_aarch64.py` checks the
rejection rule and each bound:

- `test_reference_agreement_never_accepts_an_uncontracted_difference`
  rejects a difference in stages 7, 9 and 10 when the candidate equals the
  reference. The stage 7 case is the `acoshl` correction carried by the
  reference.
- `test_acoshl_contract_accepts_only_narrowing_flags_on_domain_errors`
  accepts the observed flag classes. It rejects x >= 1, a NaN argument, flags
  not explained by narrowing, extra or missing candidate flags, another
  function, a different or non-NaN result, a different errno, and a reference
  that carries the correction.
- `test_narrowing_exceptions_follow_binary64_representability` covers the
  binary64 range and precision edges.
- `test_cpowl_contract_accepts_only_quiet_nan_sign_and_payload` accepts the
  observed sign and payload cases. It rejects the dense phase, a single NaN
  factor, another function, a finite or signaling component, different flags,
  and a reference that does not reproduce the candidate.
