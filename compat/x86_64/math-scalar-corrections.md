# Native scalar math conformance corrections

The native x86 math providers preserve the algorithms from musl 1.2.6 while
correcting demonstrated result and exception defects in four source bodies.
This is C ABI compatibility machinery within the mature-algorithms policy in
`AGENTS.md`, not a new math implementation or a numerical-support limitation. The independent pinned musl
oracle remains unchanged. Candidate success and oracle failure are distinct
observations; matched failures do not establish conformance.

## Source and build ownership

The source authority is musl release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`, normalized
complete source-tree SHA-256
`2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88`.
Each existing generator validates that unmodified tree before applying
`math_scalar_corrections.py` to a temporary source copy. Exact replacement
anchors fail closed on source drift. Pinned GCC 15.2.0 emits the checked PIC
assembly; Rust builds consume that assembly through the existing modules.
No production C compiler, external runtime object, dependency, or FMA ISA is
introduced. AArch64 sources and selection remain unchanged.

| Upstream body | Established algorithm and license | Native owner / generator suffix |
| --- | --- | --- |
| `src/math/fmaf.c` (baseline generic path of `src/math/x86_64/fmaf.c`) | David Schultz's FreeBSD binary64 product/add with residual correction; BSD-2-Clause notice | `math_scalar_completion.rs` / `scalar_completion` |
| `src/math/fmal.c`, `add_and_denormalize` | David Schultz's FreeBSD scaled Dekker double-double arithmetic and sticky-bit adjustment; BSD-2-Clause notice | `math_elementary_long_double.rs` / `elementary_long_double` |
| `src/math/powf.c` | Arm logarithm/exponential table kernel; MIT notice | `math_pow.rs` / `pow` |
| `src/math/nextafterl.c`, binary80 branch | Musl's representation-based adjacent-value stepping; musl MIT license | `math_special.rs` / `special` |

Owners live in `libc/src/c_abi/x86_64/`; generators are
`compat/x86_64/generate_libc_math_SUFFIX.py`. Source-specific copyright and
license notices remain in their generated assembly. The corrected bodies are
explicitly identified as deltas, not byte-identical upstream translations.
Only these four existing assembly artifacts change.

## Binary32 FMA midpoint spacing

A product of two finite binary32 values is exact in binary64: it requires at
most 48 significant bits and its exponent range fits. Musl then adds the third
operand and repairs a binary64 result exactly halfway between adjacent
binary32 values by recovering the residual and adjusting one binary64 ULP.
That established algorithm is retained.

The original fixed 29-bit midpoint mask describes normal binary32 spacing.
Subnormal binary32 spacing is always `2^-149`. A binary64 value with unbiased
exponent `E` has ULP `2^(E-52)`, so the subnormal spacing discards
`n = -97-E` binary64 significand bits. For `-150 <= E <= -127`, `n` runs from
53 through 30. Midpoint testing includes the implicit significand bit; this
covers the zero/minimum-subnormal midpoint when `n=53`. Smaller magnitudes
cannot be binary32 midpoints. The original normal test, exact-result bypass,
signed residual repair, exceptional inputs, and directed modes are retained.

For example, the pinned source returns the upper neighbour for
`fmaf(-0x1.001p-81f, 0x1.ffe002p-70f, 0x1.0002p-133f)` under RN. Exact dyadic
arithmetic requires `0x1.0001p-133f`, with underflow and inexact. The correction
also resolves all seven retained upstream `special/fmaf.h` result failures.

## Binary80 FMA rounding and tininess

`add_and_denormalize` receives a high component and a sticky-encoded residual
from the original Dekker/double-double algorithm. Its `dd_add` computes the
same RN high component as the ordinary `r.hi + adj` path, plus an exact low
residual. `add_adjusted` preserves the information needed by that final
rounding through round-to-odd encoding. The earlier `r.hi == 0` branch owns
cancellation to zero. These invariants are unchanged.

Two defects occur here. First, `bits_lost` must use only the magnitude exponent:
the binary80 sign bit in `u.i.se` is not part of the exponent. Including it
misclassifies the one-bit denormalization case for negative results. Masking
it restores the original tie/sticky decision for both signs.

Second, the tie repair can make the final `scalbnl` exact even though the
original result was tiny and inexact. A nonzero exact `sum.lo` certifies that
the exact sum is not representable at working precision, hence cannot be exact
in the coarser destination subnormal lattice. Tininess must be classified
using the **original** RN `sum.hi` exponent plus `scale`, before tie/sticky
mutation. Biased exponent plus scale `<= 0` means tiny. This is x86's rounding
to destination precision with an unbounded exponent, as specified by
[Intel SDM volume 1, §§4.9.1.5 and 8.5.5](https://cdrdv2-public.intel.com/789574/253665-sdm-vol-1.pdf).
The final stored result can be minimum-normal while still requiring underflow.
The correction raises underflow and inexact when the saved tininess predicate
and nonzero residual both hold. Hardware scaling retains ordinary exact-low
cases, including half-ULP boundary ties. Existing sticky flags are preserved;
no floating comparison of a subnormal result introduces an extra operand flag.

For the original RN failing vector
`fmal(-0x1p-10000L, 0x1.0000000000001p-6445L, 0x1p-16382L)`, let
`q=2^-16445`, the binary80 subnormal spacing. Its exact result is
`LDBL_MIN - q - 2^-16497`: it rounds to maximum-subnormal and requires both
underflow and inexact. Pinned musl omits underflow.

The minimum-normal regression is
`fmal(-0x1p-10000L, 0x1.0000000000000002p-6447L, 0x1p-16382L)`.
Its exact value is slightly more than `q/4` below minimum-normal. RN at
unbounded binary80 precision rounds to the tiny half-step below minimum-normal;
final subnormal rounding returns minimum-normal. Both underflow and inexact
are required. The independent integer judge applies this rule to every FMA
vector, with no oracle-flag inheritance or case-name exceptions.

## Binary80 adjacent values and finite powers

When stepping from negative minimum-normal toward zero, `nextafterl` decrements
its stored sign/exponent word to `0x8000`. The original nonzero test mistakes
the sign for a remaining exponent, resets the significand, and then wraps it
to all ones. Masking the exponent preserves the required transition to the
canonical negative maximum-subnormal value. This also fixes directed FMA
paths that call `nextafterl`. Direct tests cover both signs and both directions
around normal/subnormal and minimum-subnormal/zero transitions.

For finite `powf(x, 1)`, an exact identity path returns the original bits before
entering the unchanged approximation. It preserves negative zero and avoids
spurious overflow, underflow, and inexact. Signalling NaNs and infinities stay
on the original exceptional-input path. Because the identity performs no
floating arithmetic, subnormal inputs also no longer raise x86's non-IEEE
`denormal operand` status bit. This finite difference is separately recorded;
the standard-five-exception mask does not hide unexplained status changes.

## Evidence boundaries and reproduction

`./scripts/dev-x86_64.sh math-scalar-corrections` retains its evidence directory.
The six isolated regressions run first: a corrected candidate returns zero;
the independent pinned musl executable returns failure bitmask 63. The stream
then checks 25,632 deterministic exact-dyadic vectors across all four rounding
modes and both clean and pre-existing divide-by-zero/inexact flags. It covers
signed zeros, quiet/signalling NaNs, infinities, subnormals, normal boundaries,
and positive/negative FMA and `nextafterl` transitions. Native result bits,
rounding state, all six x86 status bits, exact expectations, and per-arm failures
are retained. The integer judge separately rounds at bounded and unbounded
exponents; no host floating-point library supplies expected values.

The pure ABI proof compiles the actual production math/fenv modules through
`math_scalar_corrections_boundary.rs` into one `no_std` Rust object. Its native
freestanding executables have strong public providers, no unresolved symbols,
TLS, dynamic interpreter/library, AVX/FMA, or packed arithmetic instructions.
It also reruns the existing 9,064 family records: scalar completion (304),
binary80 completion (196), pow (256), elementary-long-double (2,764), and
special functions (5,544). The pow comparator requires exact finite identities
and preserves every other pinned record. The other four streams compare byte
for byte. This proof is separate from installed runtime integration: the whole
owned archive groups unrelated startup/regex/TLS state in some codegen units.

`run_math_scalar_corrections_libc_test.py --sysroot PATH --evidence PATH`, inside
the pinned native environment, tests the actual installed static product.
It acquires the pinned libc-test revision
`68edb8bd73dab8147ee54c8bec638f4d2b3cff37`, retains its unmodified source and
complete `fmaf`, `fmal`, `powf`, and `nextafterl` units, compiles shared application
objects with isolated installed headers, and links the candidate through the
sealed driver. Independent fixed-musl links use the same objects. Full output,
exit status, commands, and candidate link receipts remain available. A separate
installed regression seeds `errno` and verifies that all six correction vectors
leave it unchanged. This is a
focused four-unit static proof, not the full native dynamic libc-test aggregate.
Global native qualification and final oracle-defect dispositions remain with
the aggregate owner. None of these checks promotes x86 public support.
