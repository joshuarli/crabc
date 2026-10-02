# Private x86-64 unsigned 128-bit compiler-helper proof

`builtins/run_x86_64_udivmodti4.sh` proves the owned Rust-only archive's C ABI
for `__udivti3`, `__umodti3`, and `__udivmodti4`. This is private evidence for
the bounded archive, not a complete compiler runtime, installed public sysroot,
libc capability, CRT startup, or dynamic-loader proof.

## Source and ABI boundary

`builtins/src/lib.rs` implements all three helpers through
`Uint128::divmod_unsigned`. `Uint128` is `#[repr(C)]` with low then high 64-bit
words. `__udivmodti4` accepts a null remainder pointer for a quotient-only
call on x86-64, matching the pinned compiler helper ABI. A non-null pointer
must identify an aligned writable `Uint128` slot; `write_remainder` stores
the remainder there. The signed sibling requires its result slot.
The runner rebuilds `builtins/build_x86_64.py`'s one-member archive twice,
checks byte reproducibility and provenance, and hashes the source, pinned
compiler wrapper, reference `libgcc.a`, archive, final ELF, and result streams.

`builtins/fixtures/x86_64_udivmodti4_probe.c` calls the three helpers directly
in the candidate. Its reference arm evaluates ordinary unsigned C `/` and `%`
with the pinned musl x86 toolchain and its `libgcc.a`. Both arms use the same
freestanding `_start` and Linux write syscall to emit four 128-bit results per
case: division quotient, modulus remainder, divmod quotient, and divmod slot.
The runner requires byte-for-byte equality over 950 cases: combinations of
zero, limb-edge, high-limb, maximum, and near-maximum numerators and divisors;
all 128 power-of-two divisors at four quotient boundaries; and deterministic
mixed limbs. Each case also checks a null-slot quotient-only call against
the ordinary division result. Every divisor is nonzero; unsigned construction and shifts stay
within their defined C ranges.

The candidate object must have exactly those three undefined helper symbols.
The archive-free link must fail on all three. The final static x86-64 `ET_EXEC`
must trace every definition to `libcrabc-builtins.a(crabc-builtins.o)`, retain
calls to the three helpers, and have no ambient CRT/compiler runtime input,
interpreter, dynamic dependency, TLS, executable stack, unresolved symbol, or
runtime relocation. The link map, traces, disassembly, ELF inspection, output
streams, provenance JSON, and hashes remain under the checkout's ignored
`.work/x86_64/builtins-udivmodti4/` directory.

Run in the pinned native image after `./scripts/dev-x86_64.sh image`:

```sh
bash /workspace/builtins/run_x86_64_udivmodti4.sh
```

Division by zero and invalid non-null output pointers are outside the helper contract.
The signed `__divmodti4` sibling is not covered here. This proof does not
promote public x86 support or alter archive admission.
