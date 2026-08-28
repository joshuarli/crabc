//! Selected static Linux/x86-64 `inttypes.h` intmax arithmetic C ABI.
//!
//! This leaf owns exactly `imaxabs` and `imaxdiv`. It is a direct extension of
//! the selected scalar integer-arithmetic block, not integer parsing or the
//! wider `inttypes.h` conversion surface. It is stateless and allocation-free,
//! with no syscall, errno, TLS, locale, cancellation, mutable-global-state, or
//! callback boundary. It is not `strtoimax`/`strtoumax`, sorting/searching,
//! floating-point math, libc.so, a CRT, a loader, a sysroot, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/stdlib/imaxabs.c` maps to the width-specific absolute-value entry
//!   below.
//! - `src/stdlib/imaxdiv.c` maps to the quotient/remainder aggregate entry
//!   below.
//!
//! Linux/x86-64 LP64 fixes C `intmax_t` to the signed 64-bit `long` ABI, and
//! `imaxdiv_t` to two adjacent `intmax_t` fields returned through the normal
//! two-register SysV aggregate convention. C leaves an unrepresentable
//! absolute value, a zero divisor, and an unrepresentable signed-minimum
//! divided by `-1` quotient undefined. `wrapping_neg` prevents accidental Rust
//! overflow-panic machinery for the first case; native signed `idiv` retains
//! the ordinary processor fault for the two invalid division cases. Neither
//! behavior outside C's defined domain is part of this artifact's contract.

use core::ffi::c_long;

/// ABI-only counterpart of C's `imaxdiv_t` on Linux/x86-64 LP64.
#[repr(C)]
pub struct ImaxDivResult {
    quot: c_long,
    rem: c_long,
}

/// Divide two C `intmax_t` values with x86's signed quotient/remainder
/// instruction.
#[inline]
fn divide_intmax(numerator: c_long, denominator: c_long) -> ImaxDivResult {
    let quotient: c_long;
    let remainder: c_long;
    // SAFETY: C `intmax_t` is the x86-64 LP64 signed 64-bit `long` ABI. `cqo`
    // sign-extends RAX into RDX:RAX and `idiv` returns the C quotient and
    // remainder pair in those registers. A zero divisor or unrepresentable
    // quotient is C undefined behavior and retains the x86 divide fault rather
    // than acquiring a Rust panic or TLS dependency.
    unsafe {
        core::arch::asm!(
            "cqo",
            "idiv {denominator}",
            denominator = in(reg) denominator,
            inout("rax") numerator => quotient,
            out("rdx") remainder,
            options(nomem, nostack),
        );
    }
    ImaxDivResult {
        quot: quotient,
        rem: remainder,
    }
}

/// Return the C `intmax_t` absolute value for its defined input domain.
#[no_mangle]
pub extern "C" fn imaxabs(value: c_long) -> c_long {
    if value < 0 {
        value.wrapping_neg()
    } else {
        value
    }
}

/// Return C `imaxdiv_t` quotient and remainder for the defined division
/// domain.
#[no_mangle]
pub extern "C" fn imaxdiv(numerator: c_long, denominator: c_long) -> ImaxDivResult {
    divide_intmax(numerator, denominator)
}
