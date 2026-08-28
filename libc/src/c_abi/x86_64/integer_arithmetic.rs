//! Selected static Linux/x86-64 integer arithmetic C ABI.
//!
//! This leaf owns exactly `abs`, `labs`, `llabs`, `div`, `ldiv`, and `lldiv`.
//! It is scalar, stateless, allocation-free, and has no syscall, errno, TLS,
//! locale, cancellation, mutable-global-state, or callback boundary. It is
//! not integer parsing, PRNG state, `imaxabs`/`imaxdiv`, sorting/searching,
//! floating-point math, stdio, libc.so, a CRT, a loader, a sysroot, or public
//! x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/stdlib/abs.c`, `src/stdlib/labs.c`, and `src/stdlib/llabs.c` map to
//!   the three width-specific absolute-value entries below.
//! - `src/stdlib/div.c`, `src/stdlib/ldiv.c`, and `src/stdlib/lldiv.c` map to
//!   the three quotient/remainder aggregate entries below.
//!
//! The C contracts leave an unrepresentable absolute value, a zero divisor,
//! and a nonrepresentable quotient (the signed minimum divided by `-1`)
//! undefined. The defined domain has the same truncating quotient and
//! dividend-signed remainder as Rust. `wrapping_neg` keeps an accidental
//! unrepresentable absolute-value input from acquiring a Rust overflow-panic
//! dependency. The three division entries issue the native signed `idiv`
//! instruction, so invalid C division inputs retain the processor-fault
//! behavior rather than acquiring a Rust panic/TLS dependency. Neither
//! behavior outside C's defined domain is part of this artifact's contract.

use core::ffi::{c_int, c_long, c_longlong};

/// ABI-only counterpart of C's `div_t` on Linux/x86-64 LP64.
#[repr(C)]
pub struct DivResult {
    quot: c_int,
    rem: c_int,
}

/// ABI-only counterpart of C's `ldiv_t` on Linux/x86-64 LP64.
#[repr(C)]
pub struct LongDivResult {
    quot: c_long,
    rem: c_long,
}

/// ABI-only counterpart of C's `lldiv_t` on Linux/x86-64 LP64.
#[repr(C)]
pub struct LongLongDivResult {
    quot: c_longlong,
    rem: c_longlong,
}

/// Divide two C `int` values with x86's signed quotient/remainder instruction.
#[inline]
fn divide_int(numerator: c_int, denominator: c_int) -> DivResult {
    let quotient: c_int;
    let remainder: c_int;
    // SAFETY: this target root is Linux/x86-64. `cdq` sign-extends EAX into
    // EDX:EAX and `idiv` reads the distinct general-register denominator,
    // producing exactly the SysV/C signed quotient and remainder registers.
    // A zero divisor or unrepresentable quotient is C undefined behavior and
    // causes the processor's ordinary divide fault rather than a Rust panic.
    unsafe {
        core::arch::asm!(
            "cdq",
            "idiv {denominator:e}",
            denominator = in(reg) denominator,
            inout("eax") numerator => quotient,
            out("edx") remainder,
            options(nomem, nostack),
        );
    }
    DivResult {
        quot: quotient,
        rem: remainder,
    }
}

/// Divide two C `long`/`long long` values with x86's signed instruction.
#[inline]
fn divide_long(numerator: c_long, denominator: c_long) -> LongDivResult {
    let quotient: c_long;
    let remainder: c_long;
    // SAFETY: `c_long` is the x86-64 LP64 signed 64-bit C `long`. `cqo`
    // sign-extends RAX into RDX:RAX and `idiv` returns C's quotient/remainder
    // pair in those registers. The stated C undefined inputs retain an x86
    // divide fault and do not acquire a Rust runtime path.
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
    LongDivResult {
        quot: quotient,
        rem: remainder,
    }
}

/// Divide two C `long long` values with x86's signed instruction.
#[inline]
fn divide_long_long(
    numerator: c_longlong,
    denominator: c_longlong,
) -> LongLongDivResult {
    let quotient: c_longlong;
    let remainder: c_longlong;
    // SAFETY: Linux/x86-64 has 64-bit `long long`; the `cqo`/`idiv` register
    // pair is the same signed C division operation described for `ldiv`.
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
    LongLongDivResult {
        quot: quotient,
        rem: remainder,
    }
}

/// Return the C `int` absolute value for its defined input domain.
#[no_mangle]
pub extern "C" fn abs(value: c_int) -> c_int {
    if value < 0 {
        value.wrapping_neg()
    } else {
        value
    }
}

/// Return the C `long` absolute value for its defined input domain.
#[no_mangle]
pub extern "C" fn labs(value: c_long) -> c_long {
    if value < 0 {
        value.wrapping_neg()
    } else {
        value
    }
}

/// Return the C `long long` absolute value for its defined input domain.
#[no_mangle]
pub extern "C" fn llabs(value: c_longlong) -> c_longlong {
    if value < 0 {
        value.wrapping_neg()
    } else {
        value
    }
}

/// Return C `div_t` quotient and remainder for the defined division domain.
#[no_mangle]
pub extern "C" fn div(numerator: c_int, denominator: c_int) -> DivResult {
    divide_int(numerator, denominator)
}

/// Return C `ldiv_t` quotient and remainder for the defined division domain.
#[no_mangle]
pub extern "C" fn ldiv(numerator: c_long, denominator: c_long) -> LongDivResult {
    divide_long(numerator, denominator)
}

/// Return C `lldiv_t` quotient and remainder for the defined division domain.
#[no_mangle]
pub extern "C" fn lldiv(
    numerator: c_longlong,
    denominator: c_longlong,
) -> LongLongDivResult {
    divide_long_long(numerator, denominator)
}
