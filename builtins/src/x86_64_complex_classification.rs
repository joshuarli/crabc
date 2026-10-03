//! x86 floating comparisons for the binary32 and binary64 complex helpers.
//! The exact instructions retain the source algorithm's exception flags.

// Floating classification is observable through x86's denormal-operand
// status bit. Integer bit tests would omit that source comparison effect.
// Ordered comparison also keeps the source's NaN branch ahead of MAXSD-like
// speculation, so a first-operand quiet NaN is propagated without invalid.
pub(super) fn complex_division_is_nan(value: f64) -> bool {
    let unordered: u8;
    // SAFETY: register-only comparison and byte output access no memory or
    // stack. The floating exception state is deliberately observable.
    unsafe {
        core::arch::asm!(
            "ucomisd {value}, {value}", "setp {unordered}",
            value = in(xmm_reg) value, unordered = lateout(reg_byte) unordered,
            options(nomem, nostack)
        );
    }
    unordered != 0
}

pub(super) fn complex_division_is_finite(value: f64) -> bool {
    let within: u8;
    let ordered: u8;
    // SAFETY: all operands and outputs reside in registers; no memory is
    // accessed. Quiet comparison retains the source classification flags.
    unsafe {
        core::arch::asm!(
            "ucomisd {value}, {maximum}", "setbe {within}", "setnp {ordered}",
            value = in(xmm_reg) value.abs(), maximum = in(xmm_reg) f64::MAX,
            within = lateout(reg_byte) within, ordered = lateout(reg_byte) ordered,
            options(nomem, nostack)
        );
    }
    within != 0 && ordered != 0
}

pub(super) fn complex_division_is_infinite(value: f64) -> bool {
    let above: u8;
    // SAFETY: this register-only comparison accesses no memory or stack.
    // An unordered operand clears the ordered-above condition.
    unsafe {
        core::arch::asm!(
            "ucomisd {value}, {maximum}", "seta {above}",
            value = in(xmm_reg) value.abs(), maximum = in(xmm_reg) f64::MAX,
            above = lateout(reg_byte) above, options(nomem, nostack)
        );
    }
    above != 0
}

pub(super) fn complex_division_ordered_less(left: f64, right: f64) -> bool {
    let below: u8;
    let ordered: u8;
    // SAFETY: register-only comparison and byte outputs access no memory.
    // The ordered source comparison raises invalid for a NaN right operand.
    unsafe {
        core::arch::asm!(
            "comisd {left}, {right}", "setb {below}", "setnp {ordered}",
            left = in(xmm_reg) left, right = in(xmm_reg) right,
            below = lateout(reg_byte) below, ordered = lateout(reg_byte) ordered,
            options(nomem, nostack)
        );
    }
    below != 0 && ordered != 0
}

pub(super) fn float_complex_is_nan(value: f32) -> bool {
    let unordered: u8;
    // SAFETY: register-only comparison and byte output access no memory or
    // stack. The floating exception state is deliberately observable.
    unsafe {
        core::arch::asm!(
            "ucomiss {value}, {value}", "setp {unordered}",
            value = in(xmm_reg) value, unordered = lateout(reg_byte) unordered,
            options(nomem, nostack)
        );
    }
    unordered != 0
}

pub(super) fn float_complex_is_finite(value: f32) -> bool {
    let within: u8;
    let ordered: u8;
    // SAFETY: all operands and outputs reside in registers; no memory is
    // accessed. Quiet comparison retains the source classification flags.
    unsafe {
        core::arch::asm!(
            "ucomiss {value}, {maximum}", "setbe {within}", "setnp {ordered}",
            value = in(xmm_reg) value.abs(), maximum = in(xmm_reg) f32::MAX,
            within = lateout(reg_byte) within, ordered = lateout(reg_byte) ordered,
            options(nomem, nostack)
        );
    }
    within != 0 && ordered != 0
}

pub(super) fn float_complex_is_infinite(value: f32) -> bool {
    let above: u8;
    // SAFETY: this register-only comparison accesses no memory or stack.
    // An unordered operand clears the ordered-above condition.
    unsafe {
        core::arch::asm!(
            "ucomiss {value}, {maximum}", "seta {above}",
            value = in(xmm_reg) value.abs(), maximum = in(xmm_reg) f32::MAX,
            above = lateout(reg_byte) above, options(nomem, nostack)
        );
    }
    above != 0
}

pub(super) fn float_complex_ordered_less(left: f32, right: f32) -> bool {
    let below: u8;
    let ordered: u8;
    // SAFETY: register-only comparison and byte outputs access no memory.
    // The ordered source comparison raises invalid for a NaN right operand.
    unsafe {
        core::arch::asm!(
            "comiss {left}, {right}", "setb {below}", "setnp {ordered}",
            left = in(xmm_reg) left, right = in(xmm_reg) right,
            below = lateout(reg_byte) below, ordered = lateout(reg_byte) ordered,
            options(nomem, nostack)
        );
    }
    below != 0 && ordered != 0
}

