/// Compare one aligned `i32` using the Linux/AArch64 acquire/release exclusive
/// sequence. This avoids LLVM's outlined atomic helper, whose LSE capability
/// check is fixed work on every uncontended pthread lock acquisition.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage for the
/// whole operation. All concurrent accesses to that storage must use atomic
/// operations compatible with this acquire/release synchronization protocol.
#[inline(always)]
unsafe fn aarch64_compare_exchange_acqrel_i32(
    address: *mut c_int,
    expected: c_int,
    desired: c_int,
) -> c_int {
    let observed: c_int;
    // SAFETY: `address` is the raw pthread/atomic storage supplied by the
    // caller. `ldaxr` acquires the observed value on either return path, and
    // a successful `stlxr` releases `desired`, matching the former
    // `compare_exchange(AcqRel, Acquire)` ordering without an LSE probe.
    unsafe {
        core::arch::asm!(
            "2:",
            "ldaxr {observed:w}, [{address}]",
            "cmp {observed:w}, {expected:w}",
            "b.ne 3f",
            "stlxr {status:w}, {desired:w}, [{address}]",
            "cbnz {status:w}, 2b",
            "3:",
            address = in(reg) address,
            expected = in(reg) expected,
            desired = in(reg) desired,
            observed = out(reg) observed,
            status = out(reg) _,
            options(nostack),
        );
    }
    observed
}

/// Exchange one aligned `i32` using a Linux/AArch64 acquire/release exclusive
/// loop, returning the value observed by the successful store-exclusive.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage for the
/// whole operation. All concurrent accesses to that storage must use atomic
/// operations compatible with this acquire/release synchronization protocol.
#[inline(always)]
unsafe fn aarch64_swap_acqrel_i32(address: *mut c_int, desired: c_int) -> c_int {
    let previous: c_int;
    // SAFETY: `address` is the raw pthread/atomic storage supplied by the
    // caller. The acquire load obtains the old state and the successful
    // store-exclusive releases `desired`, matching `swap(AcqRel)` without an
    // LSE capability probe.
    unsafe {
        core::arch::asm!(
            "2:",
            "ldaxr {previous:w}, [{address}]",
            "stlxr {status:w}, {desired:w}, [{address}]",
            "cbnz {status:w}, 2b",
            address = in(reg) address,
            desired = in(reg) desired,
            previous = out(reg) previous,
            status = out(reg) _,
            options(nostack),
        );
    }
    previous
}

/// Add to one aligned `i32` using a Linux/AArch64 acquire/release exclusive
/// loop, returning the value observed before the successful store-exclusive.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage for the
/// whole operation. All concurrent accesses to that storage must use atomic
/// operations compatible with this acquire/release synchronization protocol.
#[inline(always)]
unsafe fn aarch64_fetch_add_acqrel_i32(address: *mut c_int, value: c_int) -> c_int {
    let replacement: c_int;
    // SAFETY: `address` is the raw pthread/atomic storage supplied by the
    // caller. The exclusive loop has the same ordering and wrapped `i32`
    // arithmetic as `AtomicI32::fetch_add(AcqRel)`. `value` is an immutable
    // input register: a failed `stlxr` must retry with the original addend,
    // never with the replacement calculated for a prior observed value.
    // This also avoids LLVM's outlined LSE capability dispatch on every
    // condition-variable transition.
    unsafe {
        core::arch::asm!(
            "2:",
            "ldaxr w10, [x12]",
            "add w10, w10, w9",
            "stlxr w11, w10, [x12]",
            "cbnz w11, 2b",
            // Keep the original increment in a different fixed register from
            // the retry-local replacement. Independent general-register
            // operands may be coalesced; that would turn a failed retry into
            // an accidentally growing addend.
            in("x12") address,
            in("w9") value,
            lateout("w10") replacement,
            lateout("w11") _,
            options(nostack),
        );
    }
    replacement.wrapping_sub(value)
}
