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
