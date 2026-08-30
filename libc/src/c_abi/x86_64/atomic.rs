//! Linux/x86-64 C-ABI atomic helpers.
//!
//! The standalone native probe established this exact i32 helper contract
//! before it was admitted to the selected static archive. It now serves the
//! private normal-mutex and its private condition-variable handoff artifacts,
//! plus the separately bounded pthread rwlock state machine, but remains far
//! smaller than a general C atomic or pthread
//! synchronization runtime. The complete public C runtime remains
//! Linux/AArch64-only until every x86 promotion gate passes.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 atomic leaf requires little-endian Linux/x86-64");

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

/// Load one aligned `i32` with acquire ordering.
///
/// x86's ordinary aligned 32-bit load is already acquire-compatible under
/// TSO. Using `AtomicI32::from_ptr` makes the C object's concurrent-access
/// contract explicit to Rust without manufacturing a mutable reference to
/// caller-owned storage.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage. Every
/// concurrent access to that storage must be atomic and compatible with this
/// acquire ordering.
#[inline(always)]
pub(crate) unsafe fn x86_64_load_acquire_i32(address: *const c_int) -> c_int {
    // SAFETY: the caller supplies a live aligned C atomic word and retains
    // the complete concurrent-access contract for its lifetime.
    unsafe { AtomicI32::from_ptr(address.cast_mut()) }.load(Ordering::Acquire)
}

/// Load one aligned `i32` as a relaxed bookkeeping hint.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage. Every
/// concurrent access to that storage must be atomic and compatible with this
/// relaxed operation.
#[inline(always)]
pub(crate) unsafe fn x86_64_load_relaxed_i32(address: *const c_int) -> c_int {
    // SAFETY: the caller supplies a live aligned C atomic word and retains
    // the complete concurrent-access contract for its lifetime.
    unsafe { AtomicI32::from_ptr(address.cast_mut()) }.load(Ordering::Relaxed)
}

/// Compare one aligned `i32` with an x86 locked `cmpxchg`.
///
/// A locked x86 read-modify-write is sequentially consistent, which is
/// stronger than the acquire/release success and acquire failure orderings
/// required by the corresponding AArch64 helper. `cmpxchg` leaves the value
/// observed in `eax` on both the success and mismatch paths.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage for the
/// whole operation. All concurrent accesses to that storage must use atomic
/// operations compatible with this acquire/release synchronization protocol.
#[inline(always)]
pub(crate) unsafe fn x86_64_compare_exchange_acqrel_i32(
    address: *mut c_int,
    expected: c_int,
    desired: c_int,
) -> c_int {
    let observed: c_int;
    // SAFETY: `address` is the raw pthread/atomic storage supplied by the
    // caller. `lock cmpxchg` atomically compares against eax, stores only on
    // a match, and returns the prior value in eax on either path. Its locked
    // memory operation supplies acquire/release ordering (and, on x86, the
    // stronger total-ordering guarantee) without a compiler helper call.
    unsafe {
        core::arch::asm!(
            "lock cmpxchg dword ptr [{address}], {desired:e}",
            address = in(reg) address,
            desired = in(reg) desired,
            inout("eax") expected => observed,
            options(nostack),
        );
    }
    observed
}

/// Exchange one aligned `i32` with x86's implicitly locked memory `xchg`.
///
/// The old value is returned. A memory `xchg` is implicitly locked, so it has
/// the same sequentially consistent ordering as the locked compare-exchange
/// and fetch-add helpers.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage for the
/// whole operation. All concurrent accesses to that storage must use atomic
/// operations compatible with this acquire/release synchronization protocol.
#[inline(always)]
pub(crate) unsafe fn x86_64_swap_acqrel_i32(address: *mut c_int, desired: c_int) -> c_int {
    let previous: c_int;
    // SAFETY: `address` is the raw pthread/atomic storage supplied by the
    // caller. Memory `xchg` is indivisible and implicitly locked on x86; the
    // tied register operand receives the value replaced in memory.
    unsafe {
        core::arch::asm!(
            "xchg dword ptr [{address}], {desired:e}",
            address = in(reg) address,
            desired = inout(reg) desired => previous,
            options(nostack),
        );
    }
    previous
}

/// Add to one aligned `i32` with a locked x86 `xadd`, returning the old value.
///
/// The hardware operation deliberately supplies wrapping two's-complement
/// arithmetic, matching `AtomicI32::fetch_add(AcqRel)` for every `i32`
/// addend. The locked instruction is sequentially consistent on x86 and is
/// therefore stronger than the acquire/release ordering required here.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage for the
/// whole operation. All concurrent accesses to that storage must use atomic
/// operations compatible with this acquire/release synchronization protocol.
#[inline(always)]
pub(crate) unsafe fn x86_64_fetch_add_acqrel_i32(address: *mut c_int, value: c_int) -> c_int {
    let previous: c_int;
    // SAFETY: `address` is the raw pthread/atomic storage supplied by the
    // caller. `lock xadd` atomically adds the register value, returns the old
    // value in that register, and wraps at the i32 width selected by `dword`.
    unsafe {
        core::arch::asm!(
            "lock xadd dword ptr [{address}], {value:e}",
            address = in(reg) address,
            value = inout(reg) value => previous,
            options(nostack),
        );
    }
    previous
}

/// Subtract from one aligned `i32` with the same locked RMW contract as add.
///
/// Negating the addend with wrapping arithmetic preserves the exact i32
/// behavior, including `i32::MIN`, without introducing a second assembly
/// sequence or a non-atomic load/store window.
///
/// # Safety
///
/// `address` must point to live, four-byte-aligned atomic storage for the
/// whole operation. All concurrent accesses to that storage must use atomic
/// operations compatible with this acquire/release synchronization protocol.
#[inline(always)]
pub(crate) unsafe fn x86_64_fetch_sub_acqrel_i32(address: *mut c_int, value: c_int) -> c_int {
    // SAFETY: forwards the caller's valid atomic storage to the locked add;
    // wrapping negation is the i32 subtraction identity for all addends.
    unsafe { x86_64_fetch_add_acqrel_i32(address, value.wrapping_neg()) }
}
