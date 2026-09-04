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
use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

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


/// Addressable C11 `atomic_flag` storage.
///
/// The project header defines `atomic_flag` as a one-byte record.  Keeping
/// the Rust boundary byte-based avoids creating a Rust `bool` from a
/// caller-supplied C representation before the atomic operation has observed
/// it.
#[repr(C)]
pub struct AtomicFlag {
    value: u8,
}

const _: [(); 1] = [(); core::mem::size_of::<AtomicFlag>()];
const _: [(); 1] = [(); core::mem::align_of::<AtomicFlag>()];

/// Translate the C11 ordering values accepted by read-modify-write operations.
#[inline(always)]
fn c_rmw_order(order: c_int) -> Ordering {
    match order {
        0 => Ordering::Relaxed,
        // C11 consume is conservatively acquire, as it is in the compiler
        // atomic builtin boundary used by the project header.
        1 | 2 => Ordering::Acquire,
        3 => Ordering::Release,
        4 => Ordering::AcqRel,
        5 => Ordering::SeqCst,
        // An invalid C enum value is outside the caller contract. Do not
        // permit it to turn into a Rust panic across this C ABI boundary.
        _ => Ordering::SeqCst,
    }
}

/// Translate orders permitted for C11 atomic-store operations.
#[inline(always)]
fn c_store_order(order: c_int) -> Ordering {
    match order {
        0 => Ordering::Relaxed,
        3 => Ordering::Release,
        5 => Ordering::SeqCst,
        // Acquire and acquire-release stores are outside C11's caller
        // contract. Use a conservative non-panicking fallback for malformed
        // foreign calls.
        _ => Ordering::SeqCst,
    }
}

/// Translate a C11 fence order, where relaxed is explicitly a no-op.
#[inline(always)]
fn c_fence_order(order: c_int) -> Option<Ordering> {
    match order {
        0 => None,
        1 | 2 => Some(Ordering::Acquire),
        3 => Some(Ordering::Release),
        4 => Some(Ordering::AcqRel),
        _ => Some(Ordering::SeqCst),
    }
}

/// Borrow the caller's one-byte C atomic object for one immediate operation.
///
/// # Safety
///
/// `flag` must designate a live, properly aligned `atomic_flag` object. All
/// concurrent accesses to that object must be atomic and compatible with the
/// ordering selected by the caller.
#[inline(always)]
unsafe fn c_atomic_flag<'a>(flag: *mut AtomicFlag) -> &'a AtomicU8 {
    // SAFETY: `AtomicFlag` is a repr(C), one-byte C atomic object and the
    // caller contract above provides its lifetime, alignment, and atomic
    // access discipline for this immediate operation.
    unsafe { AtomicU8::from_ptr(flag.cast()) }
}

/// Clear an address-taken C11 `atomic_flag` with sequential consistency.
///
/// # Safety
///
/// `flag` must point to a live C `atomic_flag`; all concurrent accesses must
/// be atomic and obey the C11 sequentially consistent synchronization
/// contract.
#[no_mangle]
pub unsafe extern "C" fn atomic_flag_clear(flag: *mut AtomicFlag) {
    // SAFETY: upheld by this exported function's C caller contract.
    unsafe { c_atomic_flag(flag) }.store(0, Ordering::SeqCst);
}

/// Clear an address-taken C11 `atomic_flag` with the requested store order.
///
/// # Safety
///
/// `flag` must point to a live C `atomic_flag`; all concurrent accesses must
/// be atomic. `order` must be a C11 store-compatible `memory_order` value.
#[no_mangle]
pub unsafe extern "C" fn atomic_flag_clear_explicit(flag: *mut AtomicFlag, order: c_int) {
    // SAFETY: upheld by this exported function's C caller contract.
    unsafe { c_atomic_flag(flag) }.store(0, c_store_order(order));
}

/// Set an address-taken C11 `atomic_flag`, returning its previous truth value.
///
/// # Safety
///
/// `flag` must point to a live C `atomic_flag`; all concurrent accesses must
/// be atomic and obey the C11 sequentially consistent synchronization
/// contract.
#[no_mangle]
pub unsafe extern "C" fn atomic_flag_test_and_set(flag: *mut AtomicFlag) -> bool {
    // SAFETY: upheld by this exported function's C caller contract.
    unsafe { c_atomic_flag(flag) }.swap(1, Ordering::SeqCst) != 0
}

/// Set an address-taken C11 `atomic_flag` with the requested RMW order.
///
/// # Safety
///
/// `flag` must point to a live C `atomic_flag`; all concurrent accesses must
/// be atomic. `order` must be a C11 read-modify-write-compatible
/// `memory_order` value.
#[no_mangle]
pub unsafe extern "C" fn atomic_flag_test_and_set_explicit(
    flag: *mut AtomicFlag,
    order: c_int,
) -> bool {
    // SAFETY: upheld by this exported function's C caller contract.
    unsafe { c_atomic_flag(flag) }.swap(1, c_rmw_order(order)) != 0
}

#[no_mangle]
pub extern "C" fn atomic_signal_fence(order: c_int) {
    if let Some(ordering) = c_fence_order(order) {
        core::sync::atomic::compiler_fence(ordering);
    }
}

#[no_mangle]
pub extern "C" fn atomic_thread_fence(order: c_int) {
    if let Some(ordering) = c_fence_order(order) {
        core::sync::atomic::fence(ordering);
    }
}
