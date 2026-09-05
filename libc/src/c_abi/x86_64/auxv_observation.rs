//! Bounded static Linux/x86-64 auxiliary-vector observation.
//!
//! This leaf publishes only the validated kernel initial auxiliary vector to
//! musl-compatible `__getauxval`/weak `getauxval` callers. It owns neither the
//! vector's storage nor its lifetime: Linux owns the initial stack and the
//! selected static startup path validates its envp and `(tag, value)`
//! delimiters before publishing the one raw pointer. The stored pointer is
//! immutable after that handoff, so acquire/release publication makes a
//! constructor or later caller observe the completed validation without
//! acquiring a loader, environment, allocator, or general startup owner.
//!
//! Translation provenance is musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/misc/getauxval.c` supplies the first-matching-pair lookup, zero
//! result, and `ENOENT`-on-absence contract, plus the weak same-address
//! `getauxval` alias. The selected x86 leaf deliberately returns the raw
//! observed `AT_SECURE` value like every other tag; it does not select musl's
//! secure-execution policy, `secure_getenv`, loader state, or any auxiliary
//! vector consumer beyond this direct C lookup.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 auxiliary-vector observation leaf requires little-endian Linux/x86-64");

use core::{
    ffi::c_ulong,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::errno;

const MAX_AUXV_ENTRIES: usize = 4096;
const AT_NULL: usize = 0;
const ENOENT: core::ffi::c_int = 2;

// A dynamic loader normally owns this hidden process field. The selected
// static archive instead has one startup publication point and never exports
// its raw pointer, which keeps this artifact to lookup rather than a general
// auxv state API.
static INITIAL_AUXV: AtomicUsize = AtomicUsize::new(0);

// Musl's weak_alias(__getauxval, getauxval) is a same-address ELF function
// alias. A Rust forwarding wrapper would have a distinct address and change
// the source-specific override contract.
core::arch::global_asm!(
    ".weak getauxval",
    ".set getauxval, __getauxval",
);

/// Publish the already validated kernel auxiliary-vector pointer.
///
/// # Safety
///
/// `auxv` must point to a live, naturally aligned kernel/CRT `(tag, value)`
/// vector terminated by `AT_NULL`. It may be installed exactly by the
/// selected static startup handoff before constructors or application code;
/// callers must not republish a foreign or mutable vector.
pub(super) unsafe fn install_initial(auxv: *const usize) {
    // SAFETY: The selected startup path validated this pointer and all bounded
    // pair delimiters before its sole process-wide release publication.
    INITIAL_AUXV.store(auxv as usize, Ordering::Release);
}

/// Borrow the startup-published vector address as the original stack anchor.
///
/// `pthread_getattr_np` uses this exact address for musl's initial-stack
/// mapping probe. Both owned CRT paths publish it before application code;
/// this accessor neither exposes the vector publicly nor changes its owner.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) fn initial_stack_anchor() -> Option<usize> {
    let address = INITIAL_AUXV.load(Ordering::Acquire);
    (address != 0).then_some(address)
}

/// Return one raw value from the validated Linux initial auxiliary vector.
///
/// A found zero-valued record, including normal unprivileged `AT_SECURE=0`,
/// preserves `errno`. An absent tag, `AT_NULL` query, or unavailable startup
/// vector returns zero and publishes `ENOENT` in the calling initial-TLS C
/// errno slot.
///
/// # Safety
///
/// The selected static startup path must have completed its one validated
/// initial-vector publication before this call. This C ABI function accepts
/// no caller-owned pointer and does not transfer ownership of the kernel
/// initial stack.
#[no_mangle]
pub unsafe extern "C" fn __getauxval(item: c_ulong) -> c_ulong {
    let auxv = INITIAL_AUXV.load(Ordering::Acquire) as *const usize;
    if !auxv.is_null() {
        for index in 0..MAX_AUXV_ENTRIES {
            // SAFETY: `install_initial` accepts only the bounded
            // AT_NULL-terminated kernel vector validated by static startup.
            let tag = unsafe { core::ptr::read(auxv.add(index * 2)) };
            if tag == AT_NULL {
                break;
            }
            if tag == item as usize {
                // SAFETY: every auxiliary-vector record contains its value in
                // the immediately following machine word.
                return unsafe { core::ptr::read(auxv.add(index * 2 + 1)) as c_ulong };
            }
        }
    }

    // SAFETY: an absent auxiliary-vector item has the selected C errno
    // result in the calling thread's already initialized initial-TLS slot.
    unsafe { errno::set_errno(ENOENT) };
    0
}
