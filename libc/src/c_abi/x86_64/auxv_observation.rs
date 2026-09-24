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
//! secure-execution policy, `secure_getenv`, or loader state. Narrow private
//! accessors also serve allocator page-size initialization, main-thread stack
//! observation, and the owned static executable's program-header enumeration.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 auxiliary-vector observation leaf requires little-endian Linux/x86-64");

use core::{
    ffi::c_ulong,
    sync::atomic::{AtomicUsize, Ordering},
};

use super::errno;

const MAX_AUXV_ENTRIES: usize = 4096;
const AT_NULL: usize = 0;
const AT_PAGESZ: usize = 6;
#[cfg(crabc_x86_owned_runtime)]
const AT_SYSINFO_EHDR: usize = 33;
pub(super) const AT_EXECFN: usize = 31;
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

/// Read one value from the startup-published, already validated auxv vector.
fn initial_value(item: usize) -> Option<usize> {
    let auxv = INITIAL_AUXV.load(Ordering::Acquire) as *const usize;
    if auxv.is_null() {
        return None;
    }
    for index in 0..MAX_AUXV_ENTRIES {
        // SAFETY: startup publishes only its validated, bounded initial vector.
        let tag = unsafe { core::ptr::read(auxv.add(index * 2)) };
        if tag == AT_NULL {
            return None;
        }
        if tag == item {
            // SAFETY: every auxv record has its value in the next machine word.
            return Some(unsafe { core::ptr::read(auxv.add(index * 2 + 1)) });
        }
    }
    None
}

/// Borrow the startup-published vector address as the original stack anchor.
///
/// `pthread_getattr_np` uses this exact address for musl's initial-stack
/// mapping probe. Both owned CRT paths publish it before application code;
/// this accessor neither exposes the vector publicly nor changes its owner.
#[cfg(crabc_x86_owned_runtime)]
pub(super) fn initial_stack_anchor() -> Option<usize> {
    let address = INITIAL_AUXV.load(Ordering::Acquire);
    (address != 0).then_some(address)
}

/// Return the kernel-published executable name without changing `errno`.
///
/// Musl uses `AT_EXECFN` when the initial `argv[0]` is null. Startup has
/// already validated this immutable vector before the program-name globals
/// are installed, so this bounded lookup neither parses a foreign vector nor
/// exposes a new public auxiliary-vector interface.
pub(super) fn initial_execfn() -> Option<*const core::ffi::c_char> {
    initial_value(AT_EXECFN)
        .filter(|value| *value != 0)
        .map(|value| value as *const core::ffi::c_char)
}

/// Return the kernel vDSO image base (`AT_SYSINFO_EHDR`) once startup has
/// published the initial vector; `None` before publication or when absent.
/// Only the owned clock route consumes it, as musl's `__vdsosym` does.
#[cfg(crabc_x86_owned_runtime)]
pub(super) fn initial_sysinfo_ehdr() -> Option<usize> {
    initial_value(AT_SYSINFO_EHDR).filter(|base| *base != 0)
}

/// Return the startup-published `AT_PAGESZ` value without calling the public
/// `__getauxval` ABI or changing the initial thread's errno.
///
/// The native allocator startup consumes this only after `install_initial`.
/// It is intentionally a private startup fact, not another general auxv
/// consumer or an allocator/process-lifecycle owner.
#[cfg(feature = "native-mimalloc-shadow")]
pub(super) fn initial_page_size() -> Option<usize> {
    initial_value(AT_PAGESZ).filter(|page_size| *page_size != 0)
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
    if let Some(value) = initial_value(item as usize) {
        return value as c_ulong;
    }

    // SAFETY: an absent auxiliary-vector item has the selected C errno
    // result in the calling thread's already initialized initial-TLS slot.
    unsafe { errno::set_errno(ENOENT) };
    0
}

/// Kernel main-executable program-header coordinates, published by owned CRT.
#[cfg(all(crabc_x86_owned_runtime, not(crabc_x86_dynamic_runtime)))]
pub(super) struct InitialProgramHeaders {
    pub(super) address: *const u8,
    pub(super) entry_size: usize,
    pub(super) count: usize,
}

/// Observe only the three static main-image tags without altering errno.
///
/// Musl's static `dl_iterate_phdr` collects the last value for each auxv tag.
/// Startup has validated the terminating vector and static TLS has validated
/// the ELF table before this immutable address is published.
#[cfg(all(crabc_x86_owned_runtime, not(crabc_x86_dynamic_runtime)))]
pub(super) fn initial_program_headers() -> Option<InitialProgramHeaders> {
    let auxv = INITIAL_AUXV.load(Ordering::Acquire) as *const usize;
    if auxv.is_null() {
        return None;
    }
    let mut headers = InitialProgramHeaders { address: core::ptr::null(), entry_size: 0, count: 0 };
    for index in 0..MAX_AUXV_ENTRIES {
        // SAFETY: owned startup published the validated immutable vector.
        let tag = unsafe { core::ptr::read(auxv.add(index * 2)) };
        if tag == AT_NULL {
            return Some(headers);
        }
        let value = unsafe { core::ptr::read(auxv.add(index * 2 + 1)) };
        match tag {
            3 => headers.address = value as *const u8, // AT_PHDR
            4 => headers.entry_size = value, // AT_PHENT
            5 => headers.count = value, // AT_PHNUM
            _ => {}
        }
    }
    None
}
