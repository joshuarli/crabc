//! Loader-to-libc startup snapshot for a conventional musl CRT main image.
//!
//! This is deliberately distinct from the established 72-byte main-only TLS
//! RuntimeV1 descriptor. The latter is resolved only into Rust-owned Scrt1;
//! this 88-byte record is resolved only into the one retained canonical libc
//! object after the ordinary main has been classified as conventional. Both
//! records borrow the same immutable initial graph and `InstalledInitialTls`;
//! neither allocates TLS, owns an additional graph, or widens loader imports.

use super::*;
use core::sync::atomic::{AtomicU8, Ordering};

const MAGIC: u64 = 0x4352_4142_435f_4331;
const VERSION: u32 = 1;
const ABI_SIZE: u32 = 88;
const PROCESS_MODE_DYNAMIC: u32 = 2;
const OWNER_LDSO: u32 = 1;
const GENERATION_INITIAL: u64 = 1;
const UNPUBLISHED: u8 = 0;
const PUBLISHING: u8 = 1;
const READY: u8 = 2;

/// Exact loader-owned v1 bytes. Callback addresses remain raw integers until
/// libc has acquired READY, checked the exact layout, and rejected zeroes;
/// this avoids forming a Rust function pointer from malformed foreign bytes.
#[repr(C)]
pub(super) struct ConventionalStartupV1 {
    magic: u64,
    version: u32,
    abi_size: u32,
    process_mode: u32,
    owner: u32,
    state: AtomicU8,
    reserved: [u8; 7],
    thread_pointer: *const u8,
    dtv: *const usize,
    dtv_words: usize,
    module_count: usize,
    generation: u64,
    run_initial: usize,
    process_fini: usize,
}

const _: () = {
    assert!(core::mem::size_of::<AtomicU8>() == 1);
    assert!(core::mem::align_of::<AtomicU8>() == 1);
    assert!(core::mem::size_of::<ConventionalStartupV1>() == ABI_SIZE as usize);
};

#[used]
#[no_mangle]
pub static mut __crabc_x86_64_loader_conventional_startup_v1: ConventionalStartupV1 =
    ConventionalStartupV1 {
        magic: MAGIC,
        version: VERSION,
        abi_size: ABI_SIZE,
        process_mode: PROCESS_MODE_DYNAMIC,
        owner: OWNER_LDSO,
        state: AtomicU8::new(UNPUBLISHED),
        reserved: [0; 7],
        thread_pointer: core::ptr::null(),
        dtv: core::ptr::null(),
        dtv_words: 0,
        module_count: 0,
        generation: GENERATION_INITIAL,
        run_initial: 0,
        process_fini: 0,
    };

/// Unforgeable only within this private module: the TLS transaction receives
/// it after the pre-FS CAS and must either return it to [`release`] on rollback
/// or pass it to [`publish`] after RuntimeRegistry publication.
pub(super) struct Reservation(());

/// Reserve the record before the one `ARCH_SET_FS` transition.
pub(super) fn reserve() -> Option<Reservation> {
    let record = core::ptr::addr_of_mut!(__crabc_x86_64_loader_conventional_startup_v1);
    if unsafe {
        (*record).state.compare_exchange(
            UNPUBLISHED,
            PUBLISHING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
    }
    .is_err()
    {
        return None;
    }
    Some(Reservation(()))
}

/// Undo only a pre-FS reservation. No payload field is populated until the
/// non-fallible post-FS publication path, so releasing this word is complete.
pub(super) fn release(_: Reservation) {
    let record = core::ptr::addr_of_mut!(__crabc_x86_64_loader_conventional_startup_v1);
    unsafe { (*record).state.store(UNPUBLISHED, Ordering::Release); }
}

/// Return the private record address only to the exact relocation admission.
pub(super) fn address() -> u64 {
    core::ptr::addr_of!(__crabc_x86_64_loader_conventional_startup_v1) as usize as u64
}

/// Publish after the canonical graph, TLS attachment, and RuntimeRegistry are
/// all durable. `reservation` proves the corresponding CAS occurred before
/// `ARCH_SET_FS`; every field assignment below is consequently infallible.
///
/// # Safety
/// `installed` is the unique successful result from the retained graph's TLS
/// materialization, and `RuntimeRegistry::publish` has completed immediately
/// before this call. The record is selected only for `MainCrtMode::Conventional`.
pub(super) unsafe fn publish(_: Reservation, installed: InstalledInitialTls) {
    let record = core::ptr::addr_of_mut!(__crabc_x86_64_loader_conventional_startup_v1);
    debug_assert_eq!(unsafe { (*record).state.load(Ordering::Relaxed) }, PUBLISHING);
    unsafe {
        (*record).thread_pointer = installed.thread_pointer.cast_const();
        (*record).dtv = installed.dtv.cast_const();
        (*record).dtv_words = installed.dtv_words;
        (*record).module_count = installed.module_count;
        (*record).run_initial = super::x86_64_general_initial_lifecycle::conventional_dependency_constructors as *const () as usize;
        (*record).process_fini = super::x86_64_general_initial_lifecycle::process_finalizer as *const () as usize;
        // READY is the sole release publication. The libc consumer may form
        // full record references and callback pointers only after acquiring it.
        (*record).state.store(READY, Ordering::Release);
    }
}
