//! Private consumer for the loader's conventional-musl startup snapshot.
//!
//! The merged interpreter/libc image binds this weak GOT reference to the
//! in-image record. The loader publishes READY only for a conventional main
//! and STATE_OWNED for owned startup. Rust-owned Scrt1 keeps the older 72-byte
//! main-only RuntimeV1 wire.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU8, Ordering};

const MAGIC: u64 = 0x4352_4142_435f_4331;
const VERSION: u32 = 1;
const ABI_SIZE: u32 = 88;
const PROCESS_MODE_DYNAMIC: u32 = 2;
const PROCESS_MODE_OWNED: u32 = 3;
const OWNER_LDSO: u32 = 1;
const GENERATION_INITIAL: u64 = 1;
const STATE_OWNED: u8 = 3;
const STATE_READY: u8 = 2;
type LifecycleFunction = unsafe extern "C" fn();

#[repr(C)]
struct Header {
    magic: u64,
    version: u32,
    abi_size: u32,
}

/// This exact 88-byte layout deliberately keeps callback words raw. A wrong
/// or stale record cannot become an invalid Rust function pointer while libc
/// is still deciding whether it may access loader-installed `%fs` state.
#[repr(C)]
struct Record {
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
    assert!(core::mem::size_of::<Header>() == 16);
    assert!(core::mem::size_of::<Record>() == ABI_SIZE as usize);
};

// The fixed product libc keeps this weak GOT data reference. The merged link
// binds it to the loader's record; ldso publishes the owned or conventional
// state, preserving Scrt1's existing startup ownership.
global_asm!(
    ".section .text.__crabc_x86_conventional_startup_v1_record,\"ax\",@progbits",
    ".weak __crabc_x86_64_loader_conventional_startup_v1",
    ".type __crabc_x86_64_loader_conventional_startup_v1,@object",
    ".hidden __crabc_x86_conventional_startup_v1_record",
    ".global __crabc_x86_conventional_startup_v1_record",
    ".type __crabc_x86_conventional_startup_v1_record,@function",
    "__crabc_x86_conventional_startup_v1_record:",
    "mov rax, qword ptr [rip + __crabc_x86_64_loader_conventional_startup_v1@GOTPCREL]",
    "ret",
    ".size __crabc_x86_conventional_startup_v1_record, .-__crabc_x86_conventional_startup_v1_record",
);

unsafe extern "C" {
    fn __crabc_x86_conventional_startup_v1_record() -> *const u8;
}

pub(super) struct Lifecycle {
    pub(super) run_initial: LifecycleFunction,
    pub(super) process_fini: LifecycleFunction,
}

/// A null slot selects the owned route for the split/static shape. The merged
/// image binds the slot in-image, so the published state decides between owned
/// and conventional. Callback-shaped musl CRT arguments never select a
/// lifecycle owner.
pub(super) enum Selection {
    Owned,
    Conventional(Lifecycle),
}

/// Validate the exact immutable snapshot before any `%fs`-relative access.
///
/// The header gate precedes a full record reference; READY is acquired before
/// every payload load; raw callbacks are checked for nonzero only after that
/// acquire. The loader retains the mapping, TLS allocation, and registry for
/// process life, so a successful result may be used until ordinary exit.
pub(super) unsafe fn select() -> Option<Selection> {
    let pointer = unsafe { __crabc_x86_conventional_startup_v1_record() };
    if pointer.is_null() {
        return Some(Selection::Owned);
    }
    if pointer as usize & (core::mem::align_of::<Header>() - 1) != 0 {
        return None;
    }
    let header = unsafe { &*pointer.cast::<Header>() };
    if header.magic != MAGIC || header.version != VERSION || header.abi_size != ABI_SIZE {
        return None;
    }
    let record = unsafe { &*pointer.cast::<Record>() };
    let state = record.state.load(Ordering::Acquire);
    // One merged interpreter/libc image binds the weak slot to its in-image
    // record at link time, so a null GOT word no longer selects the owned CRT.
    // The loader publishes STATE_OWNED only after its reservation succeeds;
    // any other non-READY state stays invalid.
    if state == STATE_OWNED {
        if record.process_mode != PROCESS_MODE_OWNED
            || record.owner != OWNER_LDSO
            || record.reserved != [0; 7]
            || record.generation != GENERATION_INITIAL
        {
            return None;
        }
        return Some(Selection::Owned);
    }
    if state != STATE_READY
        || record.process_mode != PROCESS_MODE_DYNAMIC
        || record.owner != OWNER_LDSO
        || record.reserved != [0; 7]
        || record.generation != GENERATION_INITIAL
        || record.thread_pointer.is_null()
        || record.dtv.is_null()
        || record.thread_pointer as usize & (core::mem::align_of::<usize>() - 1) != 0
        || record.dtv as usize & (core::mem::align_of::<usize>() - 1) != 0
        || record.module_count == 0
        || record.dtv_words < record.module_count.checked_add(1)?
        || record.run_initial == 0
        || record.process_fini == 0
    {
        return None;
    }
    let thread_pointer = unsafe { current_thread_pointer() }?;
    if thread_pointer != record.thread_pointer as usize {
        return None;
    }
    let dtv_slot = thread_pointer.checked_add(core::mem::size_of::<usize>())? as *const usize;
    // Both volatile reads remain below the complete metadata/READY gate. The
    // exact loader record and `%fs:0` self pointer now make this TCB/DTV
    // prefix safe to observe before dynamic_tls::attach_initial_thread reads
    // FS:0.
    if unsafe { core::ptr::read_volatile(record.thread_pointer.cast::<usize>()) } != thread_pointer
        || unsafe { core::ptr::read_volatile(dtv_slot) } != record.dtv as usize
        || unsafe { core::ptr::read_volatile(record.dtv) } != record.module_count
    {
        return None;
    }
    Some(Selection::Conventional(Lifecycle {
        run_initial: unsafe { core::mem::transmute(record.run_initial) },
        process_fini: unsafe { core::mem::transmute(record.process_fini) },
    }))
}

/// Read `%fs:0` only after the record's metadata and READY gate accepted the
/// loader's durable snapshot. The loader writes the self pointer before it
/// publishes READY, so the register is the same word `ARCH_GET_FS` reported.
unsafe fn current_thread_pointer() -> Option<usize> {
    let thread_pointer: usize;
    unsafe {
        asm!("mov {}, fs:[0]", out(reg) thread_pointer, options(nostack, readonly));
    }
    (thread_pointer != 0).then_some(thread_pointer)
}
