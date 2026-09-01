//! Private x86 loader/libc TLS RuntimeV1 consumer.
//!
//! This source is intentionally excluded from `static_c_abi.rs`: a static
//! executable has no `PT_INTERP` and Static Initial TLS v1 remains its sole
//! TLS owner. The isolated dynamic evidence imports one exact weak
//! loader-owned record, validates its complete metadata before touching the
//! loader-installed TCB/DTV, then observes only the already materialized main
//! thread. The fixed and arbitrary-initial-graph producers are cfg-disjoint
//! loader implementations of this same private ABI; libc remains only an
//! observer in both cases. It does not allocate a thread, resolve a runtime
//! TLS module, resize a DTV, install `%fs`, expose `__tls_get_addr`, or select
//! a general dynamic libc/loader runtime.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 loader/libc TLS RuntimeV1 consumer requires little-endian Linux/x86-64");

use core::arch::{asm, global_asm};
use core::ffi::c_int;
use core::sync::atomic::{AtomicU8, Ordering};

const RECORD_MAGIC: u64 = 0x4352_4142_435f_5451;
const RECORD_VERSION: u32 = 1;
const RECORD_SIZE: u32 = 72;
const PROCESS_MODE_DYNAMIC: u32 = 2;
const OWNER_LDSO: u32 = 1;
const GENERATION_INITIAL: u64 = 1;
const STATE_READY: u8 = 2;
const SYS_ARCH_PRCTL: i64 = 158;
const ARCH_GET_FS: i64 = 0x1003;
const LINUX_ERRNO_MAX: i64 = 4_095;

/// Exact `repr(C)` mirror of ldso's private one-shot initial-TLS record.
///
/// Ldso intentionally does not depend on `crabc-core`, so this local mirror
/// keeps the private interpreter standalone. Its fixed size is checked both
/// here and by the native linker/ELF evidence; an append-only future runtime
/// revision must use a new record rather than silently reinterpret it.
#[repr(C)]
struct LoaderLibcTlsRuntimeV1Header {
    magic: u64,
    version: u32,
    abi_size: u32,
}

#[repr(C)]
struct LoaderLibcTlsRuntimeV1 {
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
}

const _: () = {
    assert!(core::mem::size_of::<AtomicU8>() == 1);
    assert!(core::mem::align_of::<AtomicU8>() == 1);
    assert!(core::mem::size_of::<LoaderLibcTlsRuntimeV1Header>() == 16);
    assert!(core::mem::size_of::<LoaderLibcTlsRuntimeV1>() == RECORD_SIZE as usize);
};

// The static-mode variant must contain no weak loader import at all. It is
// used only by the no-PT_INTERP negative fixture and returns null before an
// `ARCH_GET_FS` syscall or any `%fs`-relative memory access can occur.
#[cfg(crabc_loader_libc_tls_runtime_v1_static_mode)]
global_asm!(
    ".section .text.__crabc_x86_loader_tls_runtime_v1_record,\"ax\",@progbits",
    ".hidden __crabc_x86_loader_tls_runtime_v1_record",
    ".global __crabc_x86_loader_tls_runtime_v1_record",
    ".type __crabc_x86_loader_tls_runtime_v1_record,@function",
    "__crabc_x86_loader_tls_runtime_v1_record:",
    "xor eax, eax",
    "ret",
    ".size __crabc_x86_loader_tls_runtime_v1_record, .-__crabc_x86_loader_tls_runtime_v1_record",
);

// The dynamic evidence keeps exactly one weak GOT import. The x86 loader
// recognizes that record only for the main image and only for weak undefined
// data; DSOs and strong/defined imports remain fail-closed in ldso before any
// pointer reaches this consumer.
#[cfg(not(crabc_loader_libc_tls_runtime_v1_static_mode))]
global_asm!(
    ".section .text.__crabc_x86_loader_tls_runtime_v1_record,\"ax\",@progbits",
    ".weak __crabc_x86_64_loader_tls_runtime_v1",
    ".hidden __crabc_x86_loader_tls_runtime_v1_record",
    ".global __crabc_x86_loader_tls_runtime_v1_record",
    ".type __crabc_x86_loader_tls_runtime_v1_record,@function",
    "__crabc_x86_loader_tls_runtime_v1_record:",
    "mov rax, qword ptr [rip + __crabc_x86_64_loader_tls_runtime_v1@GOTPCREL]",
    "ret",
    ".size __crabc_x86_loader_tls_runtime_v1_record, .-__crabc_x86_loader_tls_runtime_v1_record",
);

unsafe extern "C" {
    fn __crabc_x86_loader_tls_runtime_v1_record() -> *const u8;
}

/// Validate the loader record without observing any loader-installed TLS.
///
/// The weak symbol is a private process-internal handoff, not an untrusted
/// public pointer: the dedicated x86 loader resolves it only from its own
/// record into the main image's GOT. Still, null, wrong-revision, wrong-mode,
/// wrong-owner, and internally inconsistent records are all rejected before
/// `ARCH_GET_FS`, `%fs:0`, `%fs:8`, or either descriptor pointer is read.
#[inline(never)]
unsafe fn validate_loader_tls_runtime_v1() -> Option<&'static LoaderLibcTlsRuntimeV1> {
    let record = unsafe { __crabc_x86_loader_tls_runtime_v1_record() };
    if record.is_null()
        || record as usize & (core::mem::align_of::<LoaderLibcTlsRuntimeV1Header>() - 1) != 0
    {
        return None;
    }

    // SAFETY: the dedicated loader only resolves this one weak GOT entry to
    // its process-lifetime record. The fixed header is the minimum prefix
    // needed to reject an unknown ABI size before a full-record reference is
    // formed; a static-mode stub returns null above.
    let header = unsafe { &*record.cast::<LoaderLibcTlsRuntimeV1Header>() };
    if header.magic != RECORD_MAGIC
        || header.version != RECORD_VERSION
        || header.abi_size != RECORD_SIZE
    {
        return None;
    }

    // SAFETY: the exact header size now authorizes this exact v1 layout. The
    // loader keeps the record alive for the process lifetime and publishes its
    // remaining coordinates with the ready-state release store below.
    let record = unsafe { &*record.cast::<LoaderLibcTlsRuntimeV1>() };
    if record.state.load(Ordering::Acquire) != STATE_READY
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
    {
        return None;
    }
    Some(record)
}

/// Obtain the current x86-64 `%fs` base without assuming a libc TLS layout.
///
/// This raw syscall is intentionally below the consumer's C ABI: it is used
/// only after descriptor validation to compare the loader's declared thread
/// pointer with the kernel register state. It neither installs nor changes
/// `%fs`.
#[inline(never)]
unsafe fn current_thread_pointer() -> Option<usize> {
    let mut thread_pointer = 0usize;
    let result: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") SYS_ARCH_PRCTL => result,
            in("rdi") ARCH_GET_FS,
            in("rsi") core::ptr::addr_of_mut!(thread_pointer),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 && result >= -LINUX_ERRNO_MAX || thread_pointer == 0 {
        None
    } else {
        Some(thread_pointer)
    }
}

/// Observe the already-validated minimal Variant-II prefix.
///
/// Every volatile pointer read is intentionally below
/// [`validate_loader_tls_runtime_v1`]'s complete metadata gate. The malformed
/// native fixtures publish address `1` for both pointer fields, so moving any
/// of these reads above that gate turns a clean rejection into a fault.
#[inline(never)]
unsafe fn observe_validated_loader_tls(record: &LoaderLibcTlsRuntimeV1) -> bool {
    let Some(thread_pointer) = (unsafe { current_thread_pointer() }) else {
        return false;
    };
    if thread_pointer != record.thread_pointer as usize {
        return false;
    }
    let dtv_slot = match (record.thread_pointer as usize).checked_add(core::mem::size_of::<usize>()) {
        Some(address) => address as *const usize,
        None => return false,
    };
    // SAFETY: `record` passed every metadata and alignment check, and the
    // loader's release publication occurs only after it has mapped this TCB
    // and DTV. These are the contract's exact `%fs:0` and `%fs:8` words.
    let self_word = unsafe { core::ptr::read_volatile(record.thread_pointer.cast::<usize>()) };
    let dtv_word = unsafe { core::ptr::read_volatile(dtv_slot) };
    let dtv_count = unsafe { core::ptr::read_volatile(record.dtv) };
    self_word == thread_pointer
        && dtv_word == record.dtv as usize
        && dtv_count == record.module_count
        && record.dtv_words >= dtv_count.saturating_add(1)
}

/// Attach the freestanding libc-side consumer to one loader-owned initial TLS
/// RuntimeV1 record.
///
/// A zero result means only that this process has the exact private record and
/// its current `%fs` prefix matches it. Nonzero means absent, static-mode,
/// malformed, or mismatched runtime state. This return value never uses TLS
/// `errno`: the caller may invoke it precisely at the CRT boundary before a
/// general libc runtime exists.
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_loader_tls_runtime_v1_attach() -> c_int {
    let Some(record) = (unsafe { validate_loader_tls_runtime_v1() }) else {
        return -1;
    };
    if unsafe { observe_validated_loader_tls(record) } {
        0
    } else {
        -1
    }
}
