//! Selected static Linux/x86-64 C processor and physical-memory observation.
//!
//! This leaf owns exactly `get_nprocs_conf`, `get_nprocs`, `get_phys_pages`,
//! and `get_avphys_pages`. It shares the existing private Linux `sysinfo`
//! record seam and the fixed Linux/x86-64 base page-size fact, but does not
//! select `getloadavg`, `/proc` or system-file parsing, general `sysconf`,
//! CPU-affinity control, scheduler policy, NUMA/topology discovery, a system
//! information framework, libc.so, CRT, pthread/TLS lifecycle, dynamic TLS,
//! loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/conf/legacy.c` maps the four public legacy exports to `sysconf`.
//! - `src/conf/sysconf.c` owns the `JT_NPROCESSORS_*` and `JT_*PHYS_PAGES`
//!   cases: both processor queries use the same fixed 128-byte raw affinity
//!   mask, while page queries derive pages from `sysinfo` memory values.
//! - `src/linux/sysinfo.c` supplies the direct `sysinfo` adapter used by the
//!   page cases.
//!
//! Musl intentionally discards the raw affinity result after initializing CPU
//! zero in its 128-byte mask. The selected processor calls therefore preserve
//! stale `errno` and return one after an affinity error. The page cases mirror
//! musl's successful-call wrapping arithmetic. Musl reads an uninitialized C
//! `struct sysinfo` after a failed `sysinfo` call, which has no usable C
//! contract; this Rust leaf instead returns `-1` after publishing that raw
//! errno, without claiming page-count behavior for that failure path.

use core::ffi::{c_int, c_long, c_ulong};
use core::mem::MaybeUninit;

use super::{c_status, raw_syscall, system_configuration, system_observation};

const CPUSET_BYTES: usize = 128;

/// Count the bits in musl's fixed CPU-affinity mask.
///
/// Musl gives CPU zero a one-bit fallback before asking Linux to fill the
/// 128-byte representation, then deliberately ignores the raw result. This
/// preserves stale errno on both success and raw failure and retains the
/// defined one-CPU fallback when the kernel leaves the initialized mask alone.
#[inline(always)]
fn nprocs() -> c_int {
    let mut mask = [0u8; CPUSET_BYTES];
    mask[0] = 1;
    // SAFETY: Linux/x86-64 sched_getaffinity=204 takes current task zero,
    // the fixed musl 128-byte mask length, and the complete writable stack
    // mask in rdi/rsi/rdx. Its raw status is deliberately ignored to retain
    // musl's initialized CPU-zero fallback and errno preservation.
    let _ = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SCHED_GETAFFINITY,
            0,
            CPUSET_BYTES as i64,
            mask.as_mut_ptr() as usize as i64,
        )
    };

    let mut count = 0u32;
    let mut index = 0usize;
    while index < mask.len() {
        count += mask[index].count_ones();
        index += 1;
    }
    count as c_int
}

/// Return the selected physical or available page count after one `sysinfo`.
///
/// The page arithmetic intentionally follows musl's unsigned LP64 wrapping
/// order. A page count above the public signed `long` range saturates at
/// `LONG_MAX` rather than becoming negative.
#[inline(always)]
fn page_count(available: bool) -> c_long {
    let mut info = MaybeUninit::<system_observation::SysInfo>::zeroed();
    // SAFETY: the private all-zero Rust record is a valid complete x86 public
    // sysinfo object. Linux writes its ABI prefix; the zero initialization
    // keeps Rust defined if the raw call reports an error.
    let result = unsafe { system_observation::sysinfo_raw(info.as_mut_ptr()) };
    if c_status(result) != 0 {
        return -1;
    }
    // SAFETY: all-zero bytes are valid for this integer-and-byte-array record,
    // and successful Linux sysinfo has populated every field read below.
    let info = unsafe { info.assume_init() };
    let unit = if info.memory_unit == 0 {
        1 as c_ulong
    } else {
        c_ulong::from(info.memory_unit)
    };
    let amount = if available {
        info.free_ram.wrapping_add(info.buffer_ram)
    } else {
        info.total_ram
    };
    let bytes = amount.wrapping_mul(unit);
    let pages = bytes / system_configuration::X86_64_LINUX_PAGE_SIZE as c_ulong;
    if pages > c_long::MAX as c_ulong {
        c_long::MAX
    } else {
        pages as c_long
    }
}

/// Return the fixed-mask configured processor count.
///
/// The selected Linux/musl boundary intentionally does not distinguish this
/// from the online/allowed count and does not expose affinity control.
#[no_mangle]
pub extern "C" fn get_nprocs_conf() -> c_int {
    nprocs()
}

/// Return the fixed-mask online/allowed processor count.
///
/// This is deliberately the same bounded musl query as `get_nprocs_conf`.
#[no_mangle]
pub extern "C" fn get_nprocs() -> c_int {
    nprocs()
}

/// Return physical memory in fixed x86 base pages.
#[no_mangle]
pub extern "C" fn get_phys_pages() -> c_long {
    page_count(false)
}

/// Return free-plus-buffer memory in fixed x86 base pages.
#[no_mangle]
pub extern "C" fn get_avphys_pages() -> c_long {
    page_count(true)
}
