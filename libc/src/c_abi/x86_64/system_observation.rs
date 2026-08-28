//! Selected static Linux/x86-64 C system-observation boundary.
//!
//! This leaf owns one coherent, bounded native C snapshot block: `uname` and
//! `sysinfo`. It composes only the raw Linux syscall register boundary and the
//! selected initial-TLS C `errno` slot. It is not hostname/domain mutation or
//! lookup, `/proc` or system-file parsing, processor/page-count discovery,
//! `sysconf`, a system-information framework, a general C/POSIX runtime,
//! libc.so, CRT, pthread/TLS lifecycle, dynamic TLS, loader, sysroot,
//! allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/misc/uname.c` maps directly to [`uname`].
//! - `src/linux/sysinfo.c` maps directly to [`sysinfo`]. Musl's private
//!   `__lsysinfo` weak-alias arrangement is link-composition machinery, not a
//!   second public entry point for this closed static archive.
//!
//! Linux 5.10 directly supplies both selected calls. `uname` fills its full
//! 390-byte public record. The kernel `sysinfo` ABI is 112 bytes, so it writes
//! the public record through offset 111: this includes four trailing kernel
//! padding bytes at the beginning of musl's public `__reserved` field. Bytes
//! 112 through 367 remain caller-resident, exactly as the direct musl wrapper
//! leaves them. No fallback, normalization, or private record copy is
//! selected.

use core::ffi::{c_char, c_int, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

const KERNEL_SYSINFO_BYTES: usize = 112;
pub(super) const UTS_FIELD_BYTES: usize = 65;

/// Exact x86 public `struct utsname` storage.
///
/// It is private Rust ABI machinery only. The C entry point's pointer type
/// keeps this record from establishing a Rust host-information API.
#[repr(C)]
pub(super) struct UtsName {
    pub(super) system_name: [c_char; UTS_FIELD_BYTES],
    pub(super) node_name: [c_char; UTS_FIELD_BYTES],
    pub(super) release: [c_char; UTS_FIELD_BYTES],
    pub(super) version: [c_char; UTS_FIELD_BYTES],
    pub(super) machine: [c_char; UTS_FIELD_BYTES],
    pub(super) domain_name: [c_char; UTS_FIELD_BYTES],
}

/// Exact x86 public `struct sysinfo` storage.
///
/// Linux's 112-byte kernel record reaches four bytes into
/// `compatibility_tail` for its trailing ABI padding. The remaining 252 bytes
/// are public compatibility storage that Linux and musl leave untouched.
#[repr(C)]
pub(super) struct SysInfo {
    uptime: c_ulong,
    loads: [c_ulong; 3],
    total_ram: c_ulong,
    free_ram: c_ulong,
    shared_ram: c_ulong,
    buffer_ram: c_ulong,
    total_swap: c_ulong,
    free_swap: c_ulong,
    process_count: u16,
    padding: u16,
    total_high_ram: c_ulong,
    free_high_ram: c_ulong,
    memory_unit: c_uint,
    compatibility_tail: [u8; 256],
}

const _: () = {
    assert!(size_of::<UtsName>() == 390);
    assert!(align_of::<UtsName>() == 1);
    assert!(offset_of!(UtsName, system_name) == 0);
    assert!(offset_of!(UtsName, node_name) == UTS_FIELD_BYTES);
    assert!(offset_of!(UtsName, release) == UTS_FIELD_BYTES * 2);
    assert!(offset_of!(UtsName, version) == UTS_FIELD_BYTES * 3);
    assert!(offset_of!(UtsName, machine) == UTS_FIELD_BYTES * 4);
    assert!(offset_of!(UtsName, domain_name) == UTS_FIELD_BYTES * 5);

    assert!(size_of::<SysInfo>() == 368);
    assert!(align_of::<SysInfo>() == 8);
    assert!(offset_of!(SysInfo, uptime) == 0);
    assert!(offset_of!(SysInfo, loads) == 8);
    assert!(offset_of!(SysInfo, total_ram) == 32);
    assert!(offset_of!(SysInfo, free_ram) == 40);
    assert!(offset_of!(SysInfo, shared_ram) == 48);
    assert!(offset_of!(SysInfo, buffer_ram) == 56);
    assert!(offset_of!(SysInfo, total_swap) == 64);
    assert!(offset_of!(SysInfo, free_swap) == 72);
    assert!(offset_of!(SysInfo, process_count) == 80);
    assert!(offset_of!(SysInfo, padding) == 82);
    assert!(offset_of!(SysInfo, total_high_ram) == 88);
    assert!(offset_of!(SysInfo, free_high_ram) == 96);
    assert!(offset_of!(SysInfo, memory_unit) == 104);
    assert!(offset_of!(SysInfo, compatibility_tail) == 108);
    assert!(KERNEL_SYSINFO_BYTES == offset_of!(SysInfo, compatibility_tail) + 4);
};

/// Invoke Linux `uname` for a sibling selected static C leaf.
///
/// # Safety
///
/// `output` must designate writable storage for one complete public x86
/// `struct utsname` for the raw syscall's duration.
#[inline]
pub(super) unsafe fn uname_raw(output: *mut UtsName) -> i64 {
    // SAFETY: the caller owns the complete writable public record contract.
    unsafe { raw_syscall::syscall1(raw_syscall::SYS_UNAME, output as usize as i64) }
}

/// Fill one public x86 `struct utsname` through Linux `uname(2)`.
///
/// # Safety
///
/// `output` must designate writable storage for one complete 390-byte public
/// x86 `struct utsname` for the syscall's duration. The caller owns the
/// output record and any concurrent UTS-namespace transition policy.
#[no_mangle]
pub unsafe extern "C" fn uname(output: *mut UtsName) -> c_int {
    // SAFETY: the caller owns the complete writable public record contract.
    let result = unsafe { uname_raw(output) };
    c_status(result)
}

/// Fill one public x86 `struct sysinfo` through Linux `sysinfo(2)`.
///
/// Linux writes its exact 112-byte ABI prefix, including four padding bytes
/// in the public `__reserved` field. It leaves the remaining 252 caller bytes
/// untouched; this wrapper deliberately neither clears nor copies them.
///
/// # Safety
///
/// `output` must designate writable storage for one complete 368-byte public
/// x86 `struct sysinfo` for the syscall's duration. The caller owns the output
/// record and any concurrent system-state observation policy.
#[no_mangle]
pub unsafe extern "C" fn sysinfo(output: *mut SysInfo) -> c_int {
    // SAFETY: the caller owns the complete writable public record contract;
    // Linux reads only the pointer word in x86 rdi and fills its ABI prefix.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_SYSINFO, output as usize as i64)
    };
    c_status(result)
}
