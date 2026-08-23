//! Stateless Linux/AArch64 system-information operations.

use crate::Result;
use crate::syscall::{decode, syscall1, SYS_SYSINFO, SYS_UNAME};
use core::mem::MaybeUninit;

/// Linux/AArch64 `new_utsname`, including the Linux domain-name field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UtsName {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

/// Linux/AArch64 `sysinfo` without libc's compatibility-only tail.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sysinfo {
    pub uptime: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
    // Linux's `struct sysinfo` retains this ABI tail so the 64-bit
    // representation stays 112 bytes after the alignment before
    // `totalhigh`.
    pub reserved: [u8; 4],
}

/// Reads Linux kernel and hardware naming information.
#[inline]
pub fn uname() -> Result<UtsName> {
    let mut value = MaybeUninit::<UtsName>::uninit();
    // SAFETY: `value` provides exactly one writable Linux/AArch64
    // `new_utsname`; a successful syscall initializes all fields.
    decode(unsafe { syscall1(SYS_UNAME, value.as_mut_ptr() as usize) })?;
    Ok(unsafe { value.assume_init() })
}

/// Reads Linux kernel and hardware naming information into C-ABI storage.
///
/// # Safety
///
/// `value` must designate writable Linux/AArch64 `new_utsname` storage,
/// or may deliberately be an invalid C ABI pointer for kernel validation.
#[inline]
pub unsafe fn uname_raw(value: *mut UtsName) -> Result<()> {
    // SAFETY: The caller supplies the output-pointer contract.
    decode(unsafe { syscall1(SYS_UNAME, value as usize) }).map(|_| ())
}

/// Reads Linux memory, load, and uptime information.
#[inline]
pub fn sysinfo() -> Result<Sysinfo> {
    let mut value = MaybeUninit::<Sysinfo>::uninit();
    // SAFETY: `value` is the exact Linux/AArch64 `sysinfo` ABI.
    decode(unsafe { syscall1(SYS_SYSINFO, value.as_mut_ptr() as usize) })?;
    Ok(unsafe { value.assume_init() })
}

/// Reads Linux system information into C-ABI storage.
///
/// # Safety
///
/// `value` must designate writable Linux/AArch64 `sysinfo` storage, or
/// may deliberately be an invalid C ABI pointer for kernel validation.
#[inline]
pub unsafe fn sysinfo_raw(value: *mut Sysinfo) -> Result<()> {
    // SAFETY: The caller supplies the output-pointer contract.
    decode(unsafe { syscall1(SYS_SYSINFO, value as usize) }).map(|_| ())
}
