//! Bounded Linux/x86-64 system-information operations.
//!
//! This module owns only the fixed kernel `new_utsname` and `sysinfo` output
//! records used by the staged Rust facade. It does not establish C header or
//! `crabc-libc` support.

use core::mem::MaybeUninit;

use crate::syscall::{decode, syscall1, SYS_SYSINFO, SYS_UNAME};
use crate::Result;

/// Linux/x86-64 `new_utsname`, including the Linux domain-name field.
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

const _: () = assert!(core::mem::size_of::<UtsName>() == 390);
const _: () = assert!(core::mem::align_of::<UtsName>() == 1);

/// Linux/x86-64 `sysinfo` without libc's compatibility-only tail.
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
    pub reserved: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<Sysinfo>() == 112);
const _: () = assert!(core::mem::align_of::<Sysinfo>() == 8);
const _: () = assert!(core::mem::offset_of!(Sysinfo, uptime) == 0);
const _: () = assert!(core::mem::offset_of!(Sysinfo, loads) == 8);
const _: () = assert!(core::mem::offset_of!(Sysinfo, totalram) == 32);
const _: () = assert!(core::mem::offset_of!(Sysinfo, procs) == 80);
const _: () = assert!(core::mem::offset_of!(Sysinfo, totalhigh) == 88);
const _: () = assert!(core::mem::offset_of!(Sysinfo, mem_unit) == 104);

/// Reads Linux kernel and hardware naming information.
#[inline]
pub fn uname() -> Result<UtsName> {
    let mut value = MaybeUninit::<UtsName>::uninit();
    // SAFETY: `value` is writable storage for exactly one Linux/x86-64
    // `new_utsname` record, which Linux initializes on success.
    decode(unsafe { syscall1(SYS_UNAME, value.as_mut_ptr() as usize) })?;
    // SAFETY: Successful `uname` initialized all six fixed arrays.
    Ok(unsafe { value.assume_init() })
}

/// Reads Linux kernel and hardware naming information into x86-64 C-ABI
/// storage.
///
/// # Safety
///
/// `value` must designate writable Linux/x86-64 `new_utsname` storage, or may
/// deliberately be an invalid C ABI pointer for kernel validation.
#[inline]
pub unsafe fn uname_raw(value: *mut UtsName) -> Result<()> {
    // SAFETY: The caller supplies the output-pointer contract.
    decode(unsafe { syscall1(SYS_UNAME, value as usize) }).map(|_| ())
}

/// Reads Linux memory, load, and uptime information.
#[inline]
pub fn sysinfo() -> Result<Sysinfo> {
    let mut value = MaybeUninit::<Sysinfo>::uninit();
    // SAFETY: `value` is writable storage for exactly one Linux/x86-64
    // `sysinfo` record, which Linux initializes on success.
    decode(unsafe { syscall1(SYS_SYSINFO, value.as_mut_ptr() as usize) })?;
    // SAFETY: Successful `sysinfo` initialized the complete kernel record.
    Ok(unsafe { value.assume_init() })
}

/// Reads Linux system information into x86-64 kernel-prefix storage.
///
/// # Safety
///
/// `value` must designate writable Linux/x86-64 112-byte kernel `sysinfo`
/// storage, or may deliberately be an invalid C ABI pointer for kernel
/// validation. This is not musl's larger public C `struct sysinfo`, whose
/// compatibility tail Linux does not initialize.
#[inline]
pub unsafe fn sysinfo_raw(value: *mut Sysinfo) -> Result<()> {
    // SAFETY: The caller supplies the output-pointer contract.
    decode(unsafe { syscall1(SYS_SYSINFO, value as usize) }).map(|_| ())
}
