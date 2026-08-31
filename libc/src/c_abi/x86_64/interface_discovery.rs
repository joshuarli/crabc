//! Isolated Linux/x86-64 C interface-discovery boundary.
//!
//! `if_nametoindex`, `if_indextoname`, `if_nameindex`, `if_freenameindex`,
//! `getifaddrs`, and `freeifaddrs` deliberately live outside
//! the x86 numeric-netdb boundary. A freestanding interface-only final link
//! retains only its ioctl/rtnetlink and private result-storage seams, never
//! resolver configuration, DNS packet processing, or conventional network
//! databases.
//! The shared implementation remains in `network_interface_exports.rs`; this
//! module supplies only the x86 raw-syscall, initial-TLS errno, and private
//! mapping allocation context required by that implementation.

#![allow(dead_code)]

use core::ffi::{c_char, c_int, c_uint, c_void};

use super::errno;
use super::raw_syscall;
use super::socket_transport::socket;

#[inline]
fn cabi_interface_set_errno(value: c_int) {
    unsafe { errno::set_errno(value) };
}

#[inline]
fn cabi_interface_errno() -> c_int {
    unsafe { errno::get_errno() }
}

const EFAULT_VAL: c_int = 14;
const EINVAL_VAL: c_int = 22;
const EIO_VAL: c_int = 5;
const ENOBUFS_VAL: c_int = 105;
const ENODEV_VAL: c_int = 19;
const ENOMEM_VAL: c_int = 12;
const ENXIO_VAL: c_int = 6;

const AF_UNIX: c_int = 1;
const SOCK_DGRAM: c_int = 2;

const SYS_CLOSE: i64 = 3;
const SYS_MMAP: i64 = 9;
const SYS_MUNMAP: i64 = 11;
const SYS_IOCTL: i64 = 16;
const SYS_SENDTO: i64 = 44;
const SYS_RECVFROM: i64 = 45;

const PROT_READ_WRITE: i64 = 0x3;
const MAP_PRIVATE_ANONYMOUS: i64 = 0x22;
const MAP_FAILED: i64 = -1;
const PAGE_SIZE: usize = 4096;
const ALLOCATION_MAGIC: usize = 0x4352_4142_4946_4143;

#[repr(C)]
pub(crate) struct sockaddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

// These allocations are private result storage for the interface records.
// They are intentionally module-local rather than a C allocation API, so an
// interface-only link owns its output buffers without acquiring an unrelated
// result-storage object.
#[repr(C, align(16))]
struct InterfaceAllocationHeader {
    mapping_length: usize,
    requested_length: usize,
    magic: usize,
    _reserved: usize,
}

#[inline]
unsafe fn malloc(size: usize) -> *mut c_void {
    let requested = size.max(1);
    let total = match requested.checked_add(core::mem::size_of::<InterfaceAllocationHeader>()) {
        Some(value) => value,
        None => {
            errno::set_errno(ENOMEM_VAL);
            return core::ptr::null_mut();
        }
    };
    let mapping_length = match total.checked_add(PAGE_SIZE - 1) {
        Some(value) => value & !(PAGE_SIZE - 1),
        None => {
            errno::set_errno(ENOMEM_VAL);
            return core::ptr::null_mut();
        }
    };
    let mapping = raw_syscall::syscall6(
        SYS_MMAP,
        0,
        mapping_length as i64,
        PROT_READ_WRITE,
        MAP_PRIVATE_ANONYMOUS,
        -1,
        0,
    );
    if mapping < 0 && mapping >= -4095 {
        errno::set_errno((-mapping) as c_int);
        return core::ptr::null_mut();
    }
    if mapping == MAP_FAILED {
        errno::set_errno(ENOMEM_VAL);
        return core::ptr::null_mut();
    }
    let header = mapping as *mut InterfaceAllocationHeader;
    header.write(InterfaceAllocationHeader {
        mapping_length,
        requested_length: requested,
        magic: ALLOCATION_MAGIC,
        _reserved: 0,
    });
    header.add(1).cast()
}

#[inline]
unsafe fn calloc(count: usize, size: usize) -> *mut c_void {
    let length = match count.checked_mul(size) {
        Some(value) => value,
        None => {
            errno::set_errno(ENOMEM_VAL);
            return core::ptr::null_mut();
        }
    };
    let allocation = malloc(length);
    if !allocation.is_null() {
        core::ptr::write_bytes(allocation.cast::<u8>(), 0, length);
    }
    allocation
}

#[inline]
unsafe fn free(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    let header = pointer.cast::<InterfaceAllocationHeader>().sub(1);
    if (*header).magic != ALLOCATION_MAGIC {
        return;
    }
    let length = (*header).mapping_length;
    (*header).magic = 0;
    let _ = raw_syscall::syscall2(SYS_MUNMAP, header as i64, length as i64);
}

#[inline]
unsafe fn realloc(pointer: *mut c_void, size: usize) -> *mut c_void {
    if pointer.is_null() {
        return malloc(size);
    }
    if size == 0 {
        free(pointer);
        return core::ptr::null_mut();
    }
    let header = pointer.cast::<InterfaceAllocationHeader>().sub(1);
    if (*header).magic != ALLOCATION_MAGIC {
        errno::set_errno(EINVAL_VAL);
        return core::ptr::null_mut();
    }
    if size <= (*header).requested_length {
        (*header).requested_length = size;
        return pointer;
    }
    let replacement = malloc(size);
    if replacement.is_null() {
        return replacement;
    }
    core::ptr::copy_nonoverlapping(
        pointer.cast::<u8>(),
        replacement.cast::<u8>(),
        (*header).requested_length,
    );
    free(pointer);
    replacement
}

#[inline]
unsafe fn sys_close(fd: i64) -> i64 {
    raw_syscall::syscall1(SYS_CLOSE, fd)
}

#[inline]
unsafe fn sys_ioctl(fd: c_int, request: u32, argument: *mut u8) -> i64 {
    raw_syscall::syscall3(SYS_IOCTL, fd as i64, request as i64, argument as i64)
}

#[inline]
unsafe fn sys_sendto(
    fd: c_int,
    buffer: *const c_void,
    length: usize,
    flags: c_int,
    address: *const sockaddr,
    address_length: c_uint,
) -> i64 {
    raw_syscall::syscall6(
        SYS_SENDTO,
        fd as i64,
        buffer as i64,
        length as i64,
        flags as i64,
        address as i64,
        address_length as i64,
    )
}

#[inline]
unsafe fn sys_recvfrom(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    flags: c_int,
    address: *mut sockaddr,
    address_length: *mut c_uint,
) -> i64 {
    raw_syscall::syscall6(
        SYS_RECVFROM,
        fd as i64,
        buffer as i64,
        length as i64,
        flags as i64,
        address as i64,
        address_length as i64,
    )
}

include!("../../network_interface_exports.rs");
