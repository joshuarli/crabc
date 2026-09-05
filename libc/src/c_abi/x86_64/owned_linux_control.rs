//! Owned Linux/x86-64 C mechanism boundaries, with kernel-owned authority.
//!
//! These wrappers translate musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT license in
//! `COPYRIGHT`. The source-to-entry mapping is:
//!
//! - `src/unistd/acct.c`: `acct`;
//! - `src/linux/cap.c`: `capget`, `capset`;
//! - `src/linux/module.c`: `init_module`, `delete_module`;
//! - `src/linux/fanotify.c`: `fanotify_init`, `fanotify_mark`;
//! - `src/linux/klogctl.c`, `pivot_root.c`, `quotactl.c`, `reboot.c`,
//!   `setns.c`, and `unshare.c`: their same-named C entries;
//! - `src/linux/swap.c`: `swapon`, `swapoff`;
//! - `src/linux/process_vm.c`: `process_vm_readv`, `process_vm_writev`;
//! - `src/linux/ptrace.c`: variadic `ptrace`, including the separate kernel
//!   output word for PEEK requests, which must not undergo errno translation.
//!
//! Linux 5.10 supplies every named syscall. The scalar wrappers retain musl's
//! argument widths and ordering, use the current task's errno owner, and add
//! no allocation, cancellation points, validation fallback, or policy state.
//! They are selected by the owned runtime only; the frozen private archive
//! and paused AArch64 implementation retain their separate contracts.

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

use super::{c_result, c_ssize_status, c_status, raw_syscall, vector_io::IoVec};

const SYS_PTRACE: i64 = 101;
const SYS_SYSLOG: i64 = 103;
const SYS_CAPGET: i64 = 125;
const SYS_CAPSET: i64 = 126;
const SYS_PIVOT_ROOT: i64 = 155;
const SYS_ACCT: i64 = 163;
const SYS_SWAPON: i64 = 167;
const SYS_SWAPOFF: i64 = 168;
const SYS_REBOOT: i64 = 169;
const SYS_INIT_MODULE: i64 = 175;
const SYS_DELETE_MODULE: i64 = 176;
const SYS_QUOTACTL: i64 = 179;
const SYS_UNSHARE: i64 = 272;
const SYS_FANOTIFY_INIT: i64 = 300;
const SYS_FANOTIFY_MARK: i64 = 301;
const SYS_SETNS: i64 = 308;
const SYS_PROCESS_VM_READV: i64 = 310;
const SYS_PROCESS_VM_WRITEV: i64 = 311;

/// Version and process ID in Linux's capability syscall ABI.
#[repr(C)]
pub struct CapabilityHeader {
    version: u32,
    pid: c_int,
}

/// One 32-bit effective/permitted/inheritable capability word group.
#[repr(C)]
pub struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const _: () = {
    assert!(core::mem::size_of::<CapabilityHeader>() == 8);
    assert!(core::mem::size_of::<CapabilityData>() == 12);
};

/// Select the kernel process-accounting file, or disable it with a null path.
///
/// # Safety
/// A non-null `path` must name a readable NUL-terminated string. The caller
/// must coordinate the requested system accounting change and file lifetime.
#[no_mangle]
pub unsafe extern "C" fn acct(path: *const c_char) -> c_int {
    c_status(unsafe { raw_syscall::syscall1(SYS_ACCT, path as i64) })
}

/// Read capability words using the caller-selected Linux record version.
///
/// # Safety
/// `header` must be writable. For a data query, `data` must hold the number
/// of writable records required by its version; null retains Linux's version
/// query behavior. The caller must synchronize access to both output buffers.
#[no_mangle]
pub unsafe extern "C" fn capget(header: *mut CapabilityHeader, data: *mut CapabilityData) -> c_int {
    c_status(unsafe { raw_syscall::syscall2(SYS_CAPGET, header as i64, data as i64) })
}

/// Apply the supplied capability sets through Linux's calling-task boundary.
///
/// # Safety
/// `header` and its version-selected data array must be valid for kernel
/// access. The caller must coordinate the resulting capability transition;
/// this entry does not perform a process-wide pthread rendezvous.
#[no_mangle]
pub unsafe extern "C" fn capset(header: *mut CapabilityHeader, data: *const CapabilityData) -> c_int {
    c_status(unsafe { raw_syscall::syscall2(SYS_CAPSET, header as i64, data as i64) })
}

/// Ask Linux to load the caller's module image.
///
/// # Safety
/// `image` must remain readable for `length` bytes and `arguments` must be a
/// readable NUL-terminated string. The caller must authorize and coordinate
/// execution of the module's kernel code and its system-wide effects.
#[no_mangle]
pub unsafe extern "C" fn init_module(image: *mut c_void, length: c_ulong, arguments: *const c_char) -> c_int {
    c_status(unsafe { raw_syscall::syscall3(SYS_INIT_MODULE, image as i64, length as i64, arguments as i64) })
}

/// Ask Linux to remove the named kernel module.
///
/// # Safety
/// `name` must remain a readable NUL-terminated string. The caller must
/// coordinate the requested removal and the lifetime of affected kernel users.
#[no_mangle]
pub unsafe extern "C" fn delete_module(name: *const c_char, flags: c_uint) -> c_int {
    c_status(unsafe { raw_syscall::syscall2(SYS_DELETE_MODULE, name as i64, flags as i64) })
}

/// Create a Linux fanotify group descriptor.
///
/// # Safety
/// The caller owns the returned descriptor and must service any requested
/// permission events so that monitored filesystem operations can progress.
#[no_mangle]
pub unsafe extern "C" fn fanotify_init(flags: c_uint, event_flags: c_uint) -> c_int {
    c_status(unsafe { raw_syscall::syscall2(SYS_FANOTIFY_INIT, flags as i64, event_flags as i64) })
}

/// Change the marks attached to a Linux fanotify group.
///
/// # Safety
/// The descriptors must remain live, and a required non-null `path` must be
/// readable and NUL-terminated. The caller owns group access, mark lifetime,
/// and servicing of any resulting permission events.
#[no_mangle]
pub unsafe extern "C" fn fanotify_mark(descriptor: c_int, flags: c_uint, mask: u64, directory: c_int, path: *const c_char) -> c_int {
    c_status(unsafe { raw_syscall::syscall5(SYS_FANOTIFY_MARK, descriptor as i64, flags as i64, mask as i64, directory as i64, path as i64) })
}

/// Read or control the kernel log according to Linux's action number.
///
/// # Safety
/// For read actions, `buffer` must be writable for `length` bytes. The caller
/// must coordinate actions that consume log data or change kernel log policy.
#[no_mangle]
pub unsafe extern "C" fn klogctl(action: c_int, buffer: *mut c_char, length: c_int) -> c_int {
    c_status(unsafe { raw_syscall::syscall3(SYS_SYSLOG, action as i64, buffer as i64, length as i64) })
}

/// Exchange the mount namespace's root through Linux `pivot_root`.
///
/// # Safety
/// Both paths must remain readable NUL-terminated strings. The caller must
/// coordinate the namespace's root transition and all affected path users.
#[no_mangle]
pub unsafe extern "C" fn pivot_root(new_root: *const c_char, old_root: *const c_char) -> c_int {
    c_status(unsafe { raw_syscall::syscall2(SYS_PIVOT_ROOT, new_root as i64, old_root as i64) })
}

/// Issue the command-selected Linux quota operation.
///
/// # Safety
/// A required `special` path must be readable and NUL-terminated. `address`
/// must provide the command's correctly sized and aligned input/output
/// record. The caller must synchronize quota changes and record access.
#[no_mangle]
pub unsafe extern "C" fn quotactl(command: c_int, special: *const c_char, id: c_int, address: *mut c_char) -> c_int {
    c_status(unsafe { raw_syscall::syscall4(SYS_QUOTACTL, command as i64, special as i64, id as i64, address as i64) })
}

/// Issue the musl-shaped Linux reboot command with its two magic words.
///
/// # Safety
/// The caller must authorize and coordinate the requested restart, shutdown,
/// or other command effect with every affected process and device.
#[no_mangle]
pub unsafe extern "C" fn reboot(command: c_int) -> c_int {
    c_status(unsafe { raw_syscall::syscall3(SYS_REBOOT, 0xfee1dead, 672274793, command as i64) })
}

/// Join the namespace named by the caller's descriptor.
///
/// # Safety
/// The descriptor must remain live. The caller must coordinate the requested
/// calling-task namespace transition with code using affected ambient state.
#[no_mangle]
pub unsafe extern "C" fn setns(descriptor: c_int, kind: c_int) -> c_int {
    c_status(unsafe { raw_syscall::syscall2(SYS_SETNS, descriptor as i64, kind as i64) })
}

/// Enable the named Linux swap object.
///
/// # Safety
/// `path` must remain readable and NUL-terminated. The caller must coordinate
/// the storage object's exclusive swap use and system memory effects.
#[no_mangle]
pub unsafe extern "C" fn swapon(path: *const c_char, flags: c_int) -> c_int {
    c_status(unsafe { raw_syscall::syscall2(SYS_SWAPON, path as i64, flags as i64) })
}

/// Disable the named Linux swap object.
///
/// # Safety
/// `path` must remain readable and NUL-terminated. The caller must coordinate
/// storage lifetime and the resulting system memory transition.
#[no_mangle]
pub unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    c_status(unsafe { raw_syscall::syscall1(SYS_SWAPOFF, path as i64) })
}

/// Separate the caller's Linux resources selected by `flags`.
///
/// # Safety
/// The caller must coordinate the requested calling-task resource/namespace
/// changes with all runtime and application users of that ambient state.
#[no_mangle]
pub unsafe extern "C" fn unshare(flags: c_int) -> c_int {
    c_status(unsafe { raw_syscall::syscall1(SYS_UNSHARE, flags as i64) })
}

/// Read process memory through Linux's two vector lists.
///
/// # Safety
/// Both vector arrays must remain readable for their stated counts. Local
/// destination buffers must be writable and synchronized; the caller owns
/// target identity, remote address lifetime, and partial-transfer handling.
#[no_mangle]
pub unsafe extern "C" fn process_vm_readv(pid: c_int, local: *const IoVec, local_count: c_ulong, remote: *const IoVec, remote_count: c_ulong, flags: c_ulong) -> isize {
    c_ssize_status(unsafe { raw_syscall::syscall6(SYS_PROCESS_VM_READV, pid as i64, local as i64, local_count as i64, remote as i64, remote_count as i64, flags as i64) })
}

/// Write process memory through Linux's two vector lists.
///
/// # Safety
/// Both vector arrays and local source buffers must remain readable for their
/// stated bounds. The caller owns target identity, synchronization of remote
/// writes, remote address lifetime, and partial-transfer handling.
#[no_mangle]
pub unsafe extern "C" fn process_vm_writev(pid: c_int, local: *const IoVec, local_count: c_ulong, remote: *const IoVec, remote_count: c_ulong, flags: c_ulong) -> isize {
    c_ssize_status(unsafe { raw_syscall::syscall6(SYS_PROCESS_VM_WRITEV, pid as i64, local as i64, local_count as i64, remote as i64, remote_count as i64, flags as i64) })
}

/// Execute Linux's request-specific tracing operation.
///
/// # Safety
/// The variadic arguments must be `pid_t`, `void *address`, and `void *data`
/// in that order. Request-selected buffers must satisfy Linux's sizes,
/// alignment and access rules. The caller owns tracee identity, stop/resume
/// sequencing, and synchronization of any memory/register changes.
#[no_mangle]
pub unsafe extern "C" fn ptrace(request: c_int, mut arguments: ...) -> c_long {
    let pid = unsafe { arguments.next_arg::<c_int>() };
    let address = unsafe { arguments.next_arg::<*mut c_void>() };
    let mut data = unsafe { arguments.next_arg::<*mut c_void>() };
    let peek = (request as u32).wrapping_sub(1) < 3;
    let mut word = 0_i64;
    if peek {
        data = core::ptr::addr_of_mut!(word).cast();
    }
    let result = c_result(unsafe { raw_syscall::syscall5(SYS_PTRACE, request as i64, pid as i64, address as i64, data as i64, 0) });
    if result < 0 || !peek { result as c_long } else { word as c_long }
}
