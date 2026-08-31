//! Selected static Linux/x86-64 C `ttyname_r` terminal-name observation.
//!
//! This is an exact, bounded mapping of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license:
//! `src/unistd/ttyname_r.c::ttyname_r` first calls the separately selected
//! `isatty`, forms `"/proc/self/fd/<fd>"` through
//! `src/internal/procfdname.c::__procfdname`, reads that link through
//! `src/unistd/readlink.c::readlink`, then confirms that the named target and
//! descriptor have equal device/inode pairs. Linux/x86-64 `readlink=89`,
//! `newfstatat=262`, and `fstat=5` supply those direct private operations.
//! The zero-capacity `readlink` dummy-byte path intentionally retains musl's
//! result-zero conversion before `ttyname_r` returns `ERANGE`.
//!
//! This leaf names an already-owned terminal only into caller-owned storage.
//! It neither exports `ttyname`'s static buffer, opens a pathname, creates a
//! PTY or session, changes terminal state, exposes generic `readlink`/`stat`/
//! `fstat`, or establishes a filesystem/path policy. Terminal control,
//! discovery beyond this descriptor-to-name check, session policy, PTY helpers,
//! generic ioctl, dynamic runtime, CRT, loader, sysroot, family completion,
//! promotion, and public x86 support remain outside this selected-private
//! artifact.

use core::ffi::{c_char, c_int};
use core::mem::{align_of, size_of, MaybeUninit};

use super::{c_status, errno, isatty, raw_syscall};

const ERANGE: c_int = 34;
const ENODEV: c_int = 19;
const AT_FDCWD: c_int = -100;

const PROC_FD_PREFIX: &[u8] = b"/proc/self/fd/";
const PROC_FD_NAME_CAPACITY: usize =
    PROC_FD_PREFIX.len() + 1 + 3 * size_of::<c_int>() + 2;
const KERNEL_STAT_SIZE: usize = 144;
const KERNEL_STAT_DEVICE_OFFSET: usize = 0;
const KERNEL_STAT_INODE_OFFSET: usize = 8;

/// Private complete Linux/x86-64 `struct stat` output storage.
///
/// `ttyname_r` consumes only `st_dev` and `st_ino`, but Linux must receive its
/// complete 144-byte output record. Keeping bytes rather than a public Rust
/// stat representation prevents this terminal leaf from becoming another
/// owner of the C `struct stat` ABI or a generic metadata API.
#[repr(C, align(8))]
struct KernelStat {
    bytes: [u8; KERNEL_STAT_SIZE],
}

const _: [(); 14] = [(); PROC_FD_PREFIX.len()];
const _: [(); 29] = [(); PROC_FD_NAME_CAPACITY];
const _: [(); 144] = [(); size_of::<KernelStat>()];
const _: [(); 8] = [(); align_of::<KernelStat>()];
const _: [(); 0] = [(); KERNEL_STAT_DEVICE_OFFSET];
const _: [(); 8] = [(); KERNEL_STAT_INODE_OFFSET];

/// Form musl's fixed `/proc/self/fd/<fd>` pathname for a verified descriptor.
///
/// `isatty` has already accepted `fd`, so its integer value is nonnegative and
/// the unsigned conversion matches `__procfdname`'s unsigned input.
#[inline]
fn procfdname(path: &mut [u8; PROC_FD_NAME_CAPACITY], fd: c_int) {
    let mut index = 0usize;
    while index < PROC_FD_PREFIX.len() {
        path[index] = PROC_FD_PREFIX[index];
        index += 1;
    }

    let mut value = fd as u32;
    if value == 0 {
        path[index] = b'0';
        path[index + 1] = 0;
        return;
    }

    let mut digit_end = index;
    let mut remaining = value;
    while remaining != 0 {
        remaining /= 10;
        digit_end += 1;
    }
    path[digit_end] = 0;
    while value != 0 {
        digit_end -= 1;
        path[digit_end] = b'0' + (value % 10) as u8;
        value /= 10;
    }
}

/// Convert one raw Linux failure to musl's current `errno` result.
///
/// The helper calls the shared initial-TLS translator only for the Linux
/// `-4095..=-1` error range, leaving every successful nonnegative result
/// untouched for callers that need its byte count.
#[inline]
fn syscall_errno(result: i64) -> Option<c_int> {
    if result < 0 && result >= -4_095 {
        let _ = c_status(result);
        // SAFETY: c_status just published this checked Linux errno in the
        // selected calling thread's initial-TLS slot.
        Some(unsafe { errno::get_errno() })
    } else {
        None
    }
}

/// Read one procfd link with musl's zero-capacity compatibility behavior.
///
/// # Safety
///
/// `path` must point to a valid NUL-terminated procfd pathname. If `capacity`
/// is nonzero, `name` must designate writable storage for exactly that many
/// bytes. A zero capacity accepts any `name` value because musl uses private
/// one-byte scratch storage instead.
#[inline]
unsafe fn readlink_name(
    path: *const c_char,
    name: *mut c_char,
    capacity: usize,
) -> Result<usize, c_int> {
    let mut dummy = 0u8;
    let (kernel_name, kernel_capacity) = if capacity == 0 {
        (&mut dummy as *mut u8 as *mut c_char, 1usize)
    } else {
        (name, capacity)
    };
    // SAFETY: the caller owns the procfd pathname and nonzero caller-buffer
    // contract; the zero-capacity branch owns the private one-byte scratch.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_READLINK,
            path as usize as i64,
            kernel_name as usize as i64,
            kernel_capacity as i64,
        )
    };
    if let Some(error) = syscall_errno(result) {
        return Err(error);
    }

    let mut length = result as usize;
    if capacity == 0 && length > 0 {
        length = 0;
    }
    Ok(length)
}

/// Read the device/inode identity of one pathname through `newfstatat`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall.
#[inline]
unsafe fn pathname_identity(path: *const c_char) -> Result<(u64, u64), c_int> {
    let mut metadata = MaybeUninit::<KernelStat>::uninit();
    // SAFETY: `metadata` is one complete private Linux/x86 stat output record;
    // the caller supplies the pathname pointer contract.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_NEWFSTATAT,
            i64::from(AT_FDCWD),
            path as usize as i64,
            metadata.as_mut_ptr() as usize as i64,
            0,
        )
    };
    if let Some(error) = syscall_errno(result) {
        return Err(error);
    }

    // SAFETY: a successful Linux newfstatat initialized the complete private
    // output record. Both offsets are fixed x86 `struct stat` u64 fields.
    unsafe { stat_identity(metadata.as_ptr()) }
}

/// Read the device/inode identity of one descriptor through `fstat`.
///
/// # Safety
///
/// `fd` is passed directly to Linux and must remain the descriptor observed by
/// the caller while a meaningful name result is required.
#[inline]
unsafe fn descriptor_identity(fd: c_int) -> Result<(u64, u64), c_int> {
    let mut metadata = MaybeUninit::<KernelStat>::uninit();
    // SAFETY: `metadata` is one complete private Linux/x86 stat output record;
    // Linux validates the scalar descriptor.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FSTAT,
            i64::from(fd),
            metadata.as_mut_ptr() as usize as i64,
        )
    };
    if let Some(error) = syscall_errno(result) {
        return Err(error);
    }

    // SAFETY: a successful Linux fstat initialized the complete private output
    // record. Both offsets are fixed x86 `struct stat` u64 fields.
    unsafe { stat_identity(metadata.as_ptr()) }
}

/// Extract only the two private identity words written by Linux.
///
/// # Safety
///
/// `metadata` must point to a successful complete `KernelStat` output.
#[inline]
unsafe fn stat_identity(metadata: *const KernelStat) -> Result<(u64, u64), c_int> {
    // SAFETY: caller proves the complete kernel output is initialized and both
    // byte offsets remain within its 144-byte private record.
    let bytes = metadata.cast::<u8>();
    let device = unsafe {
        core::ptr::read_unaligned(bytes.add(KERNEL_STAT_DEVICE_OFFSET).cast::<u64>())
    };
    // SAFETY: same complete-record proof as the preceding device read.
    let inode = unsafe {
        core::ptr::read_unaligned(bytes.add(KERNEL_STAT_INODE_OFFSET).cast::<u64>())
    };
    Ok((device, inode))
}

/// Name an already-owned terminal into caller-owned storage.
///
/// # Safety
///
/// `fd` must remain stable while the caller needs a meaningful result. For a
/// nonzero `capacity`, `name` must designate writable storage for `capacity`
/// bytes. The caller retains filesystem namespace and descriptor-lifetime
/// authority; this function only reproduces musl's transient descriptor/name
/// identity observation and returns error numbers directly.
#[no_mangle]
pub unsafe extern "C" fn ttyname_r(fd: c_int, name: *mut c_char, capacity: usize) -> c_int {
    // SAFETY: the descriptor is the caller's scalar C ABI argument; isatty is
    // the exact separately selected musl-shaped prerequisite observation.
    if unsafe { isatty::isatty(fd) } == 0 {
        // SAFETY: isatty's failure just published its raw Linux error here.
        return unsafe { errno::get_errno() };
    }

    let mut procname = [0u8; PROC_FD_NAME_CAPACITY];
    procfdname(&mut procname, fd);
    // SAFETY: procname is a private NUL-terminated fixed path. The caller owns
    // the nonzero name-buffer contract; zero capacity gets private scratch.
    let length = match unsafe {
        readlink_name(procname.as_ptr().cast::<c_char>(), name, capacity)
    } {
        Ok(length) => length,
        Err(error) => return error,
    };
    if length == capacity {
        return ERANGE;
    }

    // SAFETY: a successful readlink produced `length < capacity`; therefore
    // this NUL write remains in the caller's declared writable storage.
    unsafe { core::ptr::write(name.add(length), 0) };

    // SAFETY: the successful readlink plus the NUL write established the
    // pathname contract for the same caller-owned buffer.
    let named = match unsafe { pathname_identity(name.cast_const()) } {
        Ok(identity) => identity,
        Err(error) => return error,
    };
    // SAFETY: the caller still owns the descriptor's lifetime for this second
    // identity observation, exactly as musl does after resolving the path.
    let opened = match unsafe { descriptor_identity(fd) } {
        Ok(identity) => identity,
        Err(error) => return error,
    };
    if named != opened {
        return ENODEV;
    }

    0
}
