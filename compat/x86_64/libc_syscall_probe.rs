//! Native behavior probe for the unintegrated x86-64 libc syscall boundary.
//!
//! This binary intentionally imports only `libc/src/c_abi/x86_64/syscall.rs`.
//! It does not link or select `crabc-libc`: the probe keeps the raw register
//! ABI evidence separate until the surrounding C layouts and runtime state
//! have their own x86-64 implementation slices.

#[allow(dead_code)]
#[path = "../../libc/src/c_abi/x86_64/syscall.rs"]
mod syscall;

use core::ffi::CStr;

const AT_FDCWD: i64 = -100;
const O_RDWR: i64 = 0x0002;
const O_CREAT: i64 = 0x0040;
const O_EXCL: i64 = 0x0080;
const AF_INET: i64 = 2;
const SOCK_STREAM: i64 = 1;
const SOL_SOCKET: i64 = 1;
const SO_REUSEADDR: i64 = 2;
const PROT_READ_WRITE: i64 = 0x3;
const MAP_PRIVATE_ANONYMOUS: i64 = 0x22;
const MODE_OFFSET: usize = 24;

struct RestoreUmask(i64);

impl Drop for RestoreUmask {
    fn drop(&mut self) {
        // SAFETY: `SYS_UMASK` has exactly one scalar argument and this value
        // was returned by the preceding successful invocation.
        let _ = unsafe { syscall::syscall1(syscall::SYS_UMASK, self.0) };
    }
}

struct RemovePath(*const i8);

impl Drop for RemovePath {
    fn drop(&mut self) {
        // SAFETY: The static NUL-terminated path remains live for the entire
        // process and `unlinkat`'s remaining arguments are scalar values.
        let _ = unsafe { syscall::syscall3(syscall::SYS_UNLINKAT, AT_FDCWD, self.0 as i64, 0) };
    }
}

struct CloseFd(i64);

impl Drop for CloseFd {
    fn drop(&mut self) {
        // SAFETY: This guard owns one descriptor returned by the kernel.
        let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, self.0) };
    }
}

fn require_nonnegative(result: i64, operation: &str) -> Result<i64, String> {
    if result < 0 {
        Err(format!("{operation} returned raw kernel error {result}"))
    } else {
        Ok(result)
    }
}

fn main() -> Result<(), String> {
    // SAFETY: `SYS_GETPID` takes no pointers or additional arguments.
    let pid = unsafe { syscall::syscall0(syscall::SYS_GETPID) };
    if pid <= 0 {
        return Err(format!("getpid returned {pid}"));
    }

    let path = CStr::from_bytes_with_nul(b"/tmp/crabc-x86-libc-syscall-probe\0")
        .map_err(|error| error.to_string())?;
    // SAFETY: The fixed path is NUL-terminated; ENOENT is the expected clean
    // state and is intentionally ignored before exclusive creation.
    let _ = unsafe {
        syscall::syscall3(
            syscall::SYS_UNLINKAT,
            AT_FDCWD,
            path.as_ptr() as i64,
            0,
        )
    };
    let _remove = RemovePath(path.as_ptr());

    // SAFETY: `umask` takes one scalar mode argument. Restoring this exact
    // result makes the mode observation below independent of the harness.
    let previous_umask = require_nonnegative(
        unsafe { syscall::syscall1(syscall::SYS_UMASK, 0) },
        "umask",
    )?;
    let _restore_umask = RestoreUmask(previous_umask);

    // `openat` proves that the fourth Linux syscall word reaches x86-64 r10:
    // `fstat` reads back the requested mode after an explicit zero umask.
    let file = require_nonnegative(
        unsafe {
            syscall::syscall4(
                syscall::SYS_OPENAT,
                AT_FDCWD,
                path.as_ptr() as i64,
                O_RDWR | O_CREAT | O_EXCL,
                0o600,
            )
        },
        "openat",
    )?;
    let _file = CloseFd(file);
    let mut stat = [0u8; 144];
    require_nonnegative(
        unsafe { syscall::syscall2(syscall::SYS_FSTAT, file, stat.as_mut_ptr() as i64) },
        "fstat",
    )?;
    let mode = u32::from_le_bytes([
        stat[MODE_OFFSET],
        stat[MODE_OFFSET + 1],
        stat[MODE_OFFSET + 2],
        stat[MODE_OFFSET + 3],
    ]) & 0o777;
    if mode != 0o600 {
        return Err(format!("openat mode reached the kernel as {mode:#o}, expected 0o600"));
    }

    let socket = require_nonnegative(
        unsafe { syscall::syscall3(syscall::SYS_SOCKET, AF_INET, SOCK_STREAM, 0) },
        "socket",
    )?;
    let _socket = CloseFd(socket);
    let enabled: i32 = 1;
    // `setsockopt` proves the fifth raw word uses r8 after its pointer is
    // supplied as the fourth raw word in r10.
    require_nonnegative(
        unsafe {
            syscall::syscall5(
                syscall::SYS_SETSOCKOPT,
                socket,
                SOL_SOCKET,
                SO_REUSEADDR,
                (&enabled as *const i32) as i64,
                core::mem::size_of::<i32>() as i64,
            )
        },
        "setsockopt",
    )?;

    // `mmap` requires every x86-64 syscall register through r9: flags in r10,
    // descriptor in r8, and offset in r9. The writable mapping is touched and
    // released through the same raw table.
    let mapping = require_nonnegative(
        unsafe {
            syscall::syscall6(
                syscall::SYS_MMAP,
                0,
                4096,
                PROT_READ_WRITE,
                MAP_PRIVATE_ANONYMOUS,
                -1,
                0,
            )
        },
        "mmap",
    )?;
    // SAFETY: The successful anonymous mapping owns at least one writable
    // page, and this byte is released by the checked `munmap` below.
    unsafe { (mapping as *mut u8).write(0x5a) };
    require_nonnegative(
        unsafe { syscall::syscall2(syscall::SYS_MUNMAP, mapping, 4096) },
        "munmap",
    )?;

    println!("x86 libc syscall register probe passed (pid {pid})");
    Ok(())
}
