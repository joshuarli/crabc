//! Private x86 full-LTO consumer of direct native descriptor ownership.
//!
//! Filesystem, pipe, eventfd, descriptor flags, process identity, and direct
//! process I/O cross the typed facade. Duplicate descriptors share offsets
//! and status flags while retaining independent close-on-exec state. The
//! lifecycle definitions are private glue for the static-PIE CRT boundary;
//! they do not imply an installed sysroot, libc, loader, or stock Rust std.
#![no_main]
#![no_std]

use core::ffi::{c_void, CStr};
use core::mem::MaybeUninit;

use crabc_core::process::exit_immediately;
use crabc_rs::event::{eventfd, eventfd_read, eventfd_write, EventfdFlags};
use crabc_rs::fd::BorrowedFd;
use crabc_rs::fs::{self, Mode, OFlags, CWD};
use crabc_rs::io::{self, FdFlags};
use crabc_rs::pipe::{self, PipeFlags};
use crabc_rs::process;

type ApplicationMain = unsafe extern "C" fn() -> i32;
type LifecycleHook = unsafe extern "C" fn();

const OK: &[u8] = b"x86-native-facade-lto:ok\n";
const FAIL_PID: &[u8] = b"x86-native-facade-lto:fail:pid\n";
const FAIL_FILE: &[u8] = b"x86-native-facade-lto:fail:file\n";
const FAIL_PIPE: &[u8] = b"x86-native-facade-lto:fail:pipe\n";
const FAIL_EVENT: &[u8] = b"x86-native-facade-lto:fail:eventfd\n";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    fail(101, FAIL_FILE)
}

// The exact pinned `core` archive expects this Rust ABI symbol. Retain and
// globalize it instead of admitting a panic-runtime archive at the final link.
#[used]
static KEEP_PANIC_HANDLER: fn(&core::panic::PanicInfo<'_>) -> ! = panic;
core::arch::global_asm!(".global _RNvCshC78LsHd0gk_7___rustc17rust_begin_unwind");

// The selected abort-only image cannot unwind, but pinned `core` retains the
// personality reference. This inert owner keeps the closed boundary explicit.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[inline(never)]
fn fail(status: i32, message: &[u8]) -> ! {
    // SAFETY: descriptor 1 is borrowed from the process and never closed.
    let stdout = unsafe { BorrowedFd::borrow_raw(1) };
    let _ = io::write(stdout, message);
    exit_immediately(status)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_rs_native_facade_getpid_witness() -> i32 {
    let first = process::getpid().as_raw_pid();
    let second = process::getpid().as_raw_pid();
    let third = process::getpid().as_raw_pid();
    if first > 0 && first == second && second == third {
        0
    } else {
        1
    }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn native_facade_direct_route() -> i32 {
    if crabc_rs_native_facade_getpid_witness() != 0 {
        return 1;
    }

    // Keep the owned compiler-helper archive a genuinely selected runtime
    // input. The process-derived seed prevents full LTO from folding away the
    // two `__udivti3` calls, while equality keeps the result deterministic.
    let seed = process::getpid().as_raw_pid() as u64;
    let first = crabc_x86_consumer_lto_helper::fingerprint(seed);
    let second = crabc_x86_consumer_lto_helper::fingerprint(seed);
    if first == 0 || first != second {
        return 13;
    }

    let null_path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/null\0") };
    let null = match fs::openat(CWD, null_path, OFlags::WRONLY, Mode::empty()) {
        Ok(fd) => fd,
        Err(_) => return 2,
    };
    if io::write(&null, b"native-facade-native\n") != Ok(21) {
        return 3;
    }
    drop(null);

    // The running ELF is a stable readable file. Duplicate ownership must
    // preserve the same open-file-description offset after the first owner
    // closes, while positioned reads leave that shared offset unchanged.
    let executable = match fs::openat(CWD, c"/proc/self/exe", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => fd,
        Err(_) => return 2,
    };
    let duplicate = match io::dup(&executable) {
        Ok(fd) => fd,
        Err(_) => return 3,
    };
    if io::fcntl_getfd(&duplicate) != Ok(FdFlags::empty())
        || io::fcntl_setfd(&duplicate, FdFlags::CLOEXEC).is_err()
        || io::fcntl_setfd(&executable, FdFlags::empty()).is_err()
        || io::fcntl_getfd(&duplicate) != Ok(FdFlags::CLOEXEC) {
        return 3;
    }
    let mut magic = [0u8; 4];
    if io::read(&executable, &mut magic[..1]) != Ok(1) || magic[0] != 0x7f
        || io::read(&duplicate, &mut magic[1..]) != Ok(3) || &magic != b"\x7fELF" {
        return 3;
    }
    if io::pread(&executable, &mut magic, 0) != Ok(4) || fs::tell(&duplicate) != Ok(4) {
        return 3;
    }
    drop(executable);
    if io::read(&duplicate, &mut magic[..1]) != Ok(1) || magic[0] != 2 {
        return 3;
    }
    drop(duplicate);

    let (reader, writer) = match pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK) {
        Ok(pair) => pair,
        Err(_) => return 4,
    };
    let reader_alias = match io::dup(&reader) {
        Ok(fd) => fd,
        Err(_) => return 4,
    };
    let writer_alias = match io::dup(&writer) {
        Ok(fd) => fd,
        Err(_) => return 4,
    };
    let status = match fs::fcntl_getfl(&reader) {
        Ok(flags) => flags,
        Err(_) => return 4,
    };
    if !status.contains(OFlags::NONBLOCK)
        || fs::fcntl_setfl(&reader_alias, status & !OFlags::NONBLOCK).is_err()
        || fs::fcntl_getfl(&reader).map(|flags| flags.contains(OFlags::NONBLOCK)) != Ok(false)
        || fs::fcntl_setfl(&reader_alias, status).is_err() {
        return 4;
    }
    let mut guarded = [0xa5u8; 8];
    if io::read(&reader_alias, &mut guarded) != Err(crabc_rs::Errno::AGAIN)
        || guarded != [0xa5; 8] {
        return 6;
    }
    if io::write(&writer, b"pipe") != Ok(4) {
        return 5;
    }
    drop(writer);
    drop(reader);
    let mut received = [MaybeUninit::<u8>::uninit(); 8];
    let (initialized, remaining) = match io::read(&reader_alias, &mut received) {
        Ok(value) => value,
        Err(_) => return 6,
    };
    if initialized != b"pipe" || remaining.len() != 4 {
        return 7;
    }
    // The duplicate writer keeps the empty pipe live; only its consuming
    // close changes a subsequent read from EAGAIN to EOF.
    if io::read(&reader_alias, &mut guarded) != Err(crabc_rs::Errno::AGAIN)
        || guarded != [0xa5; 8] || writer_alias.close().is_err() {
        return 7;
    }
    let (initialized, remaining) = match io::read(&reader_alias, &mut received) {
        Ok(value) => value,
        Err(_) => return 6,
    };
    if !initialized.is_empty() || remaining.len() != 8 {
        return 7;
    }
    drop(reader_alias);

    let counter = match eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK) {
        Ok(fd) => fd,
        Err(_) => return 8,
    };
    let flags = match io::fcntl_getfd(&counter) {
        Ok(flags) => flags,
        Err(_) => return 9,
    };
    if !flags.contains(FdFlags::CLOEXEC) {
        return 10;
    }
    if eventfd_write(&counter, 7).is_err() {
        return 11;
    }
    if eventfd_read(&counter) != Ok(7) || eventfd_read(&counter) != Err(crabc_rs::Errno::AGAIN) {
        return 12;
    }
    drop(counter);

    0
}

/// Stable inspection anchor around the direct descriptor ownership workload.
#[no_mangle]
#[inline(never)]
pub extern "C" fn crabc_x86_consumer_lto_route() -> i32 {
    native_facade_direct_route()
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    match crabc_x86_consumer_lto_route() {
        0 => {
            // SAFETY: descriptor 1 is borrowed from the process and never closed.
            let stdout = unsafe { BorrowedFd::borrow_raw(1) };
            if io::write(stdout, OK) != Ok(OK.len()) {
                return 102;
            }
            0
        }
        1 => fail(1, FAIL_PID),
        2 | 3 => fail(2, FAIL_FILE),
        4..=7 => fail(3, FAIL_PIPE),
        _ => fail(4, FAIL_EVENT),
    }
}

#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_static_tls_bootstrap(
    _initial_stack: *const usize,
) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    application: ApplicationMain,
    argc: i32,
    argv: *const *const u8,
    init: *const c_void,
    fini: *const c_void,
    _rtld_fini: *const c_void,
) -> ! {
    if argc < 0 || argv.is_null() {
        exit_immediately(94);
    }
    if !init.is_null() {
        // SAFETY: the Rust CRT supplies `_init` using this exact C ABI.
        let callback: LifecycleHook = unsafe { core::mem::transmute(init) };
        unsafe { callback() };
    }
    let status = unsafe { application() };
    if !fini.is_null() {
        // SAFETY: the Rust CRT supplies `_fini` using this exact C ABI.
        let callback: LifecycleHook = unsafe { core::mem::transmute(fini) };
        unsafe { callback() };
    }
    exit_immediately(status)
}
