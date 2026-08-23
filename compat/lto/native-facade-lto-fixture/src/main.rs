//! Bounded application workload for native `crabc-rs` LTO inspection.
//!
//! This is an actual no-std Linux/AArch64 executable rather than a static
//! library probe. The target CRT enters its C-ABI `main`; every operation
//! below reaches the kernel through the direct `crabc-rs` facade.
//! In particular, there are no public C ABI calls, C `errno` reads, or
//! allocator dependencies to hide the application-to-syscall path.
//!
//! The workload is deliberately bounded: it uses fixed byte arrays, one
//! `/dev/null` descriptor, one pipe, and one eventfd.  A successful run emits
//! one deterministic line; each failed assertion emits a distinct line and
//! exits with a nonzero status so a runtime harness can distinguish failures
//! without parsing a PID or other host-dependent value.
//!
#![no_main]
#![no_std]

use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::event::{eventfd, eventfd_read, eventfd_write, EventfdFlags};
use crabc_rs::fd::BorrowedFd;
use crabc_rs::fs::{self, Mode, OFlags, CWD};
use crabc_rs::io::{self, FdFlags};
use crabc_rs::pipe::{self, PipeFlags};
use crabc_rs::process;

const OK: &[u8] = b"native-facade:ok\n";
const FAIL_PID: &[u8] = b"native-facade-crabc-rs:fail:pid\n";
const FAIL_FILE: &[u8] = b"native-facade-crabc-rs:fail:file\n";
const FAIL_PIPE: &[u8] = b"native-facade-crabc-rs:fail:pipe\n";
const FAIL_EVENT: &[u8] = b"native-facade-crabc-rs:fail:eventfd\n";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    fail(101, FAIL_FILE)
}

// `core` retains an unwind-personality reference even with `panic = "abort"`
// on this target. No unwinding can reach this fixture—the panic handler exits
// directly—but supplying the inert linker symbol lets the normal dynamic musl
// CRT own process startup without importing an unwind runtime.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// Writes a bounded diagnostic directly to stdout and terminates the process.
///
/// The borrowed descriptor is the conventional process-owned stdout and is
/// never wrapped in an owning value.  `exit_immediately` is a direct Linux
/// `exit_group` operation, so no C runtime cleanup or public ABI transition is
/// introduced at the terminal boundary.
#[inline(never)]
fn fail(status: i32, message: &[u8]) -> ! {
    // SAFETY: file descriptor 1 is the process-owned stdout descriptor. This
    // borrow does not take ownership and is used only for the one write below.
    let stdout = unsafe { BorrowedFd::borrow_raw(1) };
    let _ = io::write(stdout, message);
    process::exit_immediately(status)
}

/// An exported, fixed-shape witness for function-scoped syscall inspection.
///
/// The result is process-independent: zero means all three direct `getpid`
/// observations were positive and stable, while one means an assertion failed.
/// Keeping the three calls in this `#[inline(never)]` symbol gives an LTO
/// harness a bounded function whose `svc #0` sequence can be inspected without
/// conflating it with the descriptor workload below.
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

/// Runs the fixed native-facade assertions and returns a process status.
///
/// This exported route is the ELF inspection anchor. It consumes the
/// function-scoped `getpid` witness first, then exercises the descriptor
/// operations so the final image contains both direct scalar and I/O paths.
#[inline(never)]
#[no_mangle]
pub extern "C" fn native_facade_direct_route() -> i32 {
    if crabc_rs_native_facade_getpid_witness() != 0 {
        return 1;
    }

    // `openat` and `write` exercise the typed path and descriptor ownership
    // boundary without requiring a writable filesystem or any C strings from
    // the caller. `/dev/null` is present in the pinned Linux test image.
    let null_path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/null\0") };
    let null = match fs::openat(CWD, null_path, OFlags::WRONLY, Mode::empty()) {
        Ok(fd) => fd,
        Err(_) => return 2,
    };
    if io::write(&null, b"native-facade-native\n") != Ok(21) {
        return 3;
    }
    drop(null);

    // A pipe gives the optimizer a small typed read/write round trip.  The
    // `MaybeUninit` buffer keeps the no-std initialization contract explicit.
    let (reader, writer) = match pipe::pipe_with(PipeFlags::CLOEXEC) {
        Ok(pair) => pair,
        Err(_) => return 4,
    };
    if io::write(&writer, b"pipe") != Ok(4) {
        return 5;
    }
    let mut received = [MaybeUninit::<u8>::uninit(); 4];
    let (initialized, _) = match io::read(&reader, &mut received) {
        Ok(value) => value,
        Err(_) => return 6,
    };
    if initialized != b"pipe" {
        return 7;
    }
    drop(writer);
    drop(reader);

    // `eventfd` and `fcntl(F_GETFD)` provide a typed scalar operation and an
    // observable flag check while retaining direct errno-free errors.
    let counter = match eventfd(0, EventfdFlags::CLOEXEC) {
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
    if eventfd_read(&counter) != Ok(7) {
        return 12;
    }
    drop(counter);

    0
}

/// C-ABI entry point used by the target's normal dynamic musl startup object.
///
/// The startup path is intentionally outside the named direct-route proof.
/// The route itself reaches the kernel through `crabc-rs` rather than calling
/// any public C ABI function or reading C `errno`.
#[no_mangle]
pub extern "C" fn main() -> i32 {
    match native_facade_direct_route() {
        0 => {
            // SAFETY: file descriptor 1 is the process-owned stdout
            // descriptor; this borrow never closes it.
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
