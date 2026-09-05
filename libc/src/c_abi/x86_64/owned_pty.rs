//! Installed Linux/x86-64 PTY and terminal-session helpers, translated from
//! musl 1.2.6 (MIT), release revision 9fa28ece75d8a2191de7c5bb53bed224c5947417.
//! `src/misc/{pty,ptsname,openpty,login_tty,forkpty}.c`,
//! `src/unistd/ttyname.c`, and `src/termios/tcgetsid.c` map to the named entries.
//! Public descriptor/cancellation, signal, terminal and atfork owners retain
//! their existing transactions. The source's ignored errors and publication
//! order are deliberate: a later setup error must not invent a rollback that
//! musl never performs. Frozen private artifacts and AArch64 remain separate.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use super::{child_reaping, descriptor_entry, descriptor_io, errno, posix_exit,
    process_context, pthread_atfork, pthread_cancel, raw_syscall, signal_control,
    signal_foundation::PUBLIC_SIGSET_WORDS, signal_set_mutation, stdio_format_scan,
    termios_control, ttyname_r};

const O_RDWR: c_int = 2;
const O_NOCTTY: c_int = 0x100;
const O_CLOEXEC: c_int = 0x80000;
const EAGAIN: c_int = 11;
const ENOSPC: c_int = 28;
const ERANGE: c_int = 34;
const TIOCSCTTY: c_int = 0x540e;
const TIOCSWINSZ: c_int = 0x5414;
const TIOCGSID: c_int = 0x5429;
const TIOCGPTN: c_int = 0x80045430u32 as c_int;
const TIOCSPTLCK: c_int = 0x40045431;
const SIG_BLOCK: c_int = 0;
const SIG_SETMASK: c_int = 2;
const PTHREAD_CANCEL_DISABLE: c_int = 1;

unsafe extern "C" {
    // The owned generic ioctl entry consumes this explicit third ABI word.
    fn ioctl(fd: c_int, request: c_int, argument: usize) -> c_int;
}

/// Open the Unix98 PTY multiplexer, mapping exhausted PTYs to `EAGAIN`.
#[no_mangle]
pub extern "C" fn posix_openpt(flags: c_int) -> c_int {
    let fd = unsafe { descriptor_entry::open(c"/dev/ptmx".as_ptr(), flags, 0) };
    if fd < 0 && unsafe { errno::get_errno() } == ENOSPC {
        unsafe { errno::set_errno(EAGAIN) };
    }
    fd
}

// ptsname calls the source's internal provider even if an application replaces
// the weak public ptsname_r alias. Keep the internal spelling out of dynamic
// exports while retaining the source's same-address public weak binding.
core::arch::global_asm!(
    ".hidden __ptsname_r",
    ".weak ptsname_r",
    ".set ptsname_r, __ptsname_r",
);

/// Derive the slave path into bounded caller storage, returning an error number.
///
/// # Safety
/// A non-null `name` designates `capacity` writable bytes. A null buffer has
/// zero effective capacity. The caller owns descriptor stability and any
/// synchronization around the buffer; an error may leave a truncated name.
#[no_mangle]
pub unsafe extern "C" fn __ptsname_r(fd: c_int, name: *mut c_char, mut capacity: usize) -> c_int {
    if name.is_null() { capacity = 0; }
    let mut number: c_int = 0;
    // Musl uses the raw ioctl result here: errors do not publish errno.
    let result = unsafe { raw_syscall::syscall3(raw_syscall::SYS_IOCTL, fd as i64,
        TIOCGPTN as u32 as i64, ptr::addr_of_mut!(number) as i64) };
    if result != 0 { return -result as c_int; }
    let length = unsafe { stdio_format_scan::snprintf(name, capacity, c"/dev/pts/%d".as_ptr(), number) };
    if length as usize >= capacity { ERANGE } else { 0 }
}

// Source-sized, process-global buffers are intentionally reused and unlocked.
// Returned names are observations, not retained descriptor/path ownership.
static mut PTY_NAME: [c_char; 9 + core::mem::size_of::<c_int>() * 3 + 1] = [0; 22];
static mut TTY_NAME: [c_char; 32] = [0; 32]; // x86 TTY_NAME_MAX

/// Observe a slave name in the source's reused process-global static buffer.
///
/// # Safety
/// The caller serializes all ptsname calls and all accesses through previously
/// returned pointers. A later call may overwrite the returned name. The
/// descriptor must remain stable for a meaningful observation.
#[no_mangle]
pub unsafe extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    let buffer = ptr::addr_of_mut!(PTY_NAME).cast::<c_char>();
    let error = unsafe { __ptsname_r(fd, buffer, 22) };
    if error != 0 {
        unsafe { errno::set_errno(error) };
        ptr::null_mut()
    } else { buffer }
}

/// Observe a terminal name in the source's reused process-global static buffer.
///
/// # Safety
/// The caller serializes all ttyname calls and accesses through previously
/// returned pointers, and retains descriptor/namespace lifetime authority.
/// A later call may overwrite the returned name, including on failure.
#[no_mangle]
pub unsafe extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    let buffer = ptr::addr_of_mut!(TTY_NAME).cast::<c_char>();
    let error = unsafe { ttyname_r::ttyname_r(fd, buffer, 32) };
    if error != 0 {
        unsafe { errno::set_errno(error) };
        ptr::null_mut()
    } else { buffer }
}

/// Observe the session controlling one terminal descriptor.
#[no_mangle]
pub extern "C" fn tcgetsid(fd: c_int) -> c_int {
    let mut session: c_int = 0;
    if unsafe { ioctl(fd, TIOCGSID, ptr::addr_of_mut!(session) as usize) } < 0 {
        -1
    } else { session }
}

/// Allocate a master/slave pair without acquiring a controlling terminal.
///
/// # Safety
/// `master` and `slave` designate writable C ints, published only on success.
/// A non-null `name` designates at least 20 writable bytes, which may be
/// changed before a failed slave open. Non-null `settings` and `window`
/// designate readable public x86 termios and eight-byte winsize records.
/// The caller assumes ownership of both returned descriptors on success.
#[no_mangle]
pub unsafe extern "C" fn openpty(master: *mut c_int, slave: *mut c_int,
    name: *mut c_char, settings: *const c_void, window: *const c_void) -> c_int {
    // This first open is a cancellation point and does not use posix_openpt's
    // ENOSPC remapping. The disabled interval begins only after allocation.
    let m = unsafe { descriptor_entry::open(c"/dev/ptmx".as_ptr(), O_RDWR | O_NOCTTY, 0) };
    if m < 0 { return -1; }
    let mut previous = 0;
    unsafe { pthread_cancel::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut previous) };
    let mut number: c_int = 0;
    if unsafe { ioctl(m, TIOCSPTLCK, ptr::addr_of_mut!(number) as usize) } != 0
        || unsafe { ioctl(m, TIOCGPTN, ptr::addr_of_mut!(number) as usize) } != 0 {
        descriptor_io::close(m);
        unsafe { pthread_cancel::pthread_setcancelstate(previous, ptr::null_mut()) };
        return -1;
    }
    let mut temporary = [0 as c_char; 20];
    let name = if name.is_null() { temporary.as_mut_ptr() } else { name };
    unsafe { stdio_format_scan::snprintf(name, 20, c"/dev/pts/%d".as_ptr(), number) };
    let s = unsafe { descriptor_entry::open(name, O_RDWR | O_NOCTTY, 0) };
    if s < 0 {
        descriptor_io::close(m);
        unsafe { pthread_cancel::pthread_setcancelstate(previous, ptr::null_mut()) };
        return -1;
    }
    // Source optional setup errors do not turn a successfully allocated pair
    // into failure. Their errno remains observable alongside return zero.
    if !settings.is_null() { unsafe { termios_control::tcsetattr(s, 0, settings) }; }
    if !window.is_null() { unsafe { ioctl(s, TIOCSWINSZ, window as usize) }; }
    unsafe { master.write(m); slave.write(s); }
    unsafe { pthread_cancel::pthread_setcancelstate(previous, ptr::null_mut()) };
    0
}

/// Acquire a controlling terminal and redirect descriptors zero through two.
///
/// # Safety
/// The caller authorizes process session/controlling-terminal changes and
/// replacement of stdin/stdout/stderr. `fd` remains stable through the call;
/// on successful TIOCSCTTY it is closed after duplication when greater than 2.
/// The caller coordinates other threads' use of the affected descriptors.
#[no_mangle]
pub unsafe extern "C" fn login_tty(fd: c_int) -> c_int {
    process_context::setsid();
    if unsafe { ioctl(fd, TIOCSCTTY, 0) } != 0 { return -1; }
    // Musl deliberately ignores both setsid and dup2 errors here. Only the
    // controlling-terminal ioctl gates descriptor redirection and success.
    descriptor_io::dup2(fd, 0);
    descriptor_io::dup2(fd, 1);
    descriptor_io::dup2(fd, 2);
    if fd > 2 { descriptor_io::close(fd); }
    0
}

/// Fork a child with a newly allocated controlling terminal and error pipe.
///
/// # Safety
/// `master` designates a writable C int; only a successful parent publishes
/// it. `name`, `settings`, and `window` satisfy openpty's buffer contracts.
/// The caller assumes parent master/child ownership and the ordinary fork
/// obligations for live atfork callbacks and inherited application state.
#[no_mangle]
pub unsafe extern "C" fn forkpty(master: *mut c_int, name: *mut c_char,
    settings: *const c_void, window: *const c_void) -> c_int {
    let (mut m, mut s) = (-1, -1);
    if unsafe { openpty(&mut m, &mut s, name, settings, window) } < 0 { return -1; }
    let mut set = [0u64; PUBLIC_SIGSET_WORDS];
    let mut old_set = [0u64; PUBLIC_SIGSET_WORDS];
    unsafe {
        signal_set_mutation::sigfillset(set.as_mut_ptr().cast());
        signal_control::pthread_sigmask(SIG_BLOCK, set.as_ptr().cast(), old_set.as_mut_ptr().cast());
    }
    let mut previous = 0;
    unsafe { pthread_cancel::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut previous) };
    let mut pid = -1;
    let mut pipe = [-1; 2];
    if unsafe { descriptor_io::pipe2(pipe.as_mut_ptr(), O_CLOEXEC) } != 0 {
        descriptor_io::close(s);
    } else {
        pid = unsafe { pthread_atfork::fork() };
        if pid == 0 {
            descriptor_io::close(m);
            descriptor_io::close(pipe[0]);
            if unsafe { login_tty(s) } != 0 {
                // The pipe carries precisely one C errno word. The parent
                // reaps this failed child before returning that error.
                let error = unsafe { errno::get_errno() };
                unsafe { descriptor_io::write(pipe[1], ptr::addr_of!(error).cast(), core::mem::size_of::<c_int>()) };
                posix_exit::_exit(127);
            }
            descriptor_io::close(pipe[1]);
            unsafe {
                pthread_cancel::pthread_setcancelstate(previous, ptr::null_mut());
                signal_control::pthread_sigmask(SIG_SETMASK, old_set.as_ptr().cast(), ptr::null_mut());
            }
            return 0;
        }
        descriptor_io::close(s);
        descriptor_io::close(pipe[1]);
        let mut error: c_int = 0;
        if unsafe { descriptor_io::read(pipe[0], ptr::addr_of_mut!(error).cast(), core::mem::size_of::<c_int>()) } > 0 {
            let mut status = 0;
            unsafe { child_reaping::waitpid(pid, &mut status, 0) };
            pid = -1;
            unsafe { errno::set_errno(error) };
        }
        descriptor_io::close(pipe[0]);
    }
    if pid > 0 { unsafe { master.write(m) }; }
    else { descriptor_io::close(m); }
    unsafe {
        pthread_cancel::pthread_setcancelstate(previous, ptr::null_mut());
        signal_control::pthread_sigmask(SIG_SETMASK, old_set.as_ptr().cast(), ptr::null_mut());
    }
    pid
}
