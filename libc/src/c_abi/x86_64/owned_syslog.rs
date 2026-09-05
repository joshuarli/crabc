//! Owned Linux/x86-64 C `syslog` state and datagram delivery.
//!
//! This is a direct semantic translation of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, from the verified release
//! archive SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
//! `src/misc/syslog.c` is covered by musl's MIT license recorded in this
//! repository's upstream pin.
//!
//! | Pinned definition | Owned x86 translation |
//! | --- | --- |
//! | file-static `lock` and `__syslog_lockptr` | `SYSLOG_LOCK` plus the three `pthread_fork_*` hooks below |
//! | `log_ident`, `log_opt`, `log_facility`, `log_mask`, `log_fd` | the five matching process-global Rust statics |
//! | `setlogmask` | [`setlogmask`] |
//! | `log_addr` and `__openlog` | [`SyslogAddress`] and [`open_connection`] |
//! | `closelog`, `openlog`, `is_lost_conn` | their matching public/private functions |
//! | `_vsyslog` | [`write_message`] |
//! | private `__vsyslog` and `weak_alias(__vsyslog, vsyslog)` | private [`__vsyslog`] plus weak [`vsyslog`] |
//! | `syslog` | [`syslog`] |
//!
//! The source's internal lock pointer is represented by direct Rust fork-hook
//! calls rather than a link-visible pointer.  It remains private runtime
//! state; its observable lock acquisition, parent release, and child reset
//! occur at the same `stdio -> syslog -> timezone` fork position.
//!
//! `syslog` is bounded C logging compatibility.  It owns no daemon discovery,
//! logger configuration framework, persistent queue, host `/dev/log` fixture,
//! or console policy beyond musl's one `/dev/log` datagram and optional
//! `/dev/console` fallback.  The installed evidence creates both paths only
//! below a disposable private chroot.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void, VaList};
use core::sync::atomic::{AtomicI32, Ordering};

use super::{
    descriptor_entry, descriptor_io, errno, gmtime_r, locale_objects,
    owned_strftime, process_context, pthread_cancel, raw_syscall,
    socket_transport, stdio_format_scan, time_observation, timegm::Tm,
};

const LOG_USER: c_int = 1 << 3;
const LOG_FACMASK: c_int = 0x3f8;
const LOG_PRIORITY_MASK: c_int = 0x3ff;
const LOG_MASK_DEFAULT: c_int = 0xff;
const LOG_PID: c_int = 0x01;
const LOG_CONS: c_int = 0x02;
const LOG_NDELAY: c_int = 0x08;
const LOG_PERROR: c_int = 0x20;

const AF_UNIX: c_int = 1;
const SOCK_DGRAM: c_int = 2;
const SOCK_CLOEXEC: c_int = 0o2000000;
const O_WRONLY: c_int = 0x1;
const O_NOCTTY: c_int = 0x100;
const O_CLOEXEC: c_int = 0o2000000;

const ECONNREFUSED: c_int = 111;
const ECONNRESET: c_int = 104;
const ENOTCONN: c_int = 107;
const EPIPE: c_int = 32;

const MESSAGE_CAPACITY: usize = 1024;
const IDENT_CAPACITY: usize = 32;
const FUTEX_WAIT_PRIVATE: i64 = 128;
const FUTEX_WAKE_PRIVATE: i64 = 129;

// This is musl `__lock`'s one-word state representation.  The sign bit says
// a task owns the lock; the remaining value tracks congestion.  The owned
// runtime always takes this lock, including before the first created worker;
// musl's `libc.need_locks` single-threaded elision has no observable logger
// state effect and would only add another process-global state owner here.
const LOCK_FLAG: i32 = i32::MIN;
const LOCKED_ONE: i32 = LOCK_FLAG + 1;

static SYSLOG_LOCK: AtomicI32 = AtomicI32::new(0);
static mut LOG_IDENT: [c_char; IDENT_CAPACITY] = [0; IDENT_CAPACITY];
static mut LOG_OPT: c_int = 0;
static mut LOG_FACILITY: c_int = LOG_USER;
// Musl deliberately tests `log_mask` before acquiring `lock` in
// `__vsyslog`, while `setlogmask` writes it under that lock.  Give that
// source-level integer publication a defined Rust representation: relaxed
// operations retain the source's lack of an ordering promise, and the logger
// lock still serializes setlogmask replacement with its other state.
static LOG_MASK: AtomicI32 = AtomicI32::new(LOG_MASK_DEFAULT);
static mut LOG_FD: c_int = -1;

#[repr(C)]
struct SyslogAddress {
    family: u16,
    path: [u8; 9],
    // C gives the source's short-plus-nine-byte struct one tail-padding byte.
    // Make the transmitted twelve-byte short sockaddr layout fully defined,
    // as its static C initializer does.
    padding: u8,
}

const _: () = {
    assert!(core::mem::size_of::<SyslogAddress>() == 12);
    assert!(core::mem::align_of::<SyslogAddress>() == 2);
};

#[inline]
fn log_address() -> SyslogAddress {
    SyslogAddress {
        family: AF_UNIX as u16,
        path: *b"/dev/log\0",
        padding: 0,
    }
}

#[inline]
unsafe fn futex_wait(value: i32) {
    // SAFETY: SYSLOG_LOCK is process-private, aligned, and remains live for
    // the process.  A spurious wake or signal only retries musl's lock loop.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            SYSLOG_LOCK.as_ptr() as i64,
            FUTEX_WAIT_PRIVATE,
            i64::from(value),
            0,
        )
    };
}

#[inline]
unsafe fn futex_wake() {
    // SAFETY: SYSLOG_LOCK is the matching private futex word.  Waking one
    // waiter is musl's `__unlock` policy for this congestion representation.
    let _ = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FUTEX,
            SYSLOG_LOCK.as_ptr() as i64,
            FUTEX_WAKE_PRIVATE,
            1,
        )
    };
}

/// Acquire the pinned musl one-word logger lock.
///
/// Cancellation is disabled by the callers that can otherwise reach a C
/// cancellation point.  `setlogmask` matches musl and uses this raw-futex
/// lock without changing cancellation state.
#[inline]
unsafe fn lock() {
    let mut current = SYSLOG_LOCK
        .compare_exchange(0, LOCKED_ONE, Ordering::Acquire, Ordering::Relaxed)
        .unwrap_or_else(|value| value);
    if current == 0 {
        return;
    }

    for _ in 0..10 {
        if current < 0 {
            current = current.wrapping_sub(LOCKED_ONE);
        }
        // `__lock.c` writes `INT_MIN + (current + 1)`: the low-order
        // congestion count is separate from the locked-one fast-path value.
        let desired = LOCK_FLAG.wrapping_add(current.wrapping_add(1));
        match SYSLOG_LOCK.compare_exchange(
            current,
            desired,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(value) => current = value,
        }
    }

    current = SYSLOG_LOCK.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    loop {
        if current < 0 {
            unsafe { futex_wait(current) };
            current = current.wrapping_sub(LOCKED_ONE);
        }
        let desired = LOCK_FLAG.wrapping_add(current);
        match SYSLOG_LOCK.compare_exchange(
            current,
            desired,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(value) => current = value,
        }
    }
}

#[inline]
unsafe fn unlock() {
    if SYSLOG_LOCK.load(Ordering::Relaxed) < 0
        && SYSLOG_LOCK.fetch_add(LOCKED_ONE.wrapping_neg(), Ordering::Release) != LOCKED_ONE
    {
        unsafe { futex_wake() };
    }
}

#[inline]
unsafe fn disable_cancellation() -> Result<c_int, ()> {
    let mut previous = 0;
    // Only the initialized main task and selected workers have cancellation
    // state. Do not let a foreign task proceed through a lock-holding,
    // descriptor-reaching path without this source-required transition.
    if unsafe { pthread_cancel::pthread_setcancelstate(1, &mut previous) } == 0 {
        Ok(previous)
    } else {
        Err(())
    }
}

#[inline]
unsafe fn restore_cancellation(previous: c_int) {
    let _ = unsafe { pthread_cancel::pthread_setcancelstate(previous, core::ptr::null_mut()) };
}

/// Acquire the syslog lock in musl `fork.c`'s position after stdio and before
/// timezone state.
///
/// # Safety
/// The process owner has completed the preceding fork preparation and blocks
/// application signals.  Exactly one parent/error release or child reset must
/// follow before it permits callbacks or ordinary logger use.
pub(super) unsafe fn pthread_fork_prepare() {
    unsafe { lock() };
}

/// Complete the syslog lock transaction in the original process.
///
/// # Safety
/// This is the single parent/error completion matching `pthread_fork_prepare`.
pub(super) unsafe fn pthread_fork_parent() {
    unsafe { unlock() };
}

/// Reset only the inherited syslog lock in the sole fork child.
///
/// Ident, mask, options, facility, and the connected descriptor deliberately
/// survive, matching musl.  No vanished parent task can still own the copied
/// lock after `fork` returns in the child.
///
/// # Safety
/// Called exactly once in the child completion of a prepared `fork`, before
/// user callbacks and never in a `CLONE_VM` child.
pub(super) unsafe fn pthread_fork_child() {
    SYSLOG_LOCK.store(0, Ordering::Relaxed);
}

unsafe fn open_connection() {
    let descriptor = socket_transport::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    unsafe { LOG_FD = descriptor };
    if descriptor >= 0 {
        let address = log_address();
        // SAFETY: `address` is the exact short AF_UNIX sockaddr layout used
        // by musl's static `log_addr`; it remains live through connect.
        let _ = unsafe {
            socket_transport::connect(
                descriptor,
                core::ptr::addr_of!(address).cast::<c_void>(),
                core::mem::size_of::<SyslogAddress>() as c_uint,
            )
        };
    }
}

#[inline]
fn lost_connection(error: c_int) -> bool {
    matches!(error, ECONNREFUSED | ECONNRESET | ENOTCONN | EPIPE)
}

unsafe fn console_message(buffer: *const u8, length: usize, header_length: usize) {
    // SAFETY: the source's fixed pathname is NUL terminated and the selected
    // descriptor entry point takes its optional mode register unconditionally.
    let descriptor = unsafe {
        descriptor_entry::open(
            b"/dev/console\0".as_ptr().cast::<c_char>(),
            O_WRONLY | O_NOCTTY | O_CLOEXEC,
            0,
        )
    };
    if descriptor >= 0 {
        unsafe extern "C" {
            fn dprintf(file_descriptor: c_int, format: *const c_char, ...) -> c_int;
        }
        // SAFETY: `header_length <= length <= MESSAGE_CAPACITY` follows the
        // bounded formatting path. `%.*s` is the pinned source's display
        // shape and dprintf borrows rather than closes this descriptor.
        let _ = unsafe {
            dprintf(
                descriptor,
                b"%.*s\0".as_ptr().cast::<c_char>(),
                length.saturating_sub(header_length) as c_int,
                buffer.add(header_length).cast::<c_char>(),
            )
        };
        let _ = descriptor_io::close(descriptor);
    }
}

/// Translate musl `_vsyslog` while the caller owns `SYSLOG_LOCK` and has
/// cancellation disabled.
unsafe fn write_message(priority: c_int, message: *const c_char, args: VaList) {
    let saved_errno = unsafe { errno::get_errno() };
    if unsafe { LOG_FD } < 0 {
        unsafe { open_connection() };
    }

    let mut now: c_long = 0;
    let _ = unsafe { time_observation::time(&mut now) };
    let mut broken_down: Tm = unsafe { core::mem::zeroed() };
    let _ = unsafe { gmtime_r::gmtime_r(&now, &mut broken_down) };
    let mut timestamp = [0 as c_char; 16];
    let _ = unsafe {
        owned_strftime::strftime_l(
            timestamp.as_mut_ptr(),
            timestamp.len(),
            b"%b %e %T\0".as_ptr().cast::<c_char>(),
            &broken_down,
            locale_objects::fixed_c_locale(),
        )
    };

    let mut priority = priority;
    if priority & LOG_FACMASK == 0 {
        priority |= unsafe { LOG_FACILITY };
    }
    let process_id = if unsafe { LOG_OPT } & LOG_PID != 0 {
        process_context::getpid()
    } else {
        0
    };
    let mut buffer = [0_u8; MESSAGE_CAPACITY];
    let mut header_length = 0;
    let opening_bracket = unsafe { b"[\0".as_ptr().add(usize::from(process_id == 0)) };
    let closing_bracket = unsafe { b"]\0".as_ptr().add(usize::from(process_id == 0)) };
    let header = unsafe {
        stdio_format_scan::snprintf(
            buffer.as_mut_ptr().cast::<c_char>(),
            buffer.len(),
            b"<%d>%s %n%s%s%.0d%s: \0".as_ptr().cast::<c_char>(),
            priority,
            timestamp.as_ptr(),
            &mut header_length,
            core::ptr::addr_of!(LOG_IDENT).cast::<c_char>(),
            opening_bracket.cast::<c_char>(),
            process_id,
            closing_bracket.cast::<c_char>(),
        )
    };
    // The source's fixed fields make this impossible for a conforming owned
    // timestamp/ident state.  Retain a checked Rust boundary instead of
    // turning an unexpected formatter failure into pointer arithmetic.
    if header < 0 || header as usize >= buffer.len() {
        return;
    }

    // `open_connection` and header formatting may set errno.  Musl restores
    // it here so `%m` observes the caller's original error and a successful
    // write retains that value.
    unsafe { errno::set_errno(saved_errno) };
    let header = header as usize;
    let message_length = unsafe {
        stdio_format_scan::vsnprintf(
            buffer.as_mut_ptr().add(header).cast::<c_char>(),
            buffer.len() - header,
            message,
            args,
        )
    };
    if message_length < 0 {
        return;
    }
    let mut length = if message_length as usize >= buffer.len() - header {
        buffer.len() - 1
    } else {
        header + message_length as usize
    };
    if buffer[length - 1] != b'\n' {
        buffer[length] = b'\n';
        length += 1;
    }

    let descriptor = unsafe { LOG_FD };
    let sent = unsafe {
        socket_transport::send(
            descriptor,
            buffer.as_ptr().cast::<c_void>(),
            length,
            0,
        )
    };
    if sent < 0 {
        let send_failed = if lost_connection(unsafe { errno::get_errno() }) {
            let address = log_address();
            (unsafe {
                socket_transport::connect(
                    descriptor,
                    core::ptr::addr_of!(address).cast::<c_void>(),
                    core::mem::size_of::<SyslogAddress>() as c_uint,
                )
            }) < 0
                || unsafe {
                    socket_transport::send(
                        descriptor,
                        buffer.as_ptr().cast::<c_void>(),
                        length,
                        0,
                    )
                } < 0
        } else {
            true
        };
        if send_failed && unsafe { LOG_OPT } & LOG_CONS != 0 {
            unsafe { console_message(buffer.as_ptr(), length, header_length.max(0) as usize) };
        }
    }
    if unsafe { LOG_OPT } & LOG_PERROR != 0 {
        unsafe extern "C" {
            fn dprintf(file_descriptor: c_int, format: *const c_char, ...) -> c_int;
        }
        let _ = unsafe {
            dprintf(
                2,
                b"%.*s\0".as_ptr().cast::<c_char>(),
                length.saturating_sub(header_length.max(0) as usize) as c_int,
                buffer
                    .as_ptr()
                    .add(header_length.max(0) as usize)
                    .cast::<c_char>(),
            )
        };
    }
}

/// Replace or query the process-global priority mask.
///
/// # Safety
/// The caller uses the installed Linux/x86-64 C ABI. This entry dereferences
/// no caller storage and has no cancellation/TLS transition; its private lock
/// and atomic mask publication make concurrent replacement/query calls safe.
/// It does not extend the cancellation-bearing logger entries to foreign
/// tasks.
#[no_mangle]
pub unsafe extern "C" fn setlogmask(maskpri: c_int) -> c_int {
    unsafe { lock() };
    let old = LOG_MASK.load(Ordering::Relaxed);
    if maskpri != 0 {
        LOG_MASK.store(maskpri, Ordering::Relaxed);
    }
    unsafe { unlock() };
    old
}

/// Close the current `/dev/log` descriptor while retaining all logger settings.
///
/// # Safety
/// The current task is the initialized owned main task or a live selected
/// worker created by this runtime's `pthread_create`, and it is not in a
/// fork/lifecycle transition. A foreign task has no owned cancellation slot;
/// this defensive boundary returns before touching logger state for it.
#[no_mangle]
pub unsafe extern "C" fn closelog() {
    let Ok(cancellation) = (unsafe { disable_cancellation() }) else {
        return;
    };
    unsafe { lock() };
    let _ = descriptor_io::close(unsafe { LOG_FD });
    unsafe { LOG_FD = -1 };
    unsafe { unlock() };
    unsafe { restore_cancellation(cancellation) };
}

/// Copy one bounded identifier and configure the process-global logger.
///
/// # Safety
/// The current task is the initialized owned main task or a live selected
/// worker created by this runtime's `pthread_create`, and it is not in a
/// fork/lifecycle transition. A foreign task has no owned cancellation slot;
/// this defensive boundary returns before touching logger state for it.
///
/// When non-null, `ident` must make 31 readable bytes available or terminate
/// sooner.  The identifier is copied immediately; callers retain no storage
/// lifetime obligation after this call returns.
#[no_mangle]
pub unsafe extern "C" fn openlog(ident: *const c_char, options: c_int, facility: c_int) {
    let Ok(cancellation) = (unsafe { disable_cancellation() }) else {
        return;
    };
    unsafe { lock() };
    if !ident.is_null() {
        let destination = core::ptr::addr_of_mut!(LOG_IDENT).cast::<c_char>();
        let mut length = 0usize;
        while length < IDENT_CAPACITY - 1 && unsafe { ident.add(length).read() } != 0 {
            unsafe { destination.add(length).write(ident.add(length).read()) };
            length += 1;
        }
        unsafe { destination.add(length).write(0) };
    } else {
        unsafe { core::ptr::addr_of_mut!(LOG_IDENT).cast::<c_char>().write(0) };
    }
    unsafe {
        LOG_OPT = options;
        LOG_FACILITY = facility;
        if options & LOG_NDELAY != 0 && LOG_FD < 0 {
            open_connection();
        }
    }
    unsafe { unlock() };
    unsafe { restore_cancellation(cancellation) };
}

/// Musl's private `__vsyslog` state/mask/cancellation transaction.
unsafe fn __vsyslog(priority: c_int, message: *const c_char, args: VaList) {
    if LOG_MASK.load(Ordering::Relaxed) & (1 << (priority & 7)) == 0
        || priority & !LOG_PRIORITY_MASK != 0
    {
        return;
    }
    let Ok(cancellation) = (unsafe { disable_cancellation() }) else {
        return;
    };
    unsafe { lock() };
    unsafe { write_message(priority, message, args) };
    unsafe { unlock() };
    unsafe { restore_cancellation(cancellation) };
}

/// Weak public C spelling for musl's private `__vsyslog` body.
///
/// # Safety
/// The current task is the initialized owned main task or a live selected
/// worker created by this runtime's `pthread_create`, and it is not in a
/// fork/lifecycle transition. A foreign task has no owned cancellation slot;
/// this defensive boundary returns before touching logger state for it.
///
/// `message` is a readable NUL-terminated format string and `args` holds the
/// promoted values and storage required by every selected format conversion.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn vsyslog(priority: c_int, message: *const c_char, args: VaList) {
    unsafe { __vsyslog(priority, message, args) };
}

/// C-variadic front end for the owned syslog transaction.
///
/// # Safety
/// The current task is the initialized owned main task or a live selected
/// worker created by this runtime's `pthread_create`, and it is not in a
/// fork/lifecycle transition. A foreign task has no owned cancellation slot;
/// this defensive boundary returns before touching logger state for it.
///
/// `message` and every promoted variadic argument satisfy the selected
/// `vsnprintf` format contract.  `%m` observes the caller's saved errno.
#[no_mangle]
pub unsafe extern "C" fn syslog(priority: c_int, message: *const c_char, args: ...) {
    unsafe { __vsyslog(priority, message, args) };
}
