//! Selected static Linux/x86-64 event-descriptor C boundary.
//!
//! This leaf owns one coherent, bounded C event-descriptor block:
//! `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`,
//! `epoll_pwait`, `eventfd`, `eventfd_read`, `eventfd_write`,
//! `inotify_init`, `inotify_init1`, `inotify_add_watch`, and
//! `inotify_rm_watch`. It composes only the raw Linux/x86-64 syscall register
//! boundary and selected initial-TLS C `errno` writer. It is not a general
//! readiness policy, fanotify, timerfd, AIO, a watcher service, C open/path
//! policy, a general C/POSIX runtime, libc.so, CRT, pthread/TLS lifecycle,
//! dynamic TLS, loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/epoll.c` maps to the selected epoll wrappers below.
//! - `src/linux/eventfd.c` maps to the selected eventfd wrappers below.
//! - `src/linux/inotify.c` maps to the selected inotify wrappers below.
//!
//! Musl routes blocking epoll waits and eventfd transfers through
//! cancellation-point machinery. That pthread lifecycle is deliberately
//! outside this direct static archive, so the wrappers issue their Linux 5.10
//! syscalls directly. `epoll_wait` is the null-mask `epoll_pwait` form and
//! every `epoll_pwait` call passes the kernel's one-word, eight-byte signal
//! mask size rather than the public 128-byte `sigset_t` capacity.
//! Linux 5.10 provides every selected modern syscall, so unlike musl's wider
//! portability path this leaf deliberately has no pre-baseline `ENOSYS`
//! fallback.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;
const EVENTFD_RECORD_SIZE: usize = size_of::<u64>();
const KERNEL_SIGSET_SIZE: usize = size_of::<u64>();

/// Exact packed Linux/x86-64 `struct epoll_event` storage.
///
/// The public x86 header deliberately packs the data union at byte four. This
/// private record is passed only as an opaque pointer to Linux, so no Rust
/// code forms an unaligned reference to `data`.
#[repr(C, packed)]
struct EpollEvent {
    events: c_uint,
    data: u64,
}

const _: () = {
    assert!(size_of::<EpollEvent>() == 12);
    assert!(align_of::<EpollEvent>() == 1);
    assert!(offset_of!(EpollEvent, events) == 0);
    assert!(offset_of!(EpollEvent, data) == 4);
    assert!(EVENTFD_RECORD_SIZE == 8);
    assert!(KERNEL_SIGSET_SIZE == 8);
};

#[inline]
fn invalid_argument() -> c_int {
    // SAFETY: this selected C ABI leaf owns the calling initial-TLS errno
    // slot and publishes the source-specific local EINVAL result.
    unsafe { errno::set_errno(EINVAL) };
    -1
}

/// Create an epoll descriptor through the modern Linux `epoll_create1(2)`
/// syscall.
///
/// Musl preserves the historical positive-size validation even though Linux
/// ignores the old `epoll_create` size word and this Linux 5.10 target uses
/// `epoll_create1(0)` directly.
#[no_mangle]
pub extern "C" fn epoll_create(size: c_int) -> c_int {
    if size <= 0 {
        return invalid_argument();
    }

    // SAFETY: the zero flag word is the selected modern epoll_create form.
    let result = unsafe { raw_syscall::syscall1(raw_syscall::SYS_EPOLL_CREATE1, 0) };
    c_status(result)
}

/// Create an epoll descriptor through Linux `epoll_create1(2)`.
#[no_mangle]
pub extern "C" fn epoll_create1(flags: c_int) -> c_int {
    // SAFETY: Linux validates the scalar creation-flag word.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_EPOLL_CREATE1, i64::from(flags))
    };
    c_status(result)
}

/// Add, modify, or remove a descriptor in one epoll interest list.
///
/// # Safety
///
/// For add/modify operations, `event` must be null only when Linux permits it
/// and otherwise point to one readable packed public x86 `epoll_event` for
/// the syscall duration. Descriptor and operation lifetimes remain caller
/// policy.
#[no_mangle]
pub unsafe extern "C" fn epoll_ctl(
    epoll_descriptor: c_int,
    operation: c_int,
    descriptor: c_int,
    event: *mut c_void,
) -> c_int {
    // SAFETY: the caller owns the optional packed event-record contract. The
    // raw helper moves C's fourth word to Linux x86-64 r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_EPOLL_CTL,
            i64::from(epoll_descriptor),
            i64::from(operation),
            i64::from(descriptor),
            event as usize as i64,
        )
    };
    c_status(result)
}

#[inline(always)]
unsafe fn epoll_pwait_raw(
    epoll_descriptor: c_int,
    events: *mut c_void,
    maximum_events: c_int,
    timeout_milliseconds: c_int,
    signal_mask: *const c_void,
) -> c_int {
    // SAFETY: the caller owns the writable packed event array and optional
    // public signal-mask lifetime. Linux consumes only the first one-word
    // kernel mask and the helper moves arguments four through six into
    // r10/r8/r9 respectively.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_EPOLL_PWAIT,
            i64::from(epoll_descriptor),
            events as usize as i64,
            i64::from(maximum_events),
            i64::from(timeout_milliseconds),
            signal_mask as usize as i64,
            KERNEL_SIGSET_SIZE as i64,
        )
    };
    c_status(result)
}

/// Wait for one or more epoll events without changing the signal mask.
///
/// # Safety
///
/// `events` must designate writable storage for `maximum_events` packed x86
/// public `epoll_event` records for the syscall duration. This direct static
/// leaf deliberately omits musl's pthread cancellation-point behavior.
#[no_mangle]
pub unsafe extern "C" fn epoll_wait(
    epoll_descriptor: c_int,
    events: *mut c_void,
    maximum_events: c_int,
    timeout_milliseconds: c_int,
) -> c_int {
    // SAFETY: the public event-array contract is documented on this entry;
    // a null signal mask selects the ordinary epoll_wait behavior.
    unsafe {
        epoll_pwait_raw(
            epoll_descriptor,
            events,
            maximum_events,
            timeout_milliseconds,
            core::ptr::null(),
        )
    }
}

/// Wait for epoll events while Linux temporarily installs one signal mask.
///
/// # Safety
///
/// `events` follows [`epoll_wait`]'s writable-array contract. `signal_mask`
/// must be null or point to a readable public x86 `sigset_t`; Linux consumes
/// only its first eight-byte kernel-visible word. The caller owns temporary
/// mask and signal-delivery policy. This direct leaf is not a pthread
/// cancellation point.
#[no_mangle]
pub unsafe extern "C" fn epoll_pwait(
    epoll_descriptor: c_int,
    events: *mut c_void,
    maximum_events: c_int,
    timeout_milliseconds: c_int,
    signal_mask: *const c_void,
) -> c_int {
    // SAFETY: the caller owns the event and optional signal-mask contracts.
    unsafe {
        epoll_pwait_raw(
            epoll_descriptor,
            events,
            maximum_events,
            timeout_milliseconds,
            signal_mask,
        )
    }
}

/// Create an event counter descriptor through Linux `eventfd2(2)`.
#[no_mangle]
pub extern "C" fn eventfd(initial_value: c_uint, flags: c_int) -> c_int {
    // SAFETY: both eventfd arguments are scalar Linux words.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_EVENTFD2,
            i64::from(initial_value),
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Read exactly one eight-byte eventfd counter record.
///
/// # Safety
///
/// `value` must designate writable, aligned `eventfd_t` storage for the call.
/// Blocking and descriptor lifetime remain caller policy. This direct static
/// leaf deliberately omits musl's pthread cancellation-point behavior.
#[no_mangle]
pub unsafe extern "C" fn eventfd_read(fd: c_int, value: *mut u64) -> c_int {
    // SAFETY: the caller supplies writable eight-byte eventfd storage.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_READ,
            i64::from(fd),
            value as usize as i64,
            EVENTFD_RECORD_SIZE as i64,
        )
    };
    if c_status(result) == EVENTFD_RECORD_SIZE as c_int {
        0
    } else {
        // Match musl: an impossible positive short transfer is failure but
        // does not manufacture errno. A raw Linux error has already reached
        // the selected initial-TLS errno boundary through `c_status`.
        -1
    }
}

/// Write exactly one eight-byte eventfd counter record.
///
/// Blocking and descriptor lifetime remain caller policy. This direct static
/// leaf deliberately omits musl's pthread cancellation-point behavior.
#[no_mangle]
pub extern "C" fn eventfd_write(fd: c_int, value: u64) -> c_int {
    // SAFETY: the local scalar stays live and readable for the syscall.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_WRITE,
            i64::from(fd),
            (&value as *const u64) as usize as i64,
            EVENTFD_RECORD_SIZE as i64,
        )
    };
    if c_status(result) == EVENTFD_RECORD_SIZE as c_int {
        0
    } else {
        // See `eventfd_read`: preserve a possible positive short transfer's
        // existing errno state rather than publishing a synthetic EINVAL.
        -1
    }
}

/// Create one inotify descriptor with default flags.
#[no_mangle]
pub extern "C" fn inotify_init() -> c_int {
    // SAFETY: this is the modern inotify_init1 zero-flag form on Linux 5.10.
    let result = unsafe { raw_syscall::syscall1(raw_syscall::SYS_INOTIFY_INIT1, 0) };
    c_status(result)
}

/// Create one inotify descriptor through Linux `inotify_init1(2)`.
#[no_mangle]
pub extern "C" fn inotify_init1(flags: c_int) -> c_int {
    // SAFETY: Linux validates the scalar flag word.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_INOTIFY_INIT1, i64::from(flags))
    };
    c_status(result)
}

/// Add or update an inotify watch for one NUL-terminated pathname.
///
/// # Safety
///
/// `path` must designate a readable NUL-terminated pathname for the Linux
/// syscall duration. Namespace, descriptor, watch, and filesystem policy
/// remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn inotify_add_watch(
    fd: c_int,
    path: *const c_char,
    mask: c_uint,
) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_INOTIFY_ADD_WATCH,
            i64::from(fd),
            path as usize as i64,
            i64::from(mask),
        )
    };
    c_status(result)
}

/// Remove one inotify watch from an open descriptor.
#[no_mangle]
pub extern "C" fn inotify_rm_watch(fd: c_int, watch_descriptor: c_int) -> c_int {
    // SAFETY: both words are scalar Linux values; Linux validates ownership.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_INOTIFY_RM_WATCH,
            i64::from(fd),
            i64::from(watch_descriptor),
        )
    };
    c_status(result)
}
