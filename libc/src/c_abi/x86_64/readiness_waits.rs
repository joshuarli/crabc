//! Selected static Linux/x86-64 C readiness and signal-wait boundary.
//!
//! This leaf owns one coherent, bounded native C wait block: descriptor
//! readiness through `poll`, GNU `ppoll`, `select`, and `pselect`, plus the
//! closely related signal-interrupt waits `pause` and `sigsuspend`. It composes
//! only the raw Linux syscall register boundary and the selected initial-TLS C
//! `errno` writer. It is not epoll/eventfd support, a socket API, C
//! open/path/fcntl or vector-I/O support, AIO, a general signal-delivery or
//! signal-wait framework, pthread cancellation or mask policy, timers, C
//! process lifecycle APIs, a general C/POSIX runtime, libc.so, CRT,
//! pthread/TLS lifecycle, dynamic TLS, loader, sysroot, allocator, or public
//! x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/select/poll.c`, `src/select/ppoll.c`, `src/select/select.c`, and
//!   `src/select/pselect.c` map to the correspondingly named wrappers below.
//! - `src/unistd/pause.c` and `src/signal/sigsuspend.c` map to the two
//!   signal-interrupt wait wrappers below.
//!
//! Musl routes every one of those waits through cancellation-point machinery.
//! That machinery, including pthread cancellation state and signal-mask
//! coordination, remains deliberately outside this selected static boundary.
//! The wrappers here issue the direct Linux syscalls instead. They retain the
//! source-specific public-timeout copies: `ppoll` and `pselect` copy a public
//! const `timespec` into private two-word storage, while `select` validates and
//! normalizes a public `timeval` into private storage before Linux may mutate
//! it. This means all three public timeout records remain caller-resident,
//! matching musl instead of exposing the raw kernel's mutable timeout
//! behavior. Linux 5.10 supplies every selected syscall, so no pre-baseline
//! fallback is selected.

use core::ffi::{c_int, c_long, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

const EINVAL: i64 = 22;
const KERNEL_SIGSET_SIZE: usize = size_of::<u64>();
const MICROSECONDS_PER_SECOND: c_long = 1_000_000;
const MAX_TIME: c_long = i64::MAX;

/// Exact x86 public `struct pollfd` storage.
///
/// It is private Rust ABI machinery only; the public C entry point receives
/// an opaque pointer so it cannot accidentally establish a Rust polling API.
#[repr(C)]
struct PollFd {
    file_descriptor: c_int,
    events: i16,
    returned_events: i16,
}

/// Exact x86 public `fd_set` storage.
#[repr(C)]
struct FdSet {
    words: [u64; 16],
}

/// Exact x86 public `struct timeval` storage.
#[repr(C)]
struct Timeval {
    seconds: c_long,
    microseconds: c_long,
}

/// Exact x86 public `struct timespec` storage.
#[repr(C)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

/// Exact x86 public `sigset_t` storage.
///
/// Linux consumes only the first machine word for these syscalls. The public
/// tail stays wholly caller-resident, as it does in the selected signal-control
/// leaf.
#[repr(C)]
struct PublicSigSet {
    words: [u64; 16],
}

/// Linux x86 `pselect6`'s private pointer/size pair.
#[repr(C)]
struct PselectMaskArgument {
    mask: *const c_void,
    size: usize,
}

const _: () = {
    assert!(size_of::<PollFd>() == 8);
    assert!(align_of::<PollFd>() == 4);
    assert!(offset_of!(PollFd, file_descriptor) == 0);
    assert!(offset_of!(PollFd, events) == 4);
    assert!(offset_of!(PollFd, returned_events) == 6);

    assert!(size_of::<FdSet>() == 128);
    assert!(align_of::<FdSet>() == 8);
    assert!(size_of::<Timeval>() == 16);
    assert!(align_of::<Timeval>() == 8);
    assert!(offset_of!(Timeval, seconds) == 0);
    assert!(offset_of!(Timeval, microseconds) == 8);
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(offset_of!(Timespec, seconds) == 0);
    assert!(offset_of!(Timespec, nanoseconds) == 8);
    assert!(size_of::<PublicSigSet>() == 128);
    assert!(align_of::<PublicSigSet>() == 8);
    assert!(size_of::<PselectMaskArgument>() == 16);
    assert!(align_of::<PselectMaskArgument>() == 8);
    assert!(offset_of!(PselectMaskArgument, mask) == 0);
    assert!(offset_of!(PselectMaskArgument, size) == 8);
};

/// Wait for events on a public x86 `pollfd` array through Linux `poll(2)`.
///
/// # Safety
///
/// `file_descriptors` must be null only when `count` is zero; otherwise it
/// must designate `count` readable-and-writable eight-byte public `pollfd`
/// records for the syscall's duration. The caller owns descriptor lifetimes,
/// concurrent readiness consumption, and interruption policy. This direct
/// static leaf does not provide musl's pthread cancellation-point behavior.
#[no_mangle]
pub unsafe extern "C" fn poll(
    file_descriptors: *mut c_void,
    count: usize,
    timeout_milliseconds: c_int,
) -> c_int {
    // SAFETY: the caller owns the complete Linux poll-array contract. The
    // scalar count and timeout retain their x86 C ABI words exactly.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_POLL,
            file_descriptors as usize as i64,
            count as i64,
            i64::from(timeout_milliseconds),
        )
    };
    c_status(result)
}

/// Wait for events with an optional temporary signal mask through `ppoll(2)`.
///
/// # Safety
///
/// `file_descriptors` follows [`poll`]'s array contract. `timeout` must be
/// null or point to one readable public x86 `timespec`; `mask` must be null or
/// cover its first readable kernel-visible eight-byte word of a public x86
/// `sigset_t`. Every pointer must remain live for the syscall. The caller owns
/// temporary-mask and signal-delivery policy. Unlike musl, this direct leaf is
/// not a pthread cancellation point.
#[no_mangle]
pub unsafe extern "C" fn ppoll(
    file_descriptors: *mut c_void,
    count: usize,
    timeout: *const c_void,
    mask: *const c_void,
) -> c_int {
    let mut timeout_storage = if timeout.is_null() {
        None
    } else {
        // Musl copies the public const record before entering Linux. An
        // unaligned raw read preserves the C pointer boundary without making
        // a Rust reference to caller memory.
        // SAFETY: the caller gives one readable public timespec.
        Some(unsafe { core::ptr::read_unaligned(timeout.cast::<Timespec>()) })
    };
    let timeout_pointer = match timeout_storage.as_mut() {
        Some(storage) => storage as *mut Timespec as usize as i64,
        None => 0,
    };
    // SAFETY: all pointer and signal-mask semantics remain with the C caller;
    // Linux uses x86 r10/r8 for the timeout/mask fourth and fifth words.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_PPOLL,
            file_descriptors as usize as i64,
            count as i64,
            timeout_pointer,
            mask as usize as i64,
            KERNEL_SIGSET_SIZE as i64,
        )
    };
    c_status(result)
}

/// Wait for descriptor-set readiness through Linux `select(2)`.
///
/// This retains musl's non-kernel validation and normalization of an optional
/// public `timeval`. It passes a private two-word timeval to Linux, so neither
/// a successful wait nor an interrupted raw syscall can update the caller's
/// public timeout record.
///
/// # Safety
///
/// Each descriptor-set pointer must be null or point to writable storage for
/// one complete x86 public `fd_set`; `timeout` must be null or point to one
/// readable public x86 `timeval`. The records must remain live for the syscall
/// and satisfy the C `restrict`/descriptor-range requirements for `count`.
/// The caller owns descriptor lifetime and signal interruption policy. This
/// direct static leaf does not provide musl's pthread cancellation behavior.
#[no_mangle]
pub unsafe extern "C" fn select(
    count: c_int,
    readable: *mut c_void,
    writable: *mut c_void,
    exceptional: *mut c_void,
    timeout: *mut c_void,
) -> c_int {
    let mut timeout_storage = Timeval {
        seconds: 0,
        microseconds: 0,
    };
    let timeout_pointer = if timeout.is_null() {
        0
    } else {
        // SAFETY: the caller supplies one readable public timeval. Preserve
        // musl's local copy before its explicit negative-value validation.
        let requested = unsafe { core::ptr::read_unaligned(timeout.cast::<Timeval>()) };
        if requested.seconds < 0 || requested.microseconds < 0 {
            return c_status(-EINVAL);
        }

        // This is the direct x86 `SYS_select` branch of musl's source: carry
        // whole microseconds into seconds, saturating the public time_t range
        // before a signed addition could overflow.
        if requested.microseconds / MICROSECONDS_PER_SECOND > MAX_TIME - requested.seconds {
            timeout_storage.seconds = MAX_TIME;
            timeout_storage.microseconds = MICROSECONDS_PER_SECOND - 1;
        } else {
            timeout_storage.seconds =
                requested.seconds + requested.microseconds / MICROSECONDS_PER_SECOND;
            timeout_storage.microseconds = requested.microseconds % MICROSECONDS_PER_SECOND;
        }
        &mut timeout_storage as *mut Timeval as usize as i64
    };

    // SAFETY: the caller owns all descriptor-set extents and syscall-visible
    // storage. Linux takes its fourth and fifth arguments in x86 r10/r8.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_SELECT,
            i64::from(count),
            readable as usize as i64,
            writable as usize as i64,
            exceptional as usize as i64,
            timeout_pointer,
        )
    };
    c_status(result)
}

/// Wait for descriptor-set readiness with an optional temporary mask through
/// Linux `pselect6(2)`.
///
/// # Safety
///
/// The descriptor-set pointers follow [`select`]'s requirements. `timeout`
/// must be null or point to one readable public x86 `timespec`; `mask` must
/// be null or cover its first readable kernel-visible eight-byte word of a
/// public x86 `sigset_t`. All arguments must remain live for the syscall; the
/// caller owns temporary-mask, descriptor, and interruption policy. This
/// direct static leaf does not provide musl's pthread cancellation behavior.
#[no_mangle]
pub unsafe extern "C" fn pselect(
    count: c_int,
    readable: *mut c_void,
    writable: *mut c_void,
    exceptional: *mut c_void,
    timeout: *const c_void,
    mask: *const c_void,
) -> c_int {
    let mut timeout_storage = if timeout.is_null() {
        None
    } else {
        // SAFETY: the caller gives one readable public timespec. As in musl,
        // Linux can mutate only this private copy.
        Some(unsafe { core::ptr::read_unaligned(timeout.cast::<Timespec>()) })
    };
    let timeout_pointer = match timeout_storage.as_mut() {
        Some(storage) => storage as *mut Timespec as usize as i64,
        None => 0,
    };
    let mask_argument = PselectMaskArgument {
        mask,
        size: KERNEL_SIGSET_SIZE,
    };
    // SAFETY: the caller owns the public record and descriptor-set contracts;
    // this local pair has the Linux `pselect6` pointer/size ABI in x86 r9.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_PSELECT6,
            i64::from(count),
            readable as usize as i64,
            writable as usize as i64,
            exceptional as usize as i64,
            timeout_pointer,
            &mask_argument as *const PselectMaskArgument as usize as i64,
        )
    };
    c_status(result)
}

/// Suspend the calling thread until Linux interrupts it with a handled signal.
///
/// The usual `pause(2)` lost-wakeup race remains the caller's signal-policy
/// responsibility. This direct static leaf is deliberately not musl's pthread
/// cancellation point.
#[no_mangle]
pub extern "C" fn pause() -> c_int {
    // SAFETY: pause has no user arguments and Linux owns all wait state.
    let result = unsafe { raw_syscall::syscall0(raw_syscall::SYS_PAUSE) };
    c_status(result)
}

/// Atomically replace the calling mask and wait through `rt_sigsuspend(2)`.
///
/// # Safety
///
/// `mask` must cover its first readable kernel-visible eight-byte word of one
/// public x86 `sigset_t` and remain live until Linux returns. The caller owns
/// temporary-mask and signal-handler lifetime policy. This direct static leaf
/// does not provide musl's pthread cancellation behavior.
#[no_mangle]
pub unsafe extern "C" fn sigsuspend(mask: *const c_void) -> c_int {
    // SAFETY: Linux consumes one x86 kernel signal-set word from the caller's
    // public record and owns the atomic mask swap/restore transition.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_RT_SIGSUSPEND,
            mask as usize as i64,
            KERNEL_SIGSET_SIZE as i64,
        )
    };
    c_status(result)
}
