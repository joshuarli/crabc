//! Selected static Linux/x86-64 System V message-queue/shared-memory C boundary.
//!
//! This leaf owns a complete, deliberately bounded pair of adjacent System V
//! resource families: `ftok`, `msgget`, `msgsnd`, `msgrcv`, `msgctl`, `shmget`,
//! `shmat`, `shmdt`, and `shmctl`. It composes the existing x86 stat-layout
//! owner, raw Linux/x86-64 syscall register boundary, and selected initial-TLS
//! C `errno` writer. It is not the remaining SysV semaphore leaf, POSIX
//! message queues/shared memory or named/timed semaphores, an IPC namespace or permission
//! policy, a general C/POSIX runtime, libc.so, CRT, dynamic TLS, loader,
//! sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/ipc/ftok.c` maps to [`ftok`] through the sole x86 stat-layout owner.
//! - `src/ipc/msgget.c`, `msgsnd.c`, `msgrcv.c`, and `msgctl.c` map to the
//!   four selected message-queue entries.
//! - `src/ipc/shmget.c`, `shmat.c`, `shmdt.c`, and `shmctl.c` map to the four
//!   selected shared-memory entries.
//! - `src/ipc/ipc.h` and `arch/x86_64/syscall_arch.h` map to
//!   [`ipc_command`]'s target-specific direct-command rule.
//!
//! The owned runtime maps musl's `msgsnd` and `msgrcv` cancellation-point
//! syscalls. The standalone archive retains its direct raw syscall profile.
//! Queue lifetime stays with the caller in both profiles. Linux 5.10 supplies
//! every syscall used here, so this target-specific leaf carries no legacy
//! compatibility fallback.

use core::ffi::{c_char, c_int, c_long, c_void};

use super::{c_pointer_status, c_ssize_status, c_status, raw_syscall, stat_compat};

// `src/ipc/ipc.h` applies IPC_CMD(cmd) to msgctl and shmctl. The x86-64 musl
// syscall architecture overrides IPC_64 to zero, and IPC_STAT has no 0x100
// time64 selector on LP64, so IPC_TIME64 is also zero. Retain the names and
// formula instead of passing a naked command so this exact ABI choice remains
// visible and cannot silently inherit a 32-bit IPC encoding.
const IPC_64: c_int = 0;
const IPC_TIME64: c_int = 0;

#[inline]
const fn ipc_command(command: c_int) -> c_int {
    (command & !IPC_TIME64) | IPC_64
}

/// Derive a System V IPC key from one pathname and low-byte project id.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the duration
/// of the metadata lookup. The filesystem lookup, access checks, and C errno
/// state belong to the caller and Linux.
#[no_mangle]
pub unsafe extern "C" fn ftok(path: *const c_char, project_id: c_int) -> c_int {
    // SAFETY: the public C caller owns the pathname contract and the helper
    // preserves the existing x86 `stat` errno result on failure.
    let (device, inode) = match unsafe { stat_compat::stat_device_and_inode(path) } {
        Some(words) => words,
        None => return -1,
    };

    // Match musl's unsigned masking exactly. A set high project-id byte is a
    // successful negative `key_t`, not a C error result.
    ((inode & 0xffff)
        | ((device & 0xff) << 16)
        | (((project_id as u32 as u64) & 0xff) << 24)) as c_int
}

/// Create or obtain one System V message queue through Linux `msgget(2)`.
///
/// `key` and `flags` are forwarded unchanged; the caller owns namespace,
/// permission, creation-race, and eventual `IPC_RMID` policy.
#[no_mangle]
pub extern "C" fn msgget(key: c_int, flags: c_int) -> c_int {
    // SAFETY: the two scalar C words map directly to Linux x86-64 msgget=68.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MSGGET,
            i64::from(key),
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Send one message through Linux `msgsnd(2)`.
///
/// # Safety
///
/// `message` must designate a readable System V message record whose leading
/// `long` type word and following `length` data bytes remain accessible for
/// Linux. Blocking and signal policy are caller-owned. The owned runtime
/// checks cancellation before Linux observes the message.
#[no_mangle]
pub unsafe extern "C" fn msgsnd(
    queue_id: c_int,
    message: *const c_void,
    length: usize,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller owns the full kernel message-buffer contract. The
    // raw helper moves C's fourth word to Linux x86-64 r10.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_MSGSND,
            i64::from(queue_id),
            message as usize as i64,
            length as i64,
            i64::from(flags),
            0,
            0,
        )
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_MSGSND,
            i64::from(queue_id),
            message as usize as i64,
            length as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Receive one message through Linux `msgrcv(2)`.
///
/// # Safety
///
/// `message` must designate writable System V message-record storage for a
/// leading `long` type plus up to `length` data bytes. The caller owns queue
/// lifetime, selector semantics, blocking, and signal policy. The owned
/// runtime checks cancellation before Linux consumes a queued message.
#[no_mangle]
pub unsafe extern "C" fn msgrcv(
    queue_id: c_int,
    message: *mut c_void,
    length: usize,
    message_type: c_long,
    flags: c_int,
) -> isize {
    // SAFETY: the caller supplies the full writable message-record contract.
    // The raw helper places type and flags in Linux x86-64 r10/r8.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_MSGRCV,
            i64::from(queue_id),
            message as usize as i64,
            length as i64,
            message_type as i64,
            i64::from(flags),
            0,
        )
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_MSGRCV,
            i64::from(queue_id),
            message as usize as i64,
            length as i64,
            message_type as i64,
            i64::from(flags),
        )
    };
    c_ssize_status(result)
}

/// Control one System V message queue through Linux `msgctl(2)`.
///
/// # Safety
///
/// For commands that consume it, `buffer` must designate the exact writable
/// or readable x86 `struct msqid_ds` storage required by Linux for the
/// duration of the call. Commands that do not consume it may use null. The
/// caller owns queue lifetime, permissions, and namespace policy.
#[no_mangle]
pub unsafe extern "C" fn msgctl(
    queue_id: c_int,
    command: c_int,
    buffer: *mut c_void,
) -> c_int {
    let command = ipc_command(command);
    // SAFETY: the caller supplies any command-specific buffer contract; x86
    // msgctl=71 takes its three words in rdi/rsi/rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MSGCTL,
            i64::from(queue_id),
            i64::from(command),
            buffer as usize as i64,
        )
    };
    c_status(result)
}

/// Create or obtain one System V shared-memory segment through `shmget(2)`.
///
/// `key` and `flags` are forwarded unchanged. Match musl's only local range
/// rewrite: x86 LP64 sizes above `PTRDIFF_MAX` become `SIZE_MAX` before Linux
/// sees them; Linux owns the resulting validation and errno state.
#[no_mangle]
pub extern "C" fn shmget(key: c_int, mut size: usize, flags: c_int) -> c_int {
    if size > isize::MAX as usize {
        size = usize::MAX;
    }
    // SAFETY: the three scalar C words map directly to Linux x86-64 shmget=29.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SHMGET,
            i64::from(key),
            size as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Attach one System V shared-memory segment through Linux `shmat(2)`.
///
/// # Safety
///
/// `address` is a caller-owned optional placement hint and must satisfy the
/// selected Linux `shmat` address/flag contract. On any Linux error this
/// returns exactly `(void *)-1` after publishing errno; null is not an error
/// sentinel for this API.
#[no_mangle]
pub unsafe extern "C" fn shmat(
    segment_id: c_int,
    address: *const c_void,
    flags: c_int,
) -> *mut c_void {
    // SAFETY: the caller owns the kernel address/flag contract. The pointer
    // translator recognizes only Linux's -4095..=-1 error range and thereby
    // preserves the required MAP_FAILED all-ones sentinel.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SHMAT,
            i64::from(segment_id),
            address as usize as i64,
            i64::from(flags),
        )
    };
    c_pointer_status(result)
}

/// Detach one previously attached System V shared-memory mapping.
///
/// # Safety
///
/// `address` must be an attachment pointer owned by the caller according to
/// Linux `shmdt(2)`; all mapping lifetime and concurrency policy remain with
/// the caller.
#[no_mangle]
pub unsafe extern "C" fn shmdt(address: *const c_void) -> c_int {
    // SAFETY: the caller owns the attachment-pointer contract for shmdt=67.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_SHMDT, address as usize as i64)
    };
    c_status(result)
}

/// Control one System V shared-memory segment through Linux `shmctl(2)`.
///
/// # Safety
///
/// For commands that consume it, `buffer` must designate the exact writable
/// or readable x86 `struct shmid_ds` storage required by Linux for the call.
/// Commands that do not consume it may use null. Segment lifetime,
/// permissions, and namespace policy remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn shmctl(
    segment_id: c_int,
    command: c_int,
    buffer: *mut c_void,
) -> c_int {
    let command = ipc_command(command);
    // SAFETY: the caller supplies any command-specific buffer contract; x86
    // shmctl=31 takes its three words in rdi/rsi/rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SHMCTL,
            i64::from(segment_id),
            i64::from(command),
            buffer as usize as i64,
        )
    };
    c_status(result)
}
