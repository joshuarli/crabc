//! Owned Linux/x86-64 pthread task-name boundary for the installed products.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/thread/pthread_setname_np.c` maps to [`pthread_setname_np`]: a name
//!   longer than 15 bytes is `ERANGE`; the calling thread uses
//!   `prctl(PR_SET_NAME)`; any other thread writes the name to
//!   `/proc/self/task/<tid>/comm`.
//! - `src/thread/pthread_getname_np.c` maps to [`pthread_getname_np`]: a
//!   buffer shorter than 16 bytes is `ERANGE`; the calling thread uses
//!   `prctl(PR_GET_NAME)`; any other thread reads that comm file and replaces
//!   its final byte (the kernel's newline) with NUL.
//!
//! Each failure returns the errno that musl's `prctl`, `open`, `read`, or
//! `write` wrapper would publish, and publishes it too. Musl disables
//! cancellation around its cancellable procfs I/O; the raw syscalls here are
//! not cancellation points, so the observable cancellation state is the same.
//! The target's Linux TID comes from the lifecycle owner under its signal
//! target lock, as for the owned scheduling and signal entries; like musl,
//! the I/O itself runs after that lookup. The frozen allocation-free archive
//! keeps `pthread_name.rs`.

use core::ffi::{c_char, c_int, c_void};

use super::{errno, pthread_create_join, pthread_identity, pthread_signal::AllSignals, raw_syscall};

const ESRCH: c_int = 3;
const ERANGE: c_int = 34;
const LINUX_ERRNO_MAX: i64 = 4_095;
const TASK_COMM_LEN: usize = 16;
const PR_SET_NAME: i64 = 15;
const PR_GET_NAME: i64 = 16;
const AT_FDCWD: i64 = -100;
const O_RDONLY: i64 = 0;
const O_WRONLY: i64 = 1;
const O_CLOEXEC: i64 = 0x8_0000;
const O_LARGEFILE: i64 = 0x8000;
/// `sizeof "/proc/self/task//comm" + 3*sizeof(int)`, musl's path buffer.
const COMM_PATH_CAPACITY: usize = 22 + 3 * 4;

#[inline]
fn raw_error(result: i64) -> Option<c_int> {
    (result < 0 && result >= -LINUX_ERRNO_MAX).then(|| result.wrapping_neg() as c_int)
}

/// Publish and return one musl wrapper error.
#[inline]
fn fail(error: c_int) -> c_int {
    // SAFETY: this C ABI entry owns the calling thread's errno publication.
    unsafe { errno::set_errno(error) };
    error
}

/// The calling thread's `prctl(option, name)` result as musl's `? errno : 0`.
#[inline]
unsafe fn self_prctl(option: i64, name: *mut c_char) -> c_int {
    // SAFETY: Linux/x86-64 prctl=157 receives option/pointer/zero words in
    // rdi/rsi/rdx/r10/r8; the caller owns the 16-byte name buffer.
    let result = unsafe { raw_syscall::syscall5(raw_syscall::SYS_PRCTL, option, name as usize as i64, 0, 0, 0) };
    raw_error(result).map_or(0, fail)
}

/// Resolve a live thread's Linux TID through the lifecycle owner.
unsafe fn target_tid(thread: *mut c_void) -> Result<c_int, c_int> {
    let mask = unsafe { AllSignals::block() }?;
    let mut tid = 0;
    let _ = unsafe {
        pthread_create_join::with_selected_pthread_signal_target(thread, |_, target, _| {
            tid = target;
            0
        })
    };
    drop(mask);
    if tid > 0 { Ok(tid) } else { Err(ESRCH) }
}

/// Format musl's `"/proc/self/task/%d/comm"` into a NUL-terminated buffer.
fn comm_path(tid: c_int, path: &mut [u8; COMM_PATH_CAPACITY]) {
    let mut digits = [0u8; 10];
    let mut count = 0;
    let mut value = tid as u32;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut length = 0;
    let mut push = |byte: u8| {
        path[length] = byte;
        length += 1;
    };
    b"/proc/self/task/".iter().for_each(|&byte| push(byte));
    (0..count).rev().for_each(|index| push(digits[index]));
    b"/comm".iter().for_each(|&byte| push(byte));
    push(0);
}

/// Open one task's comm file as musl's `open(f, flags|O_CLOEXEC)`.
fn open_comm(tid: c_int, flags: i64) -> Result<i64, c_int> {
    let mut path = [0u8; COMM_PATH_CAPACITY];
    comm_path(tid, &mut path);
    // SAFETY: `path` is a NUL-terminated local buffer for the openat call.
    let fd = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_OPENAT,
            AT_FDCWD,
            path.as_ptr() as usize as i64,
            flags | O_CLOEXEC | O_LARGEFILE,
            0,
        )
    };
    raw_error(fd).map_or(Ok(fd), Err)
}

fn close(fd: i64) {
    // SAFETY: `fd` is this call's own descriptor; musl ignores close's result.
    let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, fd) };
}

/// Set a thread's Linux task name.
///
/// # Safety
///
/// `name` must be readable through its first NUL byte or its first sixteen
/// bytes, and `thread` must be a live thread of this process.
#[no_mangle]
pub unsafe extern "C" fn pthread_setname_np(thread: *mut c_void, name: *const c_char) -> c_int {
    let mut length = 0;
    // SAFETY: musl's `strnlen(name, 16)` reads the same bounded prefix.
    while length < TASK_COMM_LEN && unsafe { name.add(length).read() } != 0 {
        length += 1;
    }
    if length > TASK_COMM_LEN - 1 {
        return ERANGE;
    }
    if thread == pthread_identity::current_thread_pointer().cast() {
        return unsafe { self_prctl(PR_SET_NAME, name.cast_mut()) };
    }
    let tid = match unsafe { target_tid(thread) } {
        Ok(tid) => tid,
        Err(error) => return error,
    };
    let fd = match open_comm(tid, O_WRONLY) {
        Ok(fd) => fd,
        Err(error) => return fail(error),
    };
    // SAFETY: `name` has `length` readable bytes, established above.
    let written = unsafe { raw_syscall::syscall3(raw_syscall::SYS_WRITE, fd, name as usize as i64, length as i64) };
    close(fd);
    raw_error(written).map_or(0, fail)
}

/// Read a thread's Linux task name.
///
/// # Safety
///
/// When `len >= 16`, `name` must designate `len` writable bytes, and `thread`
/// must be a live thread of this process.
#[no_mangle]
pub unsafe extern "C" fn pthread_getname_np(thread: *mut c_void, name: *mut c_char, len: usize) -> c_int {
    if len < TASK_COMM_LEN {
        return ERANGE;
    }
    if thread == pthread_identity::current_thread_pointer().cast() {
        return unsafe { self_prctl(PR_GET_NAME, name) };
    }
    let tid = match unsafe { target_tid(thread) } {
        Ok(tid) => tid,
        Err(error) => return error,
    };
    let fd = match open_comm(tid, O_RDONLY) {
        Ok(fd) => fd,
        Err(error) => return fail(error),
    };
    // SAFETY: the caller owns `len` writable bytes at `name`.
    let read = unsafe { raw_syscall::syscall3(raw_syscall::SYS_READ, fd, name as usize as i64, len as i64) };
    close(fd);
    if let Some(error) = raw_error(read) {
        return fail(error);
    }
    // Musl removes the kernel's trailing newline only after a successful read.
    // SAFETY: a comm read returns at least the newline, so `read - 1` is
    // inside the bytes just written.
    if read > 0 {
        unsafe { name.add(read as usize - 1).write(0) };
    }
    0
}
