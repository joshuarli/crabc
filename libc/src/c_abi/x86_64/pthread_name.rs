//! Linux/x86-64 static pthread task names.
//!
//! This implementation follows musl 1.2.6 commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT): names occupy a
//! 16-byte Linux task-comm slot. A selected current task uses `prctl`; another
//! live selected task uses `/proc/self/task/<tid>/comm`. The lifecycle registry
//! validates an opaque pthread handle and pins its target TID until the file
//! operation finishes, so a retiring task cannot expose a reused TID here.
//! Pthread failures are positive return values and leave C `errno` unchanged.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread task-name leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};

use super::{pthread_create_join, pthread_identity, raw_syscall};

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
const COMM_PATH_CAPACITY: usize = 22 + 3 * 4;

/// Keep asynchronous signals out of a target's retirement transaction.
struct BlockedSignals(u64);

impl BlockedSignals {
    fn new() -> Result<Self, c_int> {
        let all = u64::MAX;
        let mut previous = 0;
        // SAFETY: Linux reads an eight-byte mask and writes the previous one.
        let result = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_RT_SIGPROCMASK,
                0,
                (&all as *const u64) as usize as i64,
                (&mut previous as *mut u64) as usize as i64,
                8,
            )
        };
        if result < 0 { Err(pthread_status(result)) } else { Ok(Self(previous)) }
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        // SAFETY: the saved mask came from the same task's successful block.
        let _ = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_RT_SIGPROCMASK,
                2,
                (&self.0 as *const u64) as usize as i64,
                0,
                8,
            )
        };
    }
}

/// Whether an opaque C handle is the current selected main or worker task.
#[inline]
fn is_selected_current_self(thread: *mut c_void) -> bool {
    let current_thread_pointer = pthread_identity::current_thread_pointer();
    !thread.is_null()
        && thread == current_thread_pointer.cast()
        && pthread_create_join::current_selected_runtime_thread_id().is_some()
}

/// Convert a raw Linux result into a positive pthread status without C errno.
#[inline]
fn pthread_status(result: i64) -> c_int {
    if result >= 0 {
        0
    } else if result < 0 && result >= -LINUX_ERRNO_MAX {
        result.wrapping_neg() as c_int
    } else {
        ESRCH
    }
}

/// Check musl's bounded task-comm name precondition and return its length.
///
/// # Safety
///
/// `name` must be readable through its first NUL byte or through all sixteen
/// bytes of Linux's task-comm window. This is the same caller-owned C string
/// validity requirement that musl's bounded `strnlen` observes.
#[inline]
unsafe fn task_comm_name_length(name: *const c_char) -> Result<usize, c_int> {
    for offset in 0..TASK_COMM_LEN {
        // SAFETY: the caller upholds the bounded readable C-string contract.
        if unsafe { name.add(offset).read() } == 0 {
            return Ok(offset);
        }
    }
    Err(ERANGE)
}

/// Run one bounded procfs operation while the selected target cannot retire.
///
/// The lifecycle callback holds the target's retirement lock and a mapping
/// lease through the raw file syscalls. Blocking application signals keeps
/// asynchronous cancellation from abandoning either. A retired or unselected
/// handle never enters the callback.
fn with_live_target(thread: *mut c_void, operation: impl FnOnce(c_int) -> c_int) -> c_int {
    let mask = match BlockedSignals::new() {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    let mut status = ESRCH;
    // SAFETY: signals remain blocked until the target lock and mapping lease
    // are released; the callback runs only raw syscalls and returns normally.
    let _ = unsafe {
        pthread_create_join::with_selected_pthread_signal_target(thread, |_, tid, _| {
            status = operation(tid);
            0
        })
    };
    drop(mask);
    status
}

/// Construct the NUL-terminated Linux task-comm path for a positive TID.
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
    for &byte in b"/proc/self/task/" {
        path[length] = byte;
        length += 1;
    }
    for &digit in digits[..count].iter().rev() {
        path[length] = digit;
        length += 1;
    }
    for &byte in b"/comm\0" {
        path[length] = byte;
        length += 1;
    }
}

/// Open the selected task's comm file with close-on-exec flags.
fn open_comm(tid: c_int, flags: i64) -> Result<i64, c_int> {
    let mut path = [0u8; COMM_PATH_CAPACITY];
    comm_path(tid, &mut path);
    // SAFETY: `path` is a NUL-terminated stack buffer valid for this syscall.
    let fd = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_OPENAT,
            AT_FDCWD,
            path.as_ptr() as usize as i64,
            flags | O_CLOEXEC | O_LARGEFILE,
            0,
        )
    };
    if fd < 0 { Err(pthread_status(fd)) } else { Ok(fd) }
}

/// Close a descriptor owned by the current name operation.
fn close_comm(fd: i64) {
    // SAFETY: the descriptor came from this operation's successful openat.
    let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, fd) };
}

// Keep each exported name function in its own static archive member.
static_archive_member! { pthread_setname_np_source {
    /// Set a selected pthread's Linux task name.
    ///
    /// # Safety
    ///
    /// `name` must be readable through its first NUL byte or sixteen bytes.
    /// `thread` must be a valid selected pthread handle or an invalid opaque
    /// value that can be rejected without dereferencing it.
    #[no_mangle]
    pub unsafe extern "C" fn pthread_setname_np(thread: *mut c_void, name: *const c_char) -> c_int {
        // Musl checks the name before resolving a different target.
        let length = match unsafe { task_comm_name_length(name) } {
            Ok(length) => length,
            Err(error) => return error,
        };
        if is_selected_current_self(thread) {
            // SAFETY: the selected C string remains readable for the raw call.
            return pthread_status(unsafe {
                raw_syscall::syscall5(raw_syscall::SYS_PRCTL, PR_SET_NAME, name as usize as i64, 0, 0, 0)
            });
        }
        with_live_target(thread, |tid| {
            let fd = match open_comm(tid, O_WRONLY) {
                Ok(fd) => fd,
                Err(error) => return error,
            };
            // SAFETY: the bounded prefix was read above; `length` excludes NUL.
            let written = unsafe {
                raw_syscall::syscall3(raw_syscall::SYS_WRITE, fd, name as usize as i64, length as i64)
            };
            close_comm(fd);
            pthread_status(written)
        })
    }
}}

static_archive_member! { pthread_getname_np_source {
    /// Read a selected pthread's Linux task name.
    ///
    /// # Safety
    ///
    /// When `len >= 16`, `name` must designate `len` writable bytes.
    /// `thread` must be a valid selected pthread handle or an invalid opaque
    /// value that can be rejected without dereferencing it.
    #[no_mangle]
    pub unsafe extern "C" fn pthread_getname_np(
        thread: *mut c_void,
        name: *mut c_char,
        len: usize,
    ) -> c_int {
        if len < TASK_COMM_LEN {
            return ERANGE;
        }
        if is_selected_current_self(thread) {
            // SAFETY: the caller owns at least sixteen writable output bytes.
            return pthread_status(unsafe {
                raw_syscall::syscall5(raw_syscall::SYS_PRCTL, PR_GET_NAME, name as usize as i64, 0, 0, 0)
            });
        }
        with_live_target(thread, |tid| {
            let fd = match open_comm(tid, O_RDONLY) {
                Ok(fd) => fd,
                Err(error) => return error,
            };
            // SAFETY: the caller owns `len` writable bytes for the raw read.
            let read = unsafe {
                raw_syscall::syscall3(raw_syscall::SYS_READ, fd, name as usize as i64, len as i64)
            };
            close_comm(fd);
            if read < 0 {
                return pthread_status(read);
            }
            // A live task's comm file ends with a newline, which musl replaces
            // with NUL. No byte is written if the kernel reports no data.
            if read > 0 {
                // SAFETY: `read` bytes were initialized in the caller's output.
                unsafe { name.add(read as usize - 1).write(0) };
            }
            0
        })
    }
}}
