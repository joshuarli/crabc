//! Owned posix_spawn/posix_spawnp and the common shell-process child seam.
//! Source: musl 1.2.6 (MIT), 9fa28ece75d8a2191de7c5bb53bed224c5947417,
//! src/process/{posix_spawn,posix_spawnp}.c; process_exec_path.rs retains the
//! shared execvp.c PATH algorithm. Existing action/attribute owners supply the
//! exact initialized public records; this module does not invent their layout.
//!
//! The parent blocks signals, holds the shared process-creation lock, and owns
//! the CLOEXEC error pipe and child stack. CLONE_VM|CLONE_VFORK suspends only
//! that parent until exec/exit. The child performs private Rust scalar work and
//! raw syscalls, never libc errno/TLS, allocator, loader, FILE, or user callbacks.
//! An explicit result slot carries source errno effects back to the parent.
//! Failure reaps the child and consumes no caller PID/descriptor ownership.
//!
//! Disposition queries replace musl's unavailable handler_set cache. All caught
//! handlers are reset before unmasking; inherited DFL/IGN are preserved except
//! explicit SETSIGDEF. Scheduling attribute flags retain pinned musl's no-op
//! behavior; USEVFORK likewise changes nothing because this source always uses
//! vfork-style clone. Deferred cancellation is masked during spawn; blocked-
//! syscall cancellation remains owned by the separate pthread runtime.

use core::{ffi::{c_char, c_int, c_void}, ptr};
use super::{environment, errno, owned_process_lock::ProcessGuard,
    posix_spawn_file_actions::{PosixSpawnFileActions, FdOp},
    posix_spawnattr_init::PosixSpawnAttr, process_exec_path, raw_syscall as sys};

const RESET_IDS: c_int = 1;
const SET_PGROUP: c_int = 2;
const SET_SIGDEF: c_int = 4;
const SET_SIGMASK: c_int = 8;
const SET_SESSION: c_int = 128;
const CLOEXEC: i64 = 0x80000;

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelSignalAction { handler: usize, flags: u64, restorer: usize, mask: u64 }
const DEFAULT: KernelSignalAction = KernelSignalAction { handler: 0, flags: 0, restorer: 0, mask: 0 };

struct SpawnArguments {
    pipe: [c_int; 2], mask: u64, defaults: u64, flags: c_int, process_group: c_int,
    path: *const c_char, actions: *const PosixSpawnFileActions,
    arguments: *const *const c_char, environment: *const *const c_char,
    search_path: bool, inherited_path: *const c_char, exec_errno: c_int,
}

unsafe extern "C" {
    fn pthread_setcancelstate(state: c_int, old: *mut c_int) -> c_int;
    fn __crabc_x86_pthread_clone(function: unsafe extern "C" fn(*mut c_void) -> c_int,
        stack: *mut u8, flags: i32, argument: *mut c_void, parent_tid: *mut c_int,
        tls: *mut c_void, child_tid: *mut c_int) -> i64;
}
unsafe fn close(fd: c_int) { unsafe { sys::syscall1(3, fd as i64); } }
unsafe fn signal_mask(how: i64, set: *const u64, old: *mut u64) -> i64 {
    unsafe {
        let result = sys::syscall4(14, how, set as i64, old as i64, 8);
        if result == 0 && !old.is_null() { *old &= !0x380000000; }
        result
    }
}
unsafe fn disposition(signal: i64, set: *const KernelSignalAction, old: *mut KernelSignalAction) {
    unsafe { sys::syscall4(13, signal, set as i64, old as i64, 8); }
}

// The only mutation of shared args is exec_errno. No Rust reference to args
// spans that write or any exec, and the parent is suspended for the interval.
unsafe fn child_exec(args: *mut SpawnArguments, error_fd: &mut c_int) -> i64 {
    unsafe {
        for signal in 1..=64 {
            let mut action = DEFAULT;
            if (*args).defaults & (1 << (signal-1)) == 0 {
                disposition(signal, ptr::null(), &mut action);
                if action.handler <= 1 { continue; }
                action = DEFAULT;
                if (32..=34).contains(&signal) { action.handler = 1; }
            }
            disposition(signal, &action, ptr::null_mut());
        }
        if (*args).flags & SET_SESSION != 0 {
            let result = sys::syscall0(112);
            if result < 0 { return result; }
        }
        if (*args).flags & SET_PGROUP != 0 {
            let result = sys::syscall2(109, 0, (*args).process_group as i64);
            if result != 0 { return result; }
        }
        if (*args).flags & RESET_IDS != 0 {
            let result = sys::syscall1(106, sys::syscall0(104));
            if result != 0 { return result; }
            let result = sys::syscall1(105, sys::syscall0(102));
            if result != 0 { return result; }
        }
        let mut op = if (*args).actions.is_null() { ptr::null_mut() }
            else { (*(*args).actions).actions.cast::<FdOp>() };
        if !op.is_null() { while !(*op).next.is_null() { op = (*op).next; } }
        while !op.is_null() {
            if (*op).fd == *error_fd {
                let result = sys::syscall1(32, *error_fd as i64);
                if result < 0 { return result; }
                close(*error_fd); *error_fd = result as c_int;
            }
            let result = match (*op).cmd {
                1 => { close((*op).fd); 0 }
                2 => {
                    if (*op).srcfd == *error_fd { return -9; }
                    if (*op).srcfd != (*op).fd { sys::syscall2(33, (*op).srcfd as i64, (*op).fd as i64) }
                    else {
                        let flags = sys::syscall3(72, (*op).fd as i64, 1, 0);
                        sys::syscall3(72, (*op).fd as i64, 2, flags & !1)
                    }
                }
                3 => {
                    // fdop's flexible pathname begins at byte 36, not its
                    // padded sizeof(40), matching the allocating owner.
                    let fd = sys::syscall3(2, op.cast::<u8>().add(36) as i64,
                        (*op).oflag as i64, (*op).mode as i64);
                    if fd < 0 { return fd; }
                    if fd != (*op).fd as i64 {
                        let result = sys::syscall2(33, fd, (*op).fd as i64);
                        if result < 0 { return result; }
                        close(fd as c_int);
                    }
                    0
                }
                4 => sys::syscall1(80, op.cast::<u8>().add(36) as i64),
                5 => sys::syscall1(81, (*op).fd as i64),
                _ => 0, // Only the existing initialized action owner writes cmd.
            };
            if result < 0 { return result; }
            op = (*op).prev;
        }
        sys::syscall3(72, *error_fd as i64, 2, 1);
        signal_mask(2, ptr::addr_of!((*args).mask), ptr::null_mut());
        if (*args).search_path {
            process_exec_path::execvpe_raw((*args).path, (*args).arguments,
                (*args).environment, (*args).inherited_path, ptr::addr_of_mut!((*args).exec_errno))
        } else {
            let result = sys::syscall3(59, (*args).path as i64, (*args).arguments as i64, (*args).environment as i64);
            if result < 0 { ptr::addr_of_mut!((*args).exec_errno).write(-result as c_int); }
            result
        }
    }
}

unsafe extern "C" fn child(pointer: *mut c_void) -> c_int {
    unsafe {
        let args = pointer.cast::<SpawnArguments>();
        close((*args).pipe[0]);
        let mut error_fd = (*args).pipe[1];
        let error = -child_exec(args, &mut error_fd) as c_int;
        if error != 0 {
            loop {
                let result = sys::syscall3(1, error_fd as i64, &error as *const c_int as i64, 4);
                if result >= 0 || result == -32 { break; }
            }
        }
        127 // private clone trampoline exits this task with raw SYS_exit.
    }
}

pub(super) unsafe fn spawn(pid: *mut c_int, path: *const c_char,
    actions: *const PosixSpawnFileActions, attributes: *const PosixSpawnAttr,
    arguments: *const *const c_char, environment_pointer: *const *const c_char,
    search_path: bool) -> c_int {
    unsafe {
        let mut old_cancel = 0;
        let cancellation_changed = pthread_setcancelstate(1, &mut old_cancel) == 0;
        let mut old_mask = 0;
        let masked = signal_mask(0, &u64::MAX, &mut old_mask);
        if masked < 0 {
            if cancellation_changed { pthread_setcancelstate(old_cancel, ptr::null_mut()); }
            return -masked as c_int;
        }
        let attributes = if attributes.is_null() { core::mem::zeroed::<PosixSpawnAttr>() }
            else { attributes.read() };
        let mut args = SpawnArguments { pipe: [-1; 2],
            mask: if attributes.flags & SET_SIGMASK != 0 { attributes.signal_mask[0] } else { old_mask },
            defaults: if attributes.flags & SET_SIGDEF != 0 { attributes.default_signals[0] } else { 0 },
            flags: attributes.flags, process_group: attributes.process_group, path, actions,
            arguments, environment: environment_pointer, search_path,
            inherited_path: if search_path { environment::getenv(c"PATH".as_ptr()) } else { ptr::null() },
            exec_errno: 0 };
        let creation = ProcessGuard::acquire_blocked();
        let mut result = sys::syscall2(293, args.pipe.as_mut_ptr() as i64, CLOEXEC);
        if result == 0 {
            let mut stack = [0u8; 5120];
            let child_pid = __crabc_x86_pthread_clone(child, stack.as_mut_ptr().add(stack.len()),
                0x100 | 0x4000 | 17, ptr::addr_of_mut!(args).cast(),
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            close(args.pipe[1]);
            drop(creation);
            if args.exec_errno != 0 { errno::set_errno(args.exec_errno); }
            result = child_pid;
            if child_pid > 0 {
                let mut error = 0i32;
                let read = sys::syscall3(0, args.pipe[0] as i64, &mut error as *mut c_int as i64, 4);
                if read == 4 {
                    let mut status = 0;
                    while sys::syscall4(61, child_pid, &mut status as *mut c_int as i64, 0, 0) == -4 {}
                    result = -(error as i64);
                } else {
                    if !pid.is_null() { pid.write(child_pid as c_int); }
                    result = 0;
                }
            }
            close(args.pipe[0]);
        } else {
            drop(creation);
            errno::set_errno(-result as c_int); // source pipe2 error translation
        }
        signal_mask(2, &old_mask, ptr::null_mut());
        if cancellation_changed { pthread_setcancelstate(old_cancel, ptr::null_mut()); }
        -result as c_int
    }
}

/// Start an image with caller-supplied arguments/environment and spawn records.
/// # Safety
/// Path is readable NUL-terminated storage; argv/envp are readable terminated
/// pointer vectors naming valid C strings through exec. Non-null actions and
/// attributes are live initialized records, not concurrently modified. PID is
/// null or writable int storage, disjoint from all inputs; it is written only
/// on success. The successful caller owns reaping that child.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn(pid: *mut c_int, path: *const c_char,
    actions: *const c_void, attributes: *const c_void,
    arguments: *const *const c_char, environment: *const *const c_char) -> c_int {
    unsafe { spawn(pid, path, actions.cast(), attributes.cast(), arguments, environment, false) }
}

/// Spawn after searching the calling process's PATH (not the supplied envp).
/// # Safety
/// Obligations are those of posix_spawn; the inherited environment/PATH must
/// additionally remain readable and unchanged through the child exec attempt.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnp(pid: *mut c_int, file: *const c_char,
    actions: *const c_void, attributes: *const c_void,
    arguments: *const *const c_char, environment: *const *const c_char) -> c_int {
    unsafe { spawn(pid, file, actions.cast(), attributes.cast(), arguments, environment, true) }
}
