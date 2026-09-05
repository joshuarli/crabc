//! Owned process streams, translated from pinned musl 1.2.6 (MIT), commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417: src/stdio/popen.c, pclose.c,
//! and src/process/system.c. The shared owned_spawn engine now supplies the
//! child/exec/error-pipe transaction used by both shell and public spawn APIs.
//!
//! FILE registry locking spans close-action allocation, spawn, and pipe_pid
//! publication. Allocator diagnostics may use permanent stderr without taking
//! that lock. fclose removes a process stream before pclose's raw child wait.
//! No public atfork callback runs in a spawn child. The common spawn seam
//! owns its cancellation-disabled transaction and process-creation/SIGABRT
//! lock. `system` then uses the public cancellation-point `waitpid`, whereas
//! `pclose` retains musl's raw wait and raw-EINTR retry. As in the source,
//! cancellation during the system wait adds no child kill/reap or signal-state
//! restoration cleanup.

use super::{c_char, c_int, c_void, errno, ptr, raw_syscall as sys, ListGuard,
    StandardStream, OPEN_STREAMS};
use super::super::{owned_spawn, posix_spawn_file_actions::PosixSpawnFileActions as SpawnFileActions,
    posix_spawnattr_init::PosixSpawnAttr};

const CLOEXEC: i64 = 0x80000;
const EINTR: i64 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelSignalAction { handler: usize, flags: u64, restorer: usize, mask: u64 }
const DEFAULT: KernelSignalAction = KernelSignalAction { handler: 0, flags: 0, restorer: 0, mask: 0 };

unsafe extern "C" {
    fn posix_spawn_file_actions_addclose(actions: *mut c_void, fd: c_int) -> c_int;
    fn posix_spawn_file_actions_adddup2(actions: *mut c_void, fd: c_int, target: c_int) -> c_int;
    fn posix_spawn_file_actions_destroy(actions: *mut c_void) -> c_int;
    fn pthread_testcancel();
    static mut __environ: *mut *mut c_char;
}

unsafe fn close(fd: c_int) { unsafe { sys::syscall1(3, fd as i64); } }
unsafe fn mask(how: i64, set: *const u64, old: *mut u64) {
    unsafe {
        let result = sys::syscall4(14, how, set as i64, old as i64, 8);
        if result == 0 && !old.is_null() { *old &= !0x380000000; }
    }
}
unsafe fn disposition(sig: i64, set: *const KernelSignalAction, old: *mut KernelSignalAction) {
    unsafe { sys::syscall4(13, sig, set as i64, old as i64, 8); }
}

unsafe fn spawn(command: *const c_char, actions: *const SpawnFileActions,
    supplied_mask: Option<u64>, reset: u64, pid: *mut c_int) -> c_int {
    unsafe {
        let mut attributes = core::mem::zeroed::<PosixSpawnAttr>();
        attributes.flags = 4;
        attributes.default_signals[0] = reset;
        if let Some(mask) = supplied_mask { attributes.flags |= 8; attributes.signal_mask[0] = mask; }
        let arguments = [c"sh".as_ptr(), c"-c".as_ptr(), command, ptr::null()];
        owned_spawn::spawn(pid, c"/bin/sh".as_ptr(), actions, &attributes, arguments.as_ptr(),
            ptr::read(ptr::addr_of!(__environ)) as *const *const c_char, false)
    }
}

/// Pinned `pclose.c` retries raw __sys_wait4 without publishing EINTR.
unsafe fn wait_process_stream_raw(pid: c_int, status: *mut c_int) -> i64 {
    loop {
        let result = unsafe { sys::syscall4(61, pid as i64, status as i64, 0, 0) };
        if result != -EINTR { return result; }
    }
}

/// Open a shell command's standard output (`r`) or standard input (`w`).
/// # Safety
/// `command` and `mode` are readable NUL-terminated strings. The process
/// environment remains readable and unchanged through child exec. The caller
/// owns the returned FILE and eventually closes/reaps it with pclose.
#[no_mangle]
pub unsafe extern "C" fn popen(command: *const c_char, mode: *const c_char) -> *mut StandardStream {
    unsafe {
        let direction = match *mode as u8 { b'r' => 0, b'w' => 1,
            _ => { errno::set_errno(22); return ptr::null_mut(); } };
        let mut pipes = [-1i32; 2];
        let result = sys::syscall2(293, pipes.as_mut_ptr() as i64, CLOEXEC);
        if result < 0 { errno::set_errno(-result as c_int); return ptr::null_mut(); }
        let stream = super::fdopen(pipes[direction], mode);
        if stream.is_null() { close(pipes[0]); close(pipes[1]); return stream; }
        let mut actions = SpawnFileActions { _pad0: [0; 2], actions: ptr::null_mut(), _pad: [0; 16] };
        let action_pointer = ptr::addr_of_mut!(actions).cast();
        let mut error = 0;
        {
            let _registry = ListGuard::acquire();
            let mut current = OPEN_STREAMS;
            while !current.is_null() {
                if (*current).pipe_pid != 0 {
                    error = posix_spawn_file_actions_addclose(action_pointer, (*current).file_descriptor);
                    if error != 0 { break; }
                }
                current = (*current).next;
            }
            if error == 0 {
                error = posix_spawn_file_actions_adddup2(action_pointer, pipes[1-direction], (1-direction) as c_int);
            }
            let mut pid = 0;
            if error == 0 { error = spawn(command, &actions, None, 0, &mut pid); }
            posix_spawn_file_actions_destroy(action_pointer);
            if error == 0 {
                (*stream).pipe_pid = pid;
                let mut cursor = mode;
                while *cursor != 0 && *cursor as u8 != b'e' { cursor = cursor.add(1); }
                if *cursor == 0 { sys::syscall3(72, pipes[direction] as i64, 2, 0); }
                close(pipes[1-direction]);
                return stream;
            }
        }
        super::fclose(stream);
        close(pipes[1-direction]);
        errno::set_errno(error);
        ptr::null_mut()
    }
}

/// Close a process stream and return its child's encoded wait status.
/// # Safety
/// `stream` is a live popen result, exclusively owned by this call. It is
/// consumed even if closing or waiting fails; no other code may reap its child.
#[no_mangle]
pub unsafe extern "C" fn pclose(stream: *mut StandardStream) -> c_int {
    unsafe {
        let pid = (*stream).pipe_pid;
        super::fclose(stream);
        let mut status = 0;
        let result = wait_process_stream_raw(pid, &mut status);
        if result < 0 { errno::set_errno(-result as c_int); -1 } else { status }
    }
}

/// Execute a shell command and return its encoded wait status.
/// # Safety
/// A non-null command is a readable NUL-terminated string; the process
/// environment remains readable and unchanged through exec. Concurrent SIGINT
/// and SIGQUIT disposition changes require caller coordination, as in musl's
/// save/install/restore system.c algorithm.
#[no_mangle]
pub unsafe extern "C" fn system(command: *const c_char) -> c_int {
    unsafe {
        pthread_testcancel();
        if command.is_null() { return 1; }
        let ignore = KernelSignalAction { handler: 1, ..DEFAULT };
        let mut old_int = DEFAULT;
        let mut old_quit = DEFAULT;
        disposition(2, &ignore, &mut old_int);
        disposition(3, &ignore, &mut old_quit);
        let mut old_mask = 0;
        mask(0, &(1 << 16), &mut old_mask);
        let reset = if old_int.handler != 1 { 1 << 1 } else { 0 }
            | if old_quit.handler != 1 { 1 << 2 } else { 0 };
        let mut pid = 0;
        let error = spawn(command, ptr::null(), Some(old_mask), reset, &mut pid);
        let mut status = -1;
        if error == 0 {
            // Unlike pclose.c, system.c retries the public waitpid boundary.
            // Its EINTR translation remains observable after a later success;
            // a canceled wait bypasses the source's following restorations.
            while super::super::child_reaping::waitpid(pid, &mut status, 0) < 0
                && errno::get_errno() == EINTR as c_int {}
        }
        disposition(2, &old_int, ptr::null_mut());
        disposition(3, &old_quit, ptr::null_mut());
        mask(2, &old_mask, ptr::null_mut());
        if error != 0 { errno::set_errno(error); }
        status
    }
}
