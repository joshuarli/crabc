//! Owned process streams, translated from pinned musl 1.2.6 (MIT), commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417: src/stdio/popen.c, pclose.c,
//! src/process/system.c and posix_spawn.c. The private spawn seam admits only
//! the close/dup2 actions and signal attributes those three callers require;
//! it is not a partial public posix_spawn implementation.
//!
//! The parent owns action allocations, the error pipe, and child-stack storage.
//! CLONE_VM|CLONE_VFORK suspends that parent until exec or child exit. The child
//! performs raw syscalls only: no allocation, errno writes, FILE locks, TLS
//! mutation, Rust mutable borrow into parent data, or callbacks. It shares VM
//! but not the descriptor table or signal dispositions. FILE registry locking
//! spans action construction, spawn and pipe_pid publication, as in popen.c.
//! Allocator diagnostics may use permanent stderr without taking that lock.
//!
//! Instead of musl's unavailable handler_set cache, the child queries kernel
//! dispositions and resets caught handlers while signals are blocked. Reserved
//! signals 32..34 are ignored when caught. This preserves inherited DFL/IGN
//! behavior without a new signal bookkeeping owner. The runtime's existing
//! concurrent-abort limitation remains: there is no shared __abort_lock.
//! Selected deferred cancellation is disabled around spawn and explicitly
//! checked by system; syscall cancellation remains a separate runtime contract.

use super::{c_char, c_int, c_void, errno, ptr, raw_syscall as sys, ListGuard,
    StandardStream, OPEN_STREAMS};

const CLOEXEC: i64 = 0x80000;
const EINTR: i64 = 4;

#[repr(C)]
struct SpawnFileActions { padding: [c_int; 2], head: *mut DescriptorOperation, tail: [c_int; 16] }
#[repr(C)]
struct DescriptorOperation { next: *mut DescriptorOperation, prev: *mut DescriptorOperation, command: c_int, fd: c_int,
    source: c_int, flags: c_int, mode: u32 }
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelSignalAction { handler: usize, flags: u64, restorer: usize, mask: u64 }
const DEFAULT: KernelSignalAction = KernelSignalAction { handler: 0, flags: 0, restorer: 0, mask: 0 };
const _: () = assert!(core::mem::size_of::<SpawnFileActions>() == 80);
const _: () = assert!(core::mem::offset_of!(SpawnFileActions, head) == 8);
const _: () = assert!(core::mem::size_of::<DescriptorOperation>() == 40);

unsafe extern "C" {
    fn posix_spawn_file_actions_addclose(actions: *mut c_void, fd: c_int) -> c_int;
    fn posix_spawn_file_actions_adddup2(actions: *mut c_void, fd: c_int, target: c_int) -> c_int;
    fn posix_spawn_file_actions_destroy(actions: *mut c_void) -> c_int;
    fn pthread_setcancelstate(state: c_int, old: *mut c_int) -> c_int;
    fn pthread_testcancel();
    static mut __environ: *mut *mut c_char;
    fn __crabc_x86_pthread_clone(function: unsafe extern "C" fn(*mut c_void) -> c_int,
        stack: *mut u8, flags: i32, argument: *mut c_void, parent_tid: *mut c_int,
        tls: *mut c_void, child_tid: *mut c_int) -> i64;
}

struct ShellSpawn {
    pipe: [c_int; 2],
    mask: u64,
    reset: u64,
    actions: *const SpawnFileActions,
    arguments: [*const c_char; 4],
    environment: *mut *mut c_char,
}

unsafe fn close(fd: c_int) { unsafe { sys::syscall1(3, fd as i64); } }
unsafe fn mask(how: i64, set: *const u64, old: *mut u64) {
    unsafe {
        let result = sys::syscall4(14, how, set as i64, old as i64, 8);
        // pthread_sigmask.c filters reserved 32..34 only from returned masks.
        if result == 0 && !old.is_null() { *old &= !0x380000000; }
    }
}
unsafe fn disposition(sig: i64, set: *const KernelSignalAction, old: *mut KernelSignalAction) {
    unsafe { sys::syscall4(13, sig, set as i64, old as i64, 8); }
}

// All arguments and linked records remain immutable and live through the
// vfork interval. No call here may access allocator, stream, or TLS state.
unsafe extern "C" fn child(pointer: *mut c_void) -> c_int {
    unsafe {
        let args = pointer.cast::<ShellSpawn>();
        close((*args).pipe[0]);
        let mut error_fd = (*args).pipe[1];
        for signal in 1..=64 {
            let mut action = DEFAULT;
            if (*args).reset & (1 << (signal - 1)) == 0 {
                disposition(signal, ptr::null(), &mut action);
                if action.handler <= 1 { continue; }
                action = DEFAULT;
                if (32..=34).contains(&signal) { action.handler = 1; }
            }
            disposition(signal, &action, ptr::null_mut());
        }
        let mut result = 0;
        let mut op = if (*args).actions.is_null() { ptr::null_mut() }
            else { (*(*args).actions).head };
        if !op.is_null() { while !(*op).next.is_null() { op = (*op).next; } }
        while !op.is_null() {
            if (*op).fd == error_fd {
                result = sys::syscall1(32, error_fd as i64);
                if result < 0 { break; }
                close(error_fd);
                error_fd = result as c_int;
            }
            if (*op).command == 1 {
                close((*op).fd);
                result = 0;
            } else {
                // Only addclose/adddup2 records can enter this private seam.
                if (*op).source == error_fd { result = -9; break; }
                result = if (*op).source != (*op).fd {
                    sys::syscall2(33, (*op).source as i64, (*op).fd as i64)
                } else {
                    let flags = sys::syscall3(72, (*op).fd as i64, 1, 0);
                    sys::syscall3(72, (*op).fd as i64, 2, flags & !1)
                };
                if result < 0 { break; }
            }
            op = (*op).prev;
        }
        if result >= 0 {
            sys::syscall3(72, error_fd as i64, 2, 1);
            mask(2, ptr::addr_of!((*args).mask), ptr::null_mut());
            result = sys::syscall3(59, c"/bin/sh".as_ptr() as i64,
                ptr::addr_of!((*args).arguments) as i64, (*args).environment as i64);
        }
        let error = (-result) as c_int;
        loop {
            let written = sys::syscall3(1, error_fd as i64, &error as *const c_int as i64, 4);
            if written >= 0 || written == -32 { break; }
        }
        127
    }
}

// Return positive errno, never publish a PID on failure. Main-thread
// cancellation currently has no selected slot; ENOTSUP means no state changed.
unsafe fn spawn(command: *const c_char, actions: *const SpawnFileActions,
    supplied_mask: Option<u64>, reset: u64, pid: *mut c_int) -> c_int {
    unsafe {
        let mut old_cancel = 0;
        let cancellation_changed = pthread_setcancelstate(1, &mut old_cancel) == 0;
        let mut old_mask = 0;
        mask(0, &u64::MAX, &mut old_mask);
        let mut args = ShellSpawn { pipe: [-1; 2], mask: supplied_mask.unwrap_or(old_mask), reset,
            actions, arguments: [c"sh".as_ptr(), c"-c".as_ptr(), command, ptr::null()],
            environment: ptr::read(ptr::addr_of!(__environ)) };
        let mut result = sys::syscall2(293, args.pipe.as_mut_ptr() as i64, CLOEXEC);
        if result == 0 {
            // Same 1024+PATH_MAX child stack and x86 clone entry as musl.
            let mut stack = [0u8; 5120];
            let child_pid = __crabc_x86_pthread_clone(child, stack.as_mut_ptr().add(stack.len()),
                0x100 | 0x4000 | 17, ptr::addr_of_mut!(args).cast(),
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            close(args.pipe[1]);
            result = child_pid;
            if child_pid > 0 {
                let mut error = 0i32;
                let read = sys::syscall3(0, args.pipe[0] as i64, &mut error as *mut c_int as i64, 4);
                if read == 4 {
                    let mut status = 0;
                    wait(child_pid as c_int, &mut status);
                    result = -(error as i64);
                } else {
                    ptr::write(pid, child_pid as c_int);
                    result = 0;
                }
            }
            close(args.pipe[0]);
        }
        mask(2, &old_mask, ptr::null_mut());
        if cancellation_changed { pthread_setcancelstate(old_cancel, ptr::null_mut()); }
        (-result) as c_int
    }
}

unsafe fn wait(pid: c_int, status: *mut c_int) -> i64 {
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
        let mut actions = SpawnFileActions { padding: [0; 2], head: ptr::null_mut(), tail: [0; 16] };
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
        let result = wait(pid, &mut status);
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
            let result = wait(pid, &mut status);
            if result < 0 { errno::set_errno(-result as c_int); status = -1; }
        }
        disposition(2, &old_int, ptr::null_mut());
        disposition(3, &old_quit, ptr::null_mut());
        mask(2, &old_mask, ptr::null_mut());
        if error != 0 { errno::set_errno(error); }
        status
    }
}
