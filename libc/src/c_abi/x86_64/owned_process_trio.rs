//! Owned Linux/x86-64 process creation, translated from musl 1.2.6 (MIT),
//! revision 9fa28ece75d8a2191de7c5bb53bed224c5947417:
//! `src/linux/clone.c` -> clone/clone_start, `src/thread/x86_64/clone.s`
//! -> __crabc_owned_clone_raw, `src/process/x86_64/vfork.s` -> vfork,
//! `src/legacy/daemon.c` -> daemon. `_Fork.c::__post_Fork` maps to the
//! process lock and pthread_create_join::clone_child's caller-only identity,
//! robust/list reset. The latter copies caller TSD solely because the owned
//! runtime stores main values separately; it does not reset the key lock.
//!
//! CLONE_VM intentionally bypasses every libc child repair, matching musl's
//! vfork-like restricted execution context. Non-VM clone never runs atfork
//! hooks or the loader/stdio/allocator transactions of full fork. The separate
//! owned raw entry admits the public flag/pointer contract without widening
//! the frozen private clone leaf or selecting these providers in the private
//! archive. Paused AArch64 code is unchanged.

use core::ffi::{c_char, c_int, c_void};
use super::{c_status, owned_process_lock, pthread_create_join, signal_execution};

const CLONE_VM: c_int = 0x100;
const CLONE_PIDFD: c_int = 0x1000;
const CLONE_THREAD: c_int = 0x10000;
const CLONE_SETTLS: c_int = 0x80000;
const CLONE_PARENT_SETTID: c_int = 0x100000;
const CLONE_CHILD_CLEARTID: c_int = 0x200000;
const CLONE_CHILD_SETTID: c_int = 0x1000000;

type CloneFunction = unsafe extern "C" fn(*mut c_void) -> c_int;

unsafe extern "C" {
    fn __crabc_owned_clone_raw(function: Option<CloneFunction>, stack: *mut c_void,
        flags: c_int, argument: *mut c_void, parent_tid: *mut c_int,
        tls: *mut c_void, child_tid: *mut c_int) -> i64;
    fn chdir(path: *const c_char) -> c_int;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn dup2(fd: c_int, target: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

core::arch::global_asm!(r#"
.text
.global __crabc_owned_clone_raw
.hidden __crabc_owned_clone_raw
.type __crabc_owned_clone_raw,@function
__crabc_owned_clone_raw:
    xor eax, eax
    mov al, 56
    mov r11, rdi
    mov rdi, rdx
    mov rdx, r8
    mov r8, r9
    mov r10, qword ptr [rsp + 8]
    mov r9, r11
    and rsi, -16
    sub rsi, 8
    mov qword ptr [rsi], rcx
    syscall
    test eax, eax
    jne 1f
    xor ebp, ebp
    pop rdi
    call r9
    mov edi, eax
    xor eax, eax
    mov al, 60
    syscall
    hlt
1:  ret
.size __crabc_owned_clone_raw, .-__crabc_owned_clone_raw
.global vfork
.type vfork,@function
vfork:
    pop rdx
    mov eax, 58
    syscall
    push rdx
    mov rdi, rax
    jmp __crabc_owned_vfork_result
.size vfork, .-vfork
.hidden __crabc_owned_vfork_result
.section .note.GNU-stack,"",@progbits
"#);

// vfork cannot have a Rust frame spanning syscall58: the child shares and
// may overwrite the parent's stack. The source assembly removes its return
// address before entering Linux, then tail-calls only the errno conversion.
#[no_mangle]
unsafe extern "C" fn __crabc_owned_vfork_result(result: i64) -> c_int { c_status(result) }

struct CloneStart {
    function: Option<CloneFunction>,
    argument: *mut c_void,
    signal_mask: u64,
    caller: pthread_create_join::CloneCaller,
}

unsafe extern "C" fn clone_start(argument: *mut c_void) -> c_int {
    let start = unsafe { &*argument.cast::<CloneStart>() };
    unsafe {
        pthread_create_join::clone_child(start.caller);
        owned_process_lock::pthread_fork_child();
        signal_execution::restore_application_signals(&start.signal_mask);
        (start.function.unwrap_unchecked())(start.argument)
    }
}

/// Create a process on a caller-supplied stack, following musl's public clone.
///
/// # Safety
/// If a child can be created, the callback must be non-null and executable.
/// The stack must designate sufficient writable storage retained until child
/// exit. Optional parent-TID/TLS/child-
/// TID arguments occupy musl's documented slots and obey the Linux flags.
/// CLONE_VM callbacks have vfork's restricted shared-address-space context;
/// they must not mutate libc thread state or return into the caller's frame.
#[no_mangle]
pub unsafe extern "C" fn clone(function: Option<CloneFunction>, stack: *mut c_void,
    flags: c_int, argument: *mut c_void, mut arguments: ...) -> c_int {
    const BAD_FLAGS: c_int = CLONE_THREAD | CLONE_SETTLS | CLONE_CHILD_CLEARTID;
    if stack.is_null() || flags & BAD_FLAGS != 0 { return c_status(-22); }
    let mut parent_tid = core::ptr::null_mut();
    let mut tls = core::ptr::null_mut();
    let mut child_tid = core::ptr::null_mut();
    if flags & (CLONE_PIDFD | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID) != 0 {
        parent_tid = unsafe { arguments.next_arg::<*mut c_int>() };
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        tls = unsafe { arguments.next_arg::<*mut c_void>() };
        child_tid = unsafe { arguments.next_arg::<*mut c_int>() };
    }
    if flags & CLONE_VM != 0 {
        return c_status(unsafe { __crabc_owned_clone_raw(function, stack, flags,
            argument, parent_tid, tls, child_tid) });
    }
    let mut saved = 0;
    unsafe { signal_execution::block_all_signals(&mut saved) };
    let mut start = CloneStart { function, argument, signal_mask: saved,
        caller: unsafe { pthread_create_join::clone_caller() } };
    unsafe { owned_process_lock::pthread_fork_prepare() };
    let result = unsafe { __crabc_owned_clone_raw(Some(clone_start), stack, flags,
        core::ptr::addr_of_mut!(start).cast(), parent_tid, tls, child_tid) };
    unsafe {
        owned_process_lock::pthread_fork_parent();
        signal_execution::restore_application_signals(&saved);
    }
    c_status(result)
}

/// Detach through musl's chdir/descriptor preparation and two ordinary forks.
///
/// # Safety
/// The caller must satisfy fork's child execution obligations. Successful
/// parent branches terminate the process with _exit(0), as daemon requires.
#[no_mangle]
pub unsafe extern "C" fn daemon(nochdir: c_int, noclose: c_int) -> c_int {
    unsafe {
        if nochdir == 0 && chdir(c"/".as_ptr()) != 0 { return -1; }
        if noclose == 0 {
            let fd = open(c"/dev/null".as_ptr(), 2);
            if fd < 0 { return -1; }
            let failed = dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0;
            if fd > 2 { close(fd); }
            if failed { return -1; }
        }
        match super::pthread_atfork::fork() {
            0 => (), -1 => return -1, _ => super::immediate_termination::_Exit(0),
        }
        if super::process_context::setsid() < 0 { return -1; }
        match super::pthread_atfork::fork() {
            0 => (), -1 => return -1, _ => super::immediate_termination::_Exit(0),
        }
    }
    0
}
