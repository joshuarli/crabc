//! Owned Linux/x86-64 process-wide credential setters.
//!
//! Linux credential syscalls change only the calling task, while POSIX and
//! musl make `setuid`-family changes process-wide. Translation provenance is
//! pinned musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license:
//!
//! - `src/unistd/setxid.c::{do_setxid,__setxid}` runs one three-argument
//!   credential syscall on every thread through `__synccall` (see
//!   `owned_synccall.rs`). The context result starts at 1 so the first
//!   thread's failure is simply reported; a failure after another thread has
//!   succeeded kills the process with `SIGKILL`, because its credentials would
//!   be inconsistent. An aborted rendezvous leaves 1, reported as `EAGAIN`.
//! - `src/linux/setgroups.c` applies the same protocol to `setgroups`, but
//!   reports its context result unchanged (so an aborted rendezvous returns
//!   1, exactly as musl's `__syscall_ret(c.ret)` does).
//! - `src/unistd/{setuid,setgid,seteuid,setegid,setreuid,setregid,
//!   setresuid,setresgid}.c` select the syscall and argument words:
//!   `seteuid`/`setegid` are `setresuid`/`setresgid` with the real and saved
//!   IDs unchanged (`-1`).
//!
//! The frozen private archive keeps its separate calling-task
//! `credentials.rs` profile.

use core::ffi::{c_int, c_uint, c_void};
use core::sync::atomic::{AtomicI32, Ordering};

use super::{c_status, owned_synccall, raw_syscall};

// Linux/x86-64 `setreuid`/`setregid`; the shared raw table does not name
// them, and only this leaf needs them.
const SYS_SETREUID: i64 = 113;
const SYS_SETREGID: i64 = 114;
const EAGAIN: i64 = 11;

/// Musl `setxid.c`'s `struct ctx`.
///
/// Threads reach `ret` one at a time, ordered by the rendezvous semaphores;
/// it is atomic only so the shared context needs no `&mut` alias.
struct SetxidContext {
    number: i64,
    id: i64,
    effective_id: i64,
    saved_id: i64,
    ret: AtomicI32,
}

unsafe fn do_setxid(context: *mut c_void) {
    // SAFETY: `__setxid` passes its live context for the rendezvous.
    let context = unsafe { &*context.cast::<SetxidContext>() };
    let previous = context.ret.load(Ordering::Acquire);
    if previous < 0 {
        return;
    }
    // SAFETY: a scalar Linux credential syscall; its result is 0 or -errno.
    let ret = unsafe {
        raw_syscall::syscall3(context.number, context.id, context.effective_id, context.saved_id)
    } as c_int;
    if ret != 0 && previous == 0 {
        owned_synccall::kill_process_after_partial_transition();
    }
    context.ret.store(ret, Ordering::Release);
}

/// Musl `__setxid`: one credential syscall on every thread.
fn setxid(number: i64, id: c_int, effective_id: c_int, saved_id: c_int) -> c_int {
    let context = SetxidContext {
        number,
        id: i64::from(id),
        effective_id: i64::from(effective_id),
        saved_id: i64::from(saved_id),
        ret: AtomicI32::new(1),
    };
    // SAFETY: `do_setxid` issues only raw syscalls, and the context outlives
    // the rendezvous.
    unsafe {
        owned_synccall::synccall(do_setxid, core::ptr::addr_of!(context).cast_mut().cast())
    };
    let ret = context.ret.load(Ordering::Acquire);
    c_status(if ret > 0 { -EAGAIN } else { i64::from(ret) })
}

/// Musl `setgroups.c`'s `struct ctx`.
struct SetgroupsContext {
    count: usize,
    list: *const c_uint,
    ret: AtomicI32,
}

unsafe fn do_setgroups(context: *mut c_void) {
    // SAFETY: `setgroups` passes its live context for the rendezvous.
    let context = unsafe { &*context.cast::<SetgroupsContext>() };
    let previous = context.ret.load(Ordering::Acquire);
    if previous < 0 {
        return;
    }
    // SAFETY: the C caller's list obligation covers every thread's syscall.
    let ret = unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_SETGROUPS, context.count as i64, context.list as i64)
    } as c_int;
    if ret != 0 && previous == 0 {
        owned_synccall::kill_process_after_partial_transition();
    }
    context.ret.store(ret, Ordering::Release);
}

/// Replace every thread's supplementary-group list.
///
/// # Safety
///
/// If `count` is nonzero, `groups` must point to `count` readable `gid_t`
/// words until return. A failure on one thread after another has changed
/// its groups kills the process, as in musl.
#[no_mangle]
pub unsafe extern "C" fn setgroups(count: usize, groups: *const c_uint) -> c_int {
    let context = SetgroupsContext { count, list: groups, ret: AtomicI32::new(1) };
    // SAFETY: `do_setgroups` issues only a raw syscall over the caller's
    // list, and the context outlives the rendezvous.
    unsafe {
        owned_synccall::synccall(do_setgroups, core::ptr::addr_of!(context).cast_mut().cast())
    };
    c_status(i64::from(context.ret.load(Ordering::Acquire)))
}

/// Set every thread's user IDs through Linux `setuid(2)`.
///
/// # Safety
///
/// Scalar C ABI entry; see the module contract for partial-failure behavior.
#[no_mangle]
pub unsafe extern "C" fn setuid(user_id: c_uint) -> c_int {
    setxid(raw_syscall::SYS_SETUID, user_id as c_int, 0, 0)
}

/// Set every thread's group IDs through Linux `setgid(2)`.
///
/// # Safety
///
/// Scalar C ABI entry; see the module contract for partial-failure behavior.
#[no_mangle]
pub unsafe extern "C" fn setgid(group_id: c_uint) -> c_int {
    setxid(raw_syscall::SYS_SETGID, group_id as c_int, 0, 0)
}

/// Set every thread's effective user ID (`setresuid(-1, euid, -1)`).
///
/// # Safety
///
/// Scalar C ABI entry; see the module contract for partial-failure behavior.
#[no_mangle]
pub unsafe extern "C" fn seteuid(effective_user_id: c_uint) -> c_int {
    setxid(raw_syscall::SYS_SETRESUID, -1, effective_user_id as c_int, -1)
}

/// Set every thread's effective group ID (`setresgid(-1, egid, -1)`).
///
/// # Safety
///
/// Scalar C ABI entry; see the module contract for partial-failure behavior.
#[no_mangle]
pub unsafe extern "C" fn setegid(effective_group_id: c_uint) -> c_int {
    setxid(raw_syscall::SYS_SETRESGID, -1, effective_group_id as c_int, -1)
}

/// Set every thread's real and effective user IDs through `setreuid(2)`.
///
/// # Safety
///
/// Scalar C ABI entry; all-ones means unchanged.
#[no_mangle]
pub unsafe extern "C" fn setreuid(real_user_id: c_uint, effective_user_id: c_uint) -> c_int {
    setxid(SYS_SETREUID, real_user_id as c_int, effective_user_id as c_int, 0)
}

/// Set every thread's real and effective group IDs through `setregid(2)`.
///
/// # Safety
///
/// Scalar C ABI entry; all-ones means unchanged.
#[no_mangle]
pub unsafe extern "C" fn setregid(real_group_id: c_uint, effective_group_id: c_uint) -> c_int {
    setxid(SYS_SETREGID, real_group_id as c_int, effective_group_id as c_int, 0)
}

/// Set every thread's real, effective, and saved user IDs.
///
/// # Safety
///
/// Scalar C ABI entry; all-ones means unchanged.
#[no_mangle]
pub unsafe extern "C" fn setresuid(
    real_user_id: c_uint,
    effective_user_id: c_uint,
    saved_user_id: c_uint,
) -> c_int {
    setxid(
        raw_syscall::SYS_SETRESUID,
        real_user_id as c_int,
        effective_user_id as c_int,
        saved_user_id as c_int,
    )
}

/// Set every thread's real, effective, and saved group IDs.
///
/// # Safety
///
/// Scalar C ABI entry; all-ones means unchanged.
#[no_mangle]
pub unsafe extern "C" fn setresgid(
    real_group_id: c_uint,
    effective_group_id: c_uint,
    saved_group_id: c_uint,
) -> c_int {
    setxid(
        raw_syscall::SYS_SETRESGID,
        real_group_id as c_int,
        effective_group_id as c_int,
        saved_group_id as c_int,
    )
}
