//! Bounded Linux/x86-64 static `pthread_create`/`pthread_join` worker leaf.
//!
//! This is a deliberately private first lifecycle slice, not an x86 pthread
//! runtime. Its allocation, clone flag selection, child-stack handoff, and
//! join-after-`CLONE_CHILD_CLEARTID` ordering are source-mapped to pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under
//! musl's MIT license:
//!
//! - `src/thread/pthread_create.c::__pthread_create` supplies the exact
//!   Linux thread clone flags and the `EAGAIN` translation for allocation or
//!   clone failure.
//! - `src/thread/x86_64/clone.s::__clone` supplies the seven-argument SysV
//!   entry layout, `clone=56` register shuffle, aligned child-stack callback,
//!   and `exit=60` tail. The assembly below is a lexical private-symbol rename
//!   of that source.
//! - `src/thread/pthread_join.c` supplies the essential wait-before-reclaim
//!   ordering: a joiner waits for `CLONE_CHILD_CLEARTID` to clear the worker
//!   TID before it releases worker-owned memory.
//!
//! The admitted contract is exactly one default-attribute, joinable worker:
//! `pthread_create(NULL)`, a normal returning start routine, and one
//! `pthread_join`. The child gets a distinct zeroed instance of this target's
//! sole initial-TLS datum, `errno`, and returns one opaque pointer. The leaf
//! intentionally does **not** provide attrs, detach, `pthread_exit`,
//! cancellation, keys/TSD, synchronization objects, dynamic TLS/DTV, loader
//! TLS, signal-mask coordination, thread lists, fork/atfork, custom stacks,
//! guards, or general pthread semantics. It leaves caller `errno` untouched
//! because pthread APIs report errors as positive return values.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread create/join leaf requires little-endian Linux/x86-64");

use core::arch::asm;
use core::ffi::{c_int, c_void};
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

use super::{errno, raw_syscall};

const EAGAIN: c_int = 11;
const EINTR: c_int = 4;
const EINVAL: c_int = 22;
const ENOTSUP: c_int = 95;
const LINUX_ERRNO_MAX: i64 = 4_095;

const PROT_READ_WRITE: i64 = 0x3;
const MAP_PRIVATE_ANONYMOUS: i64 = 0x22;
const FUTEX_WAIT: i64 = 0;

const CLONE_VM: i32 = 0x0000_0100;
const CLONE_FS: i32 = 0x0000_0200;
const CLONE_FILES: i32 = 0x0000_0400;
const CLONE_SIGHAND: i32 = 0x0000_0800;
const CLONE_THREAD: i32 = 0x0001_0000;
const CLONE_SYSVSEM: i32 = 0x0004_0000;
const CLONE_SETTLS: i32 = 0x0008_0000;
const CLONE_PARENT_SETTID: i32 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: i32 = 0x0020_0000;
const CLONE_DETACHED: i32 = 0x0040_0000;
const PTHREAD_CLONE_FLAGS: i32 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_DETACHED;

// Keep control, the one admitted initial-TLS image, and worker stack in one
// private page-aligned anonymous mapping. The stack grows down from its top;
// its low address remains above the TLS image and cannot overwrite it during
// the selected normal worker path.
const CONTROL_REGION_SIZE: usize = 4_096;
const INITIAL_TLS_REGION_SIZE: usize = 4_096;
const WORKER_STACK_SIZE: usize = 1_024 * 1_024;
const WORKER_MAPPING_SIZE: usize =
    CONTROL_REGION_SIZE + INITIAL_TLS_REGION_SIZE + WORKER_STACK_SIZE;

type StartRoutine = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

/// One opaque pthread handle for the admitted lifecycle.
///
/// The handle has no public Rust representation. C observes it only through
/// its opaque `pthread_t` pointer and may not retain it after a successful
/// join, exactly when this leaf unmaps the backing storage.
#[repr(C)]
struct ThreadControl {
    // Linux writes this word on parent clone return, then clears/wakes it at
    // child exit through CLONE_CHILD_CLEARTID. It therefore must retain the
    // exact four-byte futex representation for the mapping's full lifetime.
    child_tid: AtomicI32,
    // One joiner claims a still-live handle before waiting. It is private
    // coordination only; repeated/concurrent joining is outside this slice.
    join_claimed: AtomicU8,
    // A returning child publishes its callback result before `finished`.
    result: AtomicUsize,
    // This release/acquire handoff makes result visibility explicit rather
    // than relying on the kernel clear-tid write to synchronize a different
    // user-space atomic object.
    finished: AtomicU8,
    mapping: *mut u8,
    mapping_size: usize,
    start: StartRoutine,
    argument: *mut c_void,
}

const _: () = {
    assert!(size_of::<AtomicI32>() == size_of::<c_int>());
    assert!(align_of::<AtomicI32>() == align_of::<c_int>());
    assert!(size_of::<ThreadControl>() <= CONTROL_REGION_SIZE);
    assert!(WORKER_MAPPING_SIZE % CONTROL_REGION_SIZE == 0);
};

unsafe extern "C" {
    fn __crabc_x86_pthread_clone(
        function: unsafe extern "C" fn(*mut c_void) -> c_int,
        stack: *mut u8,
        flags: i32,
        argument: *mut c_void,
        parent_tid: *mut c_int,
        tls: *mut c_void,
        child_tid: *mut c_int,
    ) -> i64;
}

core::arch::global_asm!(
    r#"
    .text
    .global __crabc_x86_pthread_clone
    .hidden __crabc_x86_pthread_clone
    .type __crabc_x86_pthread_clone,@function
__crabc_x86_pthread_clone:
    // Fixed musl 1.2.6 x86_64 clone.s algorithm, under a private symbol.
    xor eax, eax
    mov al, 56
    mov r11, rdi
    // SysV inputs are fn=rdi, stack=rsi, flags=rdx, arg=rcx, ptid=r8,
    // tls=r9, ctid=[rsp+8]. Linux clone then receives
    // flags=rdi, stack=rsi, ptid=rdx, ctid=r10, tls=r8.
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
1:
    ret
    .size __crabc_x86_pthread_clone, .-__crabc_x86_pthread_clone
    .section .note.GNU-stack,"",@progbits
"#
);

#[inline]
fn is_linux_error(result: i64) -> bool {
    result < 0 && result >= -LINUX_ERRNO_MAX
}

#[inline]
fn positive_linux_error(result: i64) -> c_int {
    result.wrapping_neg() as c_int
}

/// Return the current initial-TLS `errno` offset below the x86 thread pointer.
///
/// A normal x86 static executable has `ERRNO` in the executable initial TLS
/// image at a negative TPOFF. This leaf refuses a layout outside its private
/// one-page image instead of guessing a DTV or general TLS template.
fn initial_errno_offset() -> Option<usize> {
    let thread_pointer: usize;
    // SAFETY: this selected static artifact requires an established x86
    // initial TLS base whose self word is readable at %fs:0. Its test-only
    // entry shim establishes that precondition before calling C code.
    unsafe {
        asm!(
            "mov {thread_pointer}, fs:[0]",
            thread_pointer = out(reg) thread_pointer,
            options(readonly, nostack, preserves_flags),
        );
    }
    let errno_location = unsafe { errno::__errno_location() as usize };
    let offset = thread_pointer.checked_sub(errno_location)?;
    if offset < size_of::<c_int>()
        || offset % align_of::<c_int>() != 0
        || offset > INITIAL_TLS_REGION_SIZE - size_of::<c_int>()
    {
        return None;
    }
    Some(offset)
}

/// Map one control/TLS/stack backing range without translating `errno`.
unsafe fn map_worker() -> *mut u8 {
    // SAFETY: this fixed anonymous mapping has no caller pointers. The raw
    // syscall result stays private so pthread_create can return EAGAIN without
    // mutating the creator's C errno slot.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_MMAP,
            0,
            WORKER_MAPPING_SIZE as i64,
            PROT_READ_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            -1,
            0,
        )
    };
    if is_linux_error(result) || result == 0 {
        core::ptr::null_mut()
    } else {
        result as usize as *mut u8
    }
}

/// Release one completed worker mapping without translating `errno`.
unsafe fn unmap_worker(mapping: *mut u8, mapping_size: usize) -> i64 {
    // SAFETY: the caller proves that no child can still access this exact
    // range, through a zero child TID after CLONE_CHILD_CLEARTID.
    unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MUNMAP,
            mapping as usize as i64,
            mapping_size as i64,
        )
    }
}

/// Run the one selected C callback, then publish its result before exit.
unsafe extern "C" fn worker_entry(opaque: *mut c_void) -> c_int {
    let control = opaque.cast::<ThreadControl>();
    // SAFETY: pthread_create initialized this private record before clone;
    // the child owns the callback invocation and parent only reads result
    // after `finished` is published and the child has exited.
    let result = unsafe { ((*control).start)((*control).argument) };
    // SAFETY: this is the sole child writer and the mapping remains live until
    // pthread_join observes the child TID cleared by the kernel.
    unsafe {
        (*control).result.store(result as usize, Ordering::Relaxed);
        (*control).finished.store(1, Ordering::Release);
    }
    0
}

/// Create one default-attribute, joinable x86 worker with a private errno TLS image.
///
/// `thread` must designate writable `pthread_t` storage; `start` must be a
/// valid C function pointer and `argument` must remain valid until that
/// function stops reading it. Only a null `attributes` pointer is admitted.
/// The caller must execute under the selected static initial-TLS setup.
///
/// # Safety
///
/// This C ABI boundary cannot validate the output pointer, callback code, or
/// callback argument lifetime. A callback must return normally; calling an
/// unsupported thread-exit path leaves this bounded lifecycle outside contract.
#[no_mangle]
pub unsafe extern "C" fn pthread_create(
    thread: *mut *mut c_void,
    attributes: *const c_void,
    start: Option<StartRoutine>,
    argument: *mut c_void,
) -> c_int {
    if thread.is_null() || start.is_none() {
        return EINVAL;
    }
    if !attributes.is_null() {
        return ENOTSUP;
    }
    let start = match start {
        Some(start) => start,
        None => return EINVAL,
    };
    let errno_offset = match initial_errno_offset() {
        Some(offset) => offset,
        None => return ENOTSUP,
    };
    let mapping = unsafe { map_worker() };
    if mapping.is_null() {
        return EAGAIN;
    }

    let control = mapping.cast::<ThreadControl>();
    let child_thread_pointer = unsafe { mapping.add(CONTROL_REGION_SIZE + INITIAL_TLS_REGION_SIZE) };
    let child_errno = match (child_thread_pointer as usize).checked_sub(errno_offset) {
        Some(address) => address as *mut c_int,
        None => {
            let _ = unsafe { unmap_worker(mapping, WORKER_MAPPING_SIZE) };
            return ENOTSUP;
        }
    };
    let stack_top = unsafe { mapping.add(WORKER_MAPPING_SIZE) };

    // SAFETY: mmap returned a private page-aligned zeroed allocation of the
    // exact fixed size. These two values establish the minimal Variant-II
    // image needed by the sole `ERRNO` initial-TLS datum and opaque %fs:0
    // identity; no general TLS template or DTV is implied.
    unsafe {
        core::ptr::write(child_errno, 0);
        core::ptr::write(child_thread_pointer.cast::<usize>(), child_thread_pointer as usize);
        core::ptr::write(
            control,
            ThreadControl {
                child_tid: AtomicI32::new(0),
                join_claimed: AtomicU8::new(0),
                result: AtomicUsize::new(0),
                finished: AtomicU8::new(0),
                mapping,
                mapping_size: WORKER_MAPPING_SIZE,
                start,
                argument,
            },
        );
    }
    let child_tid = unsafe { core::ptr::addr_of_mut!((*control).child_tid).cast::<c_int>() };
    // SAFETY: the private clone seam uses musl's exact x86 argument shuffle.
    // The mapping supplies a writable child stack, live control record, and
    // zeroed initial TLS image through the child's normal-return exit.
    let clone_result = unsafe {
        __crabc_x86_pthread_clone(
            worker_entry,
            stack_top,
            PTHREAD_CLONE_FLAGS,
            control.cast(),
            child_tid,
            child_thread_pointer.cast(),
            child_tid,
        )
    };
    if is_linux_error(clone_result) {
        let _ = unsafe { unmap_worker(mapping, WORKER_MAPPING_SIZE) };
        // Musl intentionally translates every clone failure to EAGAIN.
        return EAGAIN;
    }

    // SAFETY: clone succeeded, so its opaque record stays live until the one
    // admitted join reclaims the mapping. Publish only after full setup.
    unsafe { core::ptr::write(thread, control.cast()) };
    0
}

/// Join one normal-returning worker created by [`pthread_create`].
///
/// `thread` must be the still-live opaque result of this leaf's
/// `pthread_create`; `result` may be null or writable pointer-result storage.
/// No caller may use `thread` after a successful return because its backing
/// mapping has been released.
///
/// # Safety
///
/// The opaque handle and optional result storage must meet those lifetime and
/// alignment requirements. The caller must not concurrently join the same
/// handle; such broader pthread behavior is deliberately outside this slice.
#[no_mangle]
pub unsafe extern "C" fn pthread_join(thread: *mut c_void, result: *mut *mut c_void) -> c_int {
    if thread.is_null() {
        return EINVAL;
    }
    let control = thread.cast::<ThreadControl>();
    // SAFETY: the caller promises a live handle. This claim keeps a second
    // joiner from racing the only unmap in the admitted lifecycle.
    let claim = unsafe {
        (*control)
            .join_claimed
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
    };
    if claim.is_err() {
        return EINVAL;
    }

    loop {
        // SAFETY: the handle remains mapped until this joining caller either
        // releases its claim on an error or successfully unmaps it below.
        let child_tid = unsafe { (*control).child_tid.load(Ordering::Acquire) };
        if child_tid == 0 {
            break;
        }
        if child_tid < 0 {
            unsafe { (*control).join_claimed.store(0, Ordering::Release) };
            return EINVAL;
        }
        // CLONE_CHILD_CLEARTID wakes this shared (not FUTEX_PRIVATE) word as
        // the last kernel action on normal child exit. EAGAIN and EINTR only
        // request another load; no C errno translation is selected here.
        let wait_result = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FUTEX,
                core::ptr::addr_of_mut!((*control).child_tid).cast::<c_int>() as usize as i64,
                FUTEX_WAIT,
                i64::from(child_tid),
                0,
            )
        };
        if is_linux_error(wait_result) {
            let error = positive_linux_error(wait_result);
            if error == EAGAIN || error == EINTR {
                continue;
            }
            unsafe { (*control).join_claimed.store(0, Ordering::Release) };
            return error;
        }
    }

    // A normal returning worker publishes `finished` after its result before
    // its assembly tail invokes exit. The acquire pairs with that release;
    // it avoids treating the kernel's clear-tid write as a Rust memory-order
    // edge for the separate result word.
    while unsafe { (*control).finished.load(Ordering::Acquire) } == 0 {
        core::hint::spin_loop();
    }
    let worker_result = unsafe { (*control).result.load(Ordering::Relaxed) as *mut c_void };
    let mapping = unsafe { (*control).mapping };
    let mapping_size = unsafe { (*control).mapping_size };
    let unmap_result = unsafe { unmap_worker(mapping, mapping_size) };
    if is_linux_error(unmap_result) {
        // An unexpected munmap failure leaves the handle live; permit a retry
        // instead of claiming successful join/reclamation.
        unsafe { (*control).join_claimed.store(0, Ordering::Release) };
        return positive_linux_error(unmap_result);
    }
    if !result.is_null() {
        // SAFETY: the caller gave writable pointer-result storage and the
        // local copy survives the just-completed worker mapping release.
        unsafe { core::ptr::write(result, worker_result) };
    }
    0
}
