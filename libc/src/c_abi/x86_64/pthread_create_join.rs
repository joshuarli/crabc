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
//! - `src/thread/pthread_create.c::__pthread_exit` supplies the selected
//!   result-before-thread-exit ordering. Its cleanup, TSD, signal, robust-list,
//!   thread-list, detach, and last-thread paths remain explicitly unselected.
//! - `src/thread/x86_64/clone.s::__clone` supplies the seven-argument SysV
//!   entry layout, `clone=56` register shuffle, aligned child-stack callback,
//!   and `exit=60` tail. The assembly below is a lexical private-symbol rename
//!   of that source.
//! - `src/thread/pthread_join.c` supplies the essential wait-before-reclaim
//!   ordering: a joiner waits for `CLONE_CHILD_CLEARTID` to clear the worker
//!   TID before it releases worker-owned memory.
//!
//! The admitted contract is exactly one default-attribute, joinable worker:
//! `pthread_create(NULL)`, a normal returning start routine or selected-worker
//! `pthread_exit`, and one `pthread_join`. The child gets a distinct zeroed
//! instance of this target's sole initial-TLS datum, `errno`, and returns one
//! opaque pointer. The private registry serializes identity scan/result
//! publication with join withdrawal, and validates `%fs:0`, Linux `gettid`,
//! and the still-live child-TID word so a foreign thread cannot turn a copied
//! TLS base into a control-record write after task-ID reuse. It is intentionally
//! neither signal-safe nor reentrant. The
//! leaf intentionally does **not** provide attrs, detach,
//! `pthread_exit` cleanup/TSD/main-thread behavior, cancellation, keys/TSD,
//! synchronization objects, dynamic TLS/DTV, loader TLS, signal-mask
//! coordination, thread lists, fork/atfork, custom stacks, guards, or general
//! pthread semantics. It leaves caller `errno` untouched because pthread APIs
//! report errors as positive return values. At most 64 selected workers may be
//! live concurrently; exhausting this artifact-local admission registry
//! returns `EAGAIN` rather than constructing broader lifecycle state.

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
// This is deliberately a fixed private admission registry, not a general
// pthread thread list. It validates the one selected explicit-exit route
// before it dereferences any control record and bounds concurrently live
// workers in this artifact to a small, auditable number.
const SELECTED_WORKER_REGISTRY_SIZE: usize = 64;
const SELECTED_WORKER_REGISTRY_RESERVING: usize = usize::MAX;

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
    // A selected child publishes its callback result before `finished`.
    result: AtomicUsize,
    // This release/acquire handoff makes result visibility explicit rather
    // than relying on the kernel clear-tid write to synchronize a different
    // user-space atomic object.
    finished: AtomicU8,
    // The selected child publishes its kernel task ID before the callback can
    // call pthread_exit. Matching it alongside `%fs:0` prevents a foreign
    // thread from impersonating a live worker merely by installing its TLS
    // base.
    worker_tid: AtomicI32,
    // Once join withdraws this mapping from the registry, a retry after an
    // unexpected munmap failure must not republish it. The retired mapping is
    // still safe to reclaim because pthread_exit can no longer find it.
    registry_retired: AtomicU8,
    mapping: *mut u8,
    mapping_size: usize,
    registry_slot: usize,
    start: StartRoutine,
    argument: *mut c_void,
}

struct SelectedWorkerRegistrySlot {
    // Zero means free; the transient all-ones state is owned by pthread_create
    // while it initializes the control record before making it visible to a
    // possible child. A nonzero ordinary pointer identifies one live mapping.
    control: AtomicUsize,
    // This is the child Variant-II thread pointer, not a general thread ID.
    // pthread_exit pairs it with worker_tid and the live child-TID word before
    // using the paired control pointer.
    thread_pointer: AtomicUsize,
}

impl SelectedWorkerRegistrySlot {
    const fn empty() -> Self {
        Self {
            control: AtomicUsize::new(0),
            thread_pointer: AtomicUsize::new(0),
        }
    }
}

static SELECTED_WORKER_REGISTRY: [SelectedWorkerRegistrySlot; SELECTED_WORKER_REGISTRY_SIZE] =
    [const { SelectedWorkerRegistrySlot::empty() }; SELECTED_WORKER_REGISTRY_SIZE];

// The lock covers every registry mutation and the complete scan-to-publish
// interval. It is deliberately held only for bounded local atomics: never
// across clone, callback execution, futex wait, exit, munmap, or another
// syscall. Signal-handler/reentrant pthread_exit behavior is outside this
// private artifact because a signal interrupting a holder could otherwise
// deadlock here.
static SELECTED_WORKER_REGISTRY_LOCK: AtomicU8 = AtomicU8::new(0);

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

/// Read the current x86 Variant-II thread pointer from its `%fs:0` self word.
///
/// The selected fixture and child mapping explicitly establish this self word;
/// this is not a general dynamic-TLS lookup facility.
fn current_thread_pointer() -> *mut u8 {
    let thread_pointer: *mut u8;
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
    thread_pointer
}

/// Return the current initial-TLS `errno` offset below the x86 thread pointer.
///
/// Refusing an unexpected main-image layout avoids guessing at a dynamic TLS
/// template or silently materializing a general TLS image.
fn initial_errno_offset() -> Option<usize> {
    let thread_pointer = current_thread_pointer() as usize;
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

/// Read this task's Linux TID for selected-worker identity validation.
///
/// Linux 5.10 `gettid` has no arguments and returns a positive `pid_t` for a
/// live task. Treating an unexpected kernel-error result as no identity keeps
/// a foreign or incomplete worker on pthread_exit's raw exit path.
#[inline(always)]
fn current_linux_thread_id() -> Option<c_int> {
    // SAFETY: SYS_gettid has no arguments and the Linux/x86-64 result is read
    // only as the bounded private worker identity described above.
    let result = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) };
    if is_linux_error(result) || result <= 0 || result > i64::from(c_int::MAX) {
        return None;
    }
    Some(result as c_int)
}

/// Acquire the bounded registry lock without entering a broader pthread lock.
fn lock_selected_worker_registry() {
    while SELECTED_WORKER_REGISTRY_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while SELECTED_WORKER_REGISTRY_LOCK.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Release the bounded registry lock after its local identity operation.
fn unlock_selected_worker_registry() {
    SELECTED_WORKER_REGISTRY_LOCK.store(0, Ordering::Release);
}

/// Reserve one private selected-worker registry slot before cloning.
fn reserve_selected_worker() -> Option<usize> {
    lock_selected_worker_registry();
    let mut reservation = None;
    for (index, slot) in SELECTED_WORKER_REGISTRY.iter().enumerate() {
        if slot.control.load(Ordering::Acquire) == 0 {
            slot.thread_pointer.store(0, Ordering::Relaxed);
            slot.control
                .store(SELECTED_WORKER_REGISTRY_RESERVING, Ordering::Release);
            reservation = Some(index);
            break;
        }
    }
    unlock_selected_worker_registry();
    reservation
}

/// Publish a fully initialized selected worker before the child can start.
///
/// The `control` release follows every ThreadControl initialization write; an
/// explicit-exit child acquires it before it uses the record.
fn publish_selected_worker(
    registry_slot: usize,
    control: *mut ThreadControl,
    thread_pointer: *mut u8,
) {
    lock_selected_worker_registry();
    if let Some(slot) = SELECTED_WORKER_REGISTRY.get(registry_slot) {
        slot.thread_pointer
            .store(thread_pointer as usize, Ordering::Relaxed);
        slot.control.store(control as usize, Ordering::Release);
    }
    unlock_selected_worker_registry();
}

/// Withdraw a selected-worker registry entry without touching its mapping.
///
/// A failed compare-and-exchange deliberately retains the entry rather than
/// risking a corruption-driven release of some other worker's identity. A
/// successful return guarantees that no pthread_exit scanner can retain this
/// mapping beyond the lock, so its caller may subsequently unmap it.
fn release_selected_worker(registry_slot: usize, control: *mut ThreadControl) -> bool {
    lock_selected_worker_registry();
    let released = if let Some(slot) = SELECTED_WORKER_REGISTRY.get(registry_slot) {
        if slot
            .control
            .compare_exchange(
                control as usize,
                SELECTED_WORKER_REGISTRY_RESERVING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            slot.thread_pointer.store(0, Ordering::Relaxed);
            slot.control.store(0, Ordering::Release);
            true
        } else {
            false
        }
    } else {
        false
    };
    unlock_selected_worker_registry();
    released
}

/// Publish one result only for the current admitted selected worker.
///
/// This reads only the universally established `%fs:0` self word before it
/// finds an exact `%fs:0`, gettid, and still-live child-TID match in the
/// bounded registry. It holds the registry lock through the control-record
/// publish, never returning a raw control pointer that a joiner could unmap
/// concurrently.
fn publish_current_selected_worker_result(result: *mut c_void) {
    let thread_pointer = current_thread_pointer() as usize;
    let Some(thread_id) = current_linux_thread_id() else {
        return;
    };
    if thread_pointer == 0 {
        return;
    }

    lock_selected_worker_registry();
    for slot in &SELECTED_WORKER_REGISTRY {
        let control = slot.control.load(Ordering::Acquire);
        if control == 0 || control == SELECTED_WORKER_REGISTRY_RESERVING {
            continue;
        }
        if slot.thread_pointer.load(Ordering::Acquire) == thread_pointer {
            let control = control as *mut ThreadControl;
            // SAFETY: the matched live registry entry keeps the mapping valid
            // until this function releases the lock; join withdrawal takes
            // the same lock before it may reclaim that mapping.
            if unsafe { (*control).worker_tid.load(Ordering::Acquire) } == thread_id
                && unsafe { (*control).child_tid.load(Ordering::Acquire) } == thread_id
            {
                unsafe { publish_worker_result(control, result) };
                break;
            }
        }
    }
    unlock_selected_worker_registry();
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

/// Publish one selected worker result before the child exits.
///
/// The release makes the callback's writes and result visible to the joiner's
/// acquire of `finished`; Linux's clear-child-tid write remains solely the
/// lifetime/reclamation notification.
unsafe fn publish_worker_result(control: *mut ThreadControl, result: *mut c_void) {
    // SAFETY: the selected worker is the sole result publisher, and its mapping
    // remains live until pthread_join observes the clear-child-tid transition.
    unsafe {
        (*control).result.store(result as usize, Ordering::Relaxed);
        (*control).finished.store(1, Ordering::Release);
    }
}

/// Run the one selected C callback, then publish its result before exit.
unsafe extern "C" fn worker_entry(opaque: *mut c_void) -> c_int {
    let control = opaque.cast::<ThreadControl>();
    let Some(worker_tid) = current_linux_thread_id() else {
        // This cannot occur for Linux 5.10 SYS_gettid, but completing the
        // admitted result handoff avoids leaving a joiner to spin forever if
        // a hostile syscall filter violates that kernel precondition.
        unsafe { publish_worker_result(control, core::ptr::null_mut()) };
        return 0;
    };
    // SAFETY: this child owns initialization before it calls user code; the
    // selected pthread_exit path acquires the release below before it uses
    // this identity to validate the callback's current task.
    unsafe { (*control).worker_tid.store(worker_tid, Ordering::Release) };
    // SAFETY: pthread_create initialized this private record before clone;
    // the child owns the callback invocation and parent only reads result
    // after `finished` is published and the child has exited.
    let result = unsafe { ((*control).start)((*control).argument) };
    unsafe { publish_worker_result(control, result) };
    0
}

/// Create one default-attribute, joinable x86 worker with a private errno TLS image.
///
/// `thread` must designate writable `pthread_t` storage; `start` must be a
/// valid C function pointer and `argument` must remain valid until that
/// function stops reading it. Only a null `attributes` pointer is admitted.
/// The caller must execute under the selected static initial-TLS setup. At
/// most 64 workers from this bounded artifact may be live at once.
///
/// # Safety
///
/// This C ABI boundary cannot validate the output pointer, callback code, or
/// callback argument lifetime. A callback must return normally or call the
/// selected-worker pthread_exit path; other thread-exit behavior remains
/// outside this bounded lifecycle.
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
    let registry_slot = match reserve_selected_worker() {
        Some(registry_slot) => registry_slot,
        None => {
            let _ = unsafe { unmap_worker(mapping, WORKER_MAPPING_SIZE) };
            return EAGAIN;
        }
    };

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
                worker_tid: AtomicI32::new(0),
                registry_retired: AtomicU8::new(0),
                mapping,
                mapping_size: WORKER_MAPPING_SIZE,
                registry_slot,
                start,
                argument,
            },
        );
    }
    publish_selected_worker(registry_slot, control, child_thread_pointer);
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
        release_selected_worker(registry_slot, control);
        let _ = unsafe { unmap_worker(mapping, WORKER_MAPPING_SIZE) };
        // Musl intentionally translates every clone failure to EAGAIN.
        return EAGAIN;
    }

    // SAFETY: clone succeeded, so its opaque record stays live until the one
    // admitted join reclaims the mapping. Publish only after full setup.
    unsafe { core::ptr::write(thread, control.cast()) };
    0
}

/// Exit a selected worker and publish `result` for its admitted joiner.
///
/// This is valid only when called by a callback created through this leaf's
/// null-attribute pthread_create path. It intentionally omits the full musl
/// cleanup/TSD/detach/thread-list state machine. Outside that worker contract,
/// it still performs Linux thread exit but claims no broader pthread behavior.
///
/// # Safety
///
/// The selected callback must not use any object after this call. Its result
/// must remain valid until its joining caller consumes it.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn pthread_exit(result: *mut c_void) -> ! {
    publish_current_selected_worker_result(result);
    // SAFETY: Linux SYS_exit terminates precisely the calling task and does
    // not return. The CLONE_CHILD_CLEARTID lifecycle attached during clone
    // clears/wakes the joiner's shared child-TID word after this exit.
    unsafe { raw_syscall::syscall_noreturn1(raw_syscall::SYS_EXIT, 0) }
}

/// Join one normal-returning or selected-explicit-exit worker from [`pthread_create`].
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
    let registry_slot = unsafe { (*control).registry_slot };
    let registry_retired = unsafe { (*control).registry_retired.load(Ordering::Acquire) };
    if registry_retired == 0 {
        // Withdraw under the same lock used by pthread_exit's complete
        // scan-to-publish interval. No raw registry pointer can survive this
        // call into the following munmap, and a retry after a failed munmap
        // intentionally leaves the worker withdrawn.
        if !release_selected_worker(registry_slot, control) {
            unsafe { (*control).join_claimed.store(0, Ordering::Release) };
            return EINVAL;
        }
        unsafe { (*control).registry_retired.store(1, Ordering::Release) };
    }

    let worker_result = unsafe { (*control).result.load(Ordering::Relaxed) as *mut c_void };
    let mapping = unsafe { (*control).mapping };
    let mapping_size = unsafe { (*control).mapping_size };
    let unmap_result = unsafe { unmap_worker(mapping, mapping_size) };
    if is_linux_error(unmap_result) {
        // An unexpected munmap failure leaves the handle live; permit a retry
        // instead of claiming successful join/reclamation. Its registry entry
        // stays withdrawn: a dead worker needs no future pthread_exit lookup.
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
