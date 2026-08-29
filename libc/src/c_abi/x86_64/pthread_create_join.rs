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
//! `pthread_exit`, and one `pthread_join`. The child gets a distinct copy of
//! the libc-owned Static Initial TLS v1 final-executable image, including its
//! initialized prefix, zeroed TBSS tail, high-alignment layout, and `errno`,
//! and returns its Variant-II thread pointer as the opaque `pthread_t`, exactly
//! matching its selected `pthread_self` identity. The private registry maps
//! that public TP back to the private control record and serializes identity scan/result
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

use core::ffi::{c_int, c_void};
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

use super::{pthread_identity, raw_syscall, static_tls};

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

// Keep the control record and worker stack in one private page-aligned
// anonymous mapping. Static Initial TLS v1 owns a separate exact PT_TLS
// materialization, so this worker mapping never guesses an errno offset or
// overlays user TLS. The stack grows down from its top.
const CONTROL_REGION_SIZE: usize = 4_096;
const WORKER_STACK_SIZE: usize = 1_024 * 1_024;
const WORKER_MAPPING_SIZE: usize = CONTROL_REGION_SIZE + WORKER_STACK_SIZE;
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
    // Parent initializes every non-atomic callback/control field, then makes
    // the record visible with this release flag before clone. The child first
    // acquires it, rather than treating clone as a Rust memory-ordering edge.
    start_ready: AtomicU8,
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
    // Static Initial TLS v1 maps the complete final-executable image
    // separately from this control/stack allocation.  A failed control-map
    // reclamation retry must not unmap the TLS image twice.
    tls_released: AtomicU8,
    mapping: *mut u8,
    mapping_size: usize,
    tls_block: static_tls::StaticInitialTlsBlock,
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

/// Claim the one selected worker named by its public x86 `pthread_t` value.
///
/// The selected static identity leaf exposes the child Variant-II TP as the
/// opaque handle, matching musl x86's `__pthread_self()` value and C's raw
/// `pthread_equal` macro. This lookup remains under the same registry lock
/// that withdraws entries before `munmap`, so the returned control pointer
/// cannot name a reclaimed mapping. Claiming `join_claimed` while still
/// locked then gives this joiner exclusive ownership until it either releases
/// the claim on an error or completes reclamation.
fn claim_selected_worker_by_thread_pointer(thread: *mut c_void) -> Option<*mut ThreadControl> {
    if thread.is_null() {
        return None;
    }

    let thread_pointer = thread as usize;
    lock_selected_worker_registry();
    let mut claimed = None;
    for slot in &SELECTED_WORKER_REGISTRY {
        if slot.thread_pointer.load(Ordering::Acquire) != thread_pointer {
            continue;
        }
        let control = slot.control.load(Ordering::Acquire);
        if control == 0 || control == SELECTED_WORKER_REGISTRY_RESERVING {
            continue;
        }
        let control = control as *mut ThreadControl;
        // SAFETY: registry withdrawal uses this lock before it may unmap the
        // control record. The record is therefore live for the atomic claim.
        if unsafe {
            (*control)
                .join_claimed
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        }
        .is_ok()
        {
            claimed = Some(control);
        }
        break;
    }
    unlock_selected_worker_registry();
    claimed
}

/// Publish one result only for the current admitted selected worker.
///
/// This reads only the universally established `%fs:0` self word before it
/// finds an exact `%fs:0`, gettid, and still-live child-TID match in the
/// bounded registry. It holds the registry lock through the control-record
/// publish, never returning a raw control pointer that a joiner could unmap
/// concurrently.
fn publish_current_selected_worker_result(result: *mut c_void) {
    let thread_pointer = pthread_identity::current_thread_pointer() as usize;
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

/// Map one control/stack backing range without translating `errno`.
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
    // SAFETY: pthread_create performed the matching release after every
    // non-atomic record field was initialized and before this child exists.
    while unsafe { (*control).start_ready.load(Ordering::Acquire) } == 0 {
        core::hint::spin_loop();
    }
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

/// Create one default-attribute, joinable x86 worker with Static Initial TLS v1.
///
/// `thread` must designate writable `pthread_t` storage; `start` must be a
/// valid C function pointer and `argument` must remain valid until that
/// function stops reading it. Only a null `attributes` pointer is admitted.
/// The caller must execute after the private first-thread Static Initial TLS
/// v1 bootstrap has retained the final executable's validated template. At
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
    if !static_tls::is_ready() {
        return ENOTSUP;
    }
    let tls_block = match unsafe { static_tls::allocate_thread() } {
        Some(block) => block,
        // The retained template stays immutable after `is_ready`; a later
        // failure therefore means allocation pressure, not an unselected TLS
        // fallback or an attempt to derive an errno-only image.
        None => return EAGAIN,
    };
    let mapping = unsafe { map_worker() };
    if mapping.is_null() {
        let _ = unsafe { static_tls::release_thread(tls_block) };
        return EAGAIN;
    }

    let control = mapping.cast::<ThreadControl>();
    let stack_top = unsafe { mapping.add(WORKER_MAPPING_SIZE) };
    let registry_slot = match reserve_selected_worker() {
        Some(registry_slot) => registry_slot,
        None => {
            let _ = unsafe { unmap_worker(mapping, WORKER_MAPPING_SIZE) };
            let _ = unsafe { static_tls::release_thread(tls_block) };
            return EAGAIN;
        }
    };

    // SAFETY: mmap returned a private page-aligned zeroed allocation of the
    // exact fixed control/stack size. Static Initial TLS v1 already copied
    // the final executable's exact initialized and TBSS TLS image and wrote
    // its minimal Variant-II self word before this record becomes visible.
    unsafe {
        core::ptr::write(
            control,
            ThreadControl {
                child_tid: AtomicI32::new(0),
                start_ready: AtomicU8::new(0),
                join_claimed: AtomicU8::new(0),
                result: AtomicUsize::new(0),
                finished: AtomicU8::new(0),
                worker_tid: AtomicI32::new(0),
                registry_retired: AtomicU8::new(0),
                tls_released: AtomicU8::new(0),
                mapping,
                mapping_size: WORKER_MAPPING_SIZE,
                tls_block,
                registry_slot,
                start,
                argument,
            },
        );
        (*control).start_ready.store(1, Ordering::Release);
    }
    publish_selected_worker(registry_slot, control, tls_block.thread_pointer());
    let child_tid = unsafe { core::ptr::addr_of_mut!((*control).child_tid).cast::<c_int>() };
    // SAFETY: the private clone seam uses musl's exact x86 argument shuffle.
    // The worker mapping supplies a writable child stack/live control record,
    // while the separate v1 block supplies a full fresh final-image TLS copy.
    let clone_result = unsafe {
        __crabc_x86_pthread_clone(
            worker_entry,
            stack_top,
            PTHREAD_CLONE_FLAGS,
            control.cast(),
            child_tid,
            tls_block.thread_pointer().cast(),
            child_tid,
        )
    };
    if is_linux_error(clone_result) {
        if !release_selected_worker(registry_slot, control) {
            // The private registry can still expose `control` to the selected
            // pthread_exit scanner.  Fail closed by retaining both mappings
            // rather than unmapping a pointer that a failed withdrawal left
            // published. This impossible-under-contract corruption path leaks
            // one bounded admission slot but cannot manufacture a dangling
            // registry pointer.
            return EAGAIN;
        }
        let _ = unsafe { unmap_worker(mapping, WORKER_MAPPING_SIZE) };
        let _ = unsafe { static_tls::release_thread(tls_block) };
        // Musl intentionally translates every clone failure to EAGAIN.
        return EAGAIN;
    }

    // SAFETY: clone succeeded, so the selected child's complete Static Initial
    // TLS v1 TP stays live until the one admitted join reclaims it. On x86
    // musl this TP is the opaque pthread_t returned by pthread_self, and the
    // C header's pthread_equal macro therefore requires it to be the same
    // creator-visible handle rather than this private control-record address.
    unsafe { core::ptr::write(thread, tls_block.thread_pointer().cast()) };
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
/// `thread` must be the still-live opaque TP result of this leaf's
/// `pthread_create`; `result` may be null or writable pointer-result storage.
/// No caller may use `thread` after a successful return because its full TLS
/// and private control mappings have been released.
///
/// # Safety
///
/// The opaque handle and optional result storage must meet those lifetime and
/// alignment requirements. The caller must not concurrently join the same
/// handle; such broader pthread behavior is deliberately outside this slice.
#[no_mangle]
pub unsafe extern "C" fn pthread_join(thread: *mut c_void, result: *mut *mut c_void) -> c_int {
    let Some(control) = claim_selected_worker_by_thread_pointer(thread) else {
        return EINVAL;
    };

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
    let tls_block = unsafe { (*control).tls_block };
    if unsafe { (*control).tls_released.load(Ordering::Acquire) } == 0 {
        // The clear-child-tid observation plus registry withdrawal above prove
        // that neither a running worker nor the selected pthread_exit scan can
        // retain this full Static Initial TLS v1 mapping. Release it before
        // the control record so an unexpected control-map failure leaves a
        // retryable handle with an explicit no-double-release state.
        let tls_unmap_result = unsafe { static_tls::release_thread(tls_block) };
        if is_linux_error(tls_unmap_result) {
            unsafe { (*control).join_claimed.store(0, Ordering::Release) };
            return positive_linux_error(tls_unmap_result);
        }
        unsafe { (*control).tls_released.store(1, Ordering::Release) };
    }
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
