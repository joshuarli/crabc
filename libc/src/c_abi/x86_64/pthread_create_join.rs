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
//!   cleanup-before-TSD-destructor-before-result ordering. The separate
//!   deferred cancellation leaf owns only active selected-worker cleanup
//!   records and explicit `pthread_testcancel`; signal, robust-list,
//!   thread-list, and last-thread paths remain explicitly unselected.
//! - `src/thread/x86_64/clone.s::__clone` supplies the seven-argument SysV
//!   entry layout, `clone=56` register shuffle, aligned child-stack callback,
//!   and `exit=60` tail. The assembly below is a lexical private-symbol rename
//!   of that source.
//! - `src/thread/pthread_join.c` supplies the essential wait-before-reclaim
//!   ordering: a joiner waits for `CLONE_CHILD_CLEARTID` to clear the worker
//!   TID before it releases worker-owned memory.
//! - `src/thread/pthread_detach.c` supplies the single successful
//!   joinable-to-detached ownership transition. This selected artifact keeps
//!   musl's prompt detach shape but uses its established AArch64-style later
//!   external reaper because a worker cannot unmap its own active stack/TLS.
//!
//! The admitted contract is exactly one default-attribute worker:
//! `pthread_create(NULL)`, a normal returning start routine or selected-worker
//! `pthread_exit`, and one `pthread_join` **or** `pthread_detach`. The private
//! C11 lifecycle sibling reuses this allocation/clone/join/detach seam through a distinct typed
//! `int (*)(void *)` start mode; it never reinterprets that callback as the
//! pointer-returning pthread type. The child gets a distinct copy of the
//! libc-owned Static Initial TLS v1 final-executable image, including its
//! initialized prefix, zeroed TBSS tail, high-alignment layout, and `errno`,
//! and returns its Variant-II thread pointer as the opaque `pthread_t`, exactly
//! matching its selected `pthread_self` identity. The private registry maps
//! that public TP back to the private control record and serializes identity
//! scan/result publication with join withdrawal, and validates `%fs:0`, Linux
//! `gettid`, and the still-live child-TID word so a foreign thread cannot turn
//! a copied TLS base into a control-record write after task-ID reuse. It is
//! intentionally neither signal-safe nor reentrant. A successful selected
//! detach is prompt: it changes ownership to detached without waiting for the
//! child. A later selected create/join boundary reclaims the detached
//! TLS/control mappings only after `CLONE_CHILD_CLEARTID` has cleared the
//! child TID. This follows the existing AArch64 runtime's safe external
//! reaping shape; it is not a claim of general detached-thread reclamation or
//! full pthread parity. The leaf intentionally does **not** provide attrs,
//! detached-at-create attributes,
//! main-thread `pthread_exit` behavior, signal-driven or implicit-point
//! cancellation, general
//! keys/TSD, synchronization objects, dynamic TLS/DTV, loader TLS, signal-mask
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

use super::{pthread_cancel, pthread_identity, pthread_tsd, raw_syscall, static_tls};

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

/// The selected pthread callback ABI.
///
/// This remains distinct from [`C11StartRoutine`].  Both return through the
/// x86-64 integer return register, but the C abstract machines have different
/// function types and must not be joined by a function-pointer cast.
pub(super) type PthreadStartRoutine = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

/// The selected C11 callback ABI.
///
/// The C11 lifecycle leaf stores this typed function pointer in
/// [`SelectedWorkerStart::C11`], then the worker trampoline explicitly
/// sign-extends its `int` result into the private pointer-sized join storage.
pub(super) type C11StartRoutine = unsafe extern "C" fn(*mut c_void) -> c_int;

/// One typed start mode admitted by the bounded selected-worker seam.
///
/// This is intentionally private to the two static C lifecycle leaves.  It is
/// not a general callback adapter, a public Rust API, or a claim that other
/// pthread/C11 entry points share implementation semantics.
#[derive(Clone, Copy)]
pub(super) enum SelectedWorkerStart {
    Pthread(PthreadStartRoutine),
    C11(C11StartRoutine),
}

/// The representation a selected callback is permitted to publish at join.
///
/// This tag prevents a cross-API explicit exit from being silently decoded as
/// the other API's result type. In particular, `pthread_exit(void *)` from a
/// C11-mode callback cannot turn an arbitrary pointer into a `thrd_join` int.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum SelectedWorkerResultKind {
    Pthread,
    C11,
    Invalid,
}

impl SelectedWorkerResultKind {
    const NONE: u8 = 0;
    const PTHREAD: u8 = 1;
    const C11_TAG: u8 = 2;
    const INVALID: u8 = 3;

    #[inline]
    const fn encode(self) -> u8 {
        match self {
            Self::Pthread => Self::PTHREAD,
            Self::C11 => Self::C11_TAG,
            Self::Invalid => Self::INVALID,
        }
    }

    #[inline]
    fn decode(value: u8) -> Self {
        match value {
            Self::PTHREAD => Self::Pthread,
            Self::C11_TAG => Self::C11,
            // A missing/unknown tag is never decoded as either public result
            // representation. This keeps an interrupted or cross-mode exit
            // from manufacturing a pointer-or-int result.
            Self::NONE | Self::INVALID | _ => Self::Invalid,
        }
    }
}

/// One private callback result before it reaches the shared join word.
#[derive(Clone, Copy)]
enum SelectedWorkerResult {
    Pthread(usize),
    C11(c_int),
    Invalid,
}

impl SelectedWorkerResult {
    #[inline]
    const fn kind(self) -> SelectedWorkerResultKind {
        match self {
            Self::Pthread(_) => SelectedWorkerResultKind::Pthread,
            Self::C11(_) => SelectedWorkerResultKind::C11,
            Self::Invalid => SelectedWorkerResultKind::Invalid,
        }
    }

    #[inline]
    fn encode(self) -> usize {
        match self {
            Self::Pthread(result) => result,
            Self::C11(result) => encode_c11_result(result),
            Self::Invalid => 0,
        }
    }
}

impl SelectedWorkerStart {
    /// Run one typed callback and encode its result for the private join word.
    ///
    /// The C11 arm performs the conversion at the typed trampoline boundary,
    /// mirroring musl's separate `start_c11` helper.  It does not reinterpret
    /// a C11 function pointer as a pthread callback.
    unsafe fn invoke(self, argument: *mut c_void) -> SelectedWorkerResult {
        match self {
            Self::Pthread(start) => {
                // SAFETY: the C ABI caller supplied one valid pthread start
                // routine and keeps its argument valid for the callback.
                SelectedWorkerResult::Pthread(unsafe { start(argument) as usize })
            }
            Self::C11(start) => {
                // SAFETY: the C ABI caller supplied one valid C11 start
                // routine and keeps its argument valid for the callback.
                SelectedWorkerResult::C11(unsafe { start(argument) })
            }
        }
    }

    #[inline]
    const fn result_kind(self) -> SelectedWorkerResultKind {
        match self {
            Self::Pthread(_) => SelectedWorkerResultKind::Pthread,
            Self::C11(_) => SelectedWorkerResultKind::C11,
        }
    }
}

/// Encode a C11 `int` result in the private pointer-sized join word.
///
/// x86-64 LP64 has a 64-bit `usize` and a 32-bit C `int`, so the `isize`
/// conversion preserves every signed C11 result before the bit-preserving
/// storage cast.  [`decode_c11_result`] is its exact inverse for values made
/// by this typed C11 path, including `INT_MIN` and `INT_MAX`.
#[inline]
pub(super) fn encode_c11_result(result: c_int) -> usize {
    (result as isize) as usize
}

/// Decode one private C11 join result without treating it as a C pointer.
#[inline]
pub(super) fn decode_c11_result(result: usize) -> c_int {
    (result as isize) as c_int
}

/// One reclaimed selected worker result, tagged before either public join ABI
/// decodes the shared storage word.
#[derive(Clone, Copy)]
pub(super) struct SelectedWorkerJoinResult {
    pub(super) encoded_result: usize,
    pub(super) kind: SelectedWorkerResultKind,
}

/// One selected worker's one-winner post-create ownership state.
///
/// `Joinable` is the only claimable state. A joiner owns `JoinClaimed` until
/// it has observed clear-child-tid and reclaimed the mappings. A detacher
/// publishes `Detached` without waiting; a later external selected lifecycle
/// call may change that state to `DetachedReclaiming` after it observes the
/// kernel-cleared child TID. The worker itself never releases its stack or TLS
/// mapping: it is still executing with both while it exits.
#[derive(Clone, Copy, Eq, PartialEq)]
enum SelectedWorkerLifecycleState {
    Joinable,
    JoinClaimed,
    Detached,
    DetachedReclaiming,
}

impl SelectedWorkerLifecycleState {
    const JOINABLE: u8 = 0;
    const JOIN_CLAIMED: u8 = 1;
    const DETACHED: u8 = 2;
    const DETACHED_RECLAIMING: u8 = 3;

    #[inline]
    const fn encode(self) -> u8 {
        match self {
            Self::Joinable => Self::JOINABLE,
            Self::JoinClaimed => Self::JOIN_CLAIMED,
            Self::Detached => Self::DETACHED,
            Self::DetachedReclaiming => Self::DETACHED_RECLAIMING,
        }
    }
}

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
    // A joiner or detacher makes the sole state transition out of Joinable
    // while the registry lock still proves this control mapping is live.
    // Detached workers retain their live registry entry until a later
    // external reaper has observed the kernel's clear-child-tid write.
    lifecycle: AtomicU8,
    // A selected child publishes its callback result and its typed result tag
    // before `finished`. The tag prevents cross-mode explicit exits from
    // being decoded as the other API's public result representation.
    result: AtomicUsize,
    result_kind: AtomicU8,
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
    // The selected TSD leaf owns its values in this private worker mapping,
    // not in the Static Initial TLS v1 `%fs:0` self word. The mapping remains
    // live through the destructor phase and clear-child-tid handoff.
    tsd: pthread_tsd::SelectedTsdValues,
    registry_slot: usize,
    start: SelectedWorkerStart,
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
    assert!(size_of::<usize>() >= size_of::<c_int>());
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

/// Whether any selected worker reservation or live mapping exists.
///
/// The single-threaded atfork leaf uses this as a fail-closed admission check
/// before it copies process state. A reservation is conservatively live too:
/// a concurrent creator has not yet established a child mapping, but fork
/// cannot safely race the registry publication transition. This is not a
/// general all-thread-list query and says nothing about foreign threads.
pub(super) fn has_live_selected_workers() -> bool {
    lock_selected_worker_registry();
    let live = SELECTED_WORKER_REGISTRY.iter().any(|slot| {
        slot.control.load(Ordering::Acquire) != 0
    });
    unlock_selected_worker_registry();
    live
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

/// Withdraw a selected-worker registry entry while its registry lock is held.
///
/// A failed compare-and-exchange deliberately retains the entry rather than
/// risking a corruption-driven release of some other worker's identity. A
/// successful return guarantees that no pthread_exit scanner can retain this
/// mapping beyond the lock, so its caller may subsequently unmap it.
fn release_selected_worker_locked(registry_slot: usize, control: *mut ThreadControl) -> bool {
    if let Some(slot) = SELECTED_WORKER_REGISTRY.get(registry_slot) {
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
            // This slot is no longer reachable through the selected worker
            // registry. Clear the parallel deferred-cancellation record while
            // the same lock still prevents an ABA reuse of `registry_slot`.
            pthread_cancel::release_selected_worker_slot(registry_slot);
            slot.thread_pointer.store(0, Ordering::Relaxed);
            slot.control.store(0, Ordering::Release);
            true
        } else {
            false
        }
    } else {
        false
    }
}

/// Mark one live selected pthread worker for deferred cancellation.
///
/// The registry lock covers handle validation and the pending-bit update, so
/// join withdrawal cannot recycle this private slot between those two steps.
/// There is intentionally no signal delivery: this static artifact observes a
/// request only through the target's explicit `pthread_testcancel` call.
pub(super) fn request_selected_pthread_cancellation(thread: *mut c_void) -> bool {
    if thread.is_null() {
        return false;
    }

    let thread_pointer = thread as usize;
    lock_selected_worker_registry();
    let mut requested = false;
    for slot in &SELECTED_WORKER_REGISTRY {
        if slot.thread_pointer.load(Ordering::Acquire) != thread_pointer {
            continue;
        }
        let control = slot.control.load(Ordering::Acquire);
        if control == 0 || control == SELECTED_WORKER_REGISTRY_RESERVING {
            break;
        }
        let control = control as *mut ThreadControl;
        // SAFETY: the registry lock keeps this private control mapping live.
        // Only pointer-returning pthread workers are in this cancellation
        // slice; the typed C11 sibling is deliberately not reinterpreted as a
        // pthread cancellation target.
        if matches!(unsafe { (*control).start }, SelectedWorkerStart::Pthread(_)) {
            requested = pthread_cancel::mark_selected_worker_pending(
                unsafe { (*control).registry_slot },
            );
        }
        break;
    }
    unlock_selected_worker_registry();
    requested
}

/// Withdraw a selected-worker registry entry without touching its mapping.
fn release_selected_worker(registry_slot: usize, control: *mut ThreadControl) -> bool {
    lock_selected_worker_registry();
    let released = release_selected_worker_locked(registry_slot, control);
    unlock_selected_worker_registry();
    released
}

/// Claim the one selected worker named by its public x86 `pthread_t` value.
///
/// The selected static identity leaf exposes the child Variant-II TP as the
/// opaque handle, matching musl x86's `__pthread_self()` value and C's raw
/// `pthread_equal` macro. This lookup remains under the same registry lock
/// that withdraws entries before `munmap`, so the returned control pointer
/// cannot name a reclaimed mapping. Claiming a non-joinable lifecycle state
/// while still locked gives that caller exclusive ownership until it either
/// releases a join claim on an error or completes reclamation.
fn claim_selected_worker_by_thread_pointer(
    thread: *mut c_void,
    claimed_state: SelectedWorkerLifecycleState,
) -> Option<*mut ThreadControl> {
    if thread.is_null() {
        return None;
    }
    debug_assert!(matches!(
        claimed_state,
        SelectedWorkerLifecycleState::JoinClaimed | SelectedWorkerLifecycleState::Detached
    ));

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
                .lifecycle
                .compare_exchange(
                    SelectedWorkerLifecycleState::Joinable.encode(),
                    claimed_state.encode(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
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

/// Release a join claim before the worker has been withdrawn from the registry.
///
/// A detachment never uses this transition: once detached, only the external
/// clear-child-tid reaper may own its mappings.
unsafe fn release_join_claim(control: *mut ThreadControl) {
    // SAFETY: the joining caller still owns a registry-published control
    // record on each error path that reaches this helper.
    let _ = unsafe {
        (*control).lifecycle.compare_exchange(
            SelectedWorkerLifecycleState::JoinClaimed.encode(),
            SelectedWorkerLifecycleState::Joinable.encode(),
            Ordering::Release,
            Ordering::Relaxed,
        )
    };
}

/// Claim one exited detached worker while its registry mapping is still live.
///
/// The lock covers the lookup, `Detached -> DetachedReclaiming` transition,
/// second clear-child-tid observation, and registry withdrawal. This prevents
/// an explicit-exit publisher from retaining a raw control pointer while the
/// external reaper begins releasing its TLS/control mappings.
fn claim_finished_detached_selected_worker() -> Option<*mut ThreadControl> {
    lock_selected_worker_registry();
    let mut claimed = None;
    for (registry_slot, slot) in SELECTED_WORKER_REGISTRY.iter().enumerate() {
        let control = slot.control.load(Ordering::Acquire);
        if control == 0 || control == SELECTED_WORKER_REGISTRY_RESERVING {
            continue;
        }
        let control = control as *mut ThreadControl;
        // SAFETY: this registry entry remains published while the lock is
        // held, so every control-field access through it is valid.
        let detached = unsafe {
            (*control).lifecycle.load(Ordering::Acquire)
                == SelectedWorkerLifecycleState::Detached.encode()
        };
        if !detached {
            continue;
        }
        if unsafe { (*control).child_tid.load(Ordering::Acquire) } != 0 {
            continue;
        }
        let claimed_reclamation = unsafe {
            (*control).lifecycle.compare_exchange(
                SelectedWorkerLifecycleState::Detached.encode(),
                SelectedWorkerLifecycleState::DetachedReclaiming.encode(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
        };
        if claimed_reclamation.is_err() {
            continue;
        }
        // `CLONE_CHILD_CLEARTID` cannot restore a nonzero TID, but keep this
        // defensive second observation next to the ownership transition so a
        // future clone-path change cannot free a still-running child's stack.
        if unsafe { (*control).child_tid.load(Ordering::Acquire) } != 0 {
            let _ = unsafe {
                (*control).lifecycle.compare_exchange(
                    SelectedWorkerLifecycleState::DetachedReclaiming.encode(),
                    SelectedWorkerLifecycleState::Detached.encode(),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
            };
            continue;
        }
        if release_selected_worker_locked(registry_slot, control) {
            // The selected worker can no longer reach this record through its
            // explicit-exit identity scan, and child_tid==0 proves it is no
            // longer executing on either worker-owned mapping.
            unsafe { (*control).registry_retired.store(1, Ordering::Release) };
            claimed = Some(control);
            break;
        }
        let _ = unsafe {
            (*control).lifecycle.compare_exchange(
                SelectedWorkerLifecycleState::DetachedReclaiming.encode(),
                SelectedWorkerLifecycleState::Detached.encode(),
                Ordering::Release,
                Ordering::Relaxed,
            )
        };
    }
    unlock_selected_worker_registry();
    claimed
}

/// Release mappings for a registry-withdrawn completed selected worker.
///
/// # Safety
///
/// `control` must remain mapped, be withdrawn from the registry, and have a
/// zero `child_tid` observed after `CLONE_CHILD_CLEARTID`. The caller must not
/// access it after this function successfully unmaps its control/stack range.
unsafe fn reclaim_withdrawn_selected_worker(control: *mut ThreadControl) -> Result<(), c_int> {
    // SAFETY: the caller proves the record remains mapped for this first read.
    let tls_block = unsafe { (*control).tls_block };
    if unsafe { (*control).tls_released.load(Ordering::Acquire) } == 0 {
        // The caller's zero child-TID observation and prior registry
        // withdrawal prove that neither the worker nor pthread_exit's scan can
        // retain the private Static Initial TLS v1 mapping.
        let tls_unmap_result = unsafe { static_tls::release_thread(tls_block) };
        if is_linux_error(tls_unmap_result) {
            return Err(positive_linux_error(tls_unmap_result));
        }
        unsafe { (*control).tls_released.store(1, Ordering::Release) };
    }
    let mapping = unsafe { (*control).mapping };
    let mapping_size = unsafe { (*control).mapping_size };
    let unmap_result = unsafe { unmap_worker(mapping, mapping_size) };
    if is_linux_error(unmap_result) {
        return Err(positive_linux_error(unmap_result));
    }
    Ok(())
}

/// Reap every detached selected worker whose kernel lifetime has ended.
///
/// This deliberately runs only at later selected lifecycle boundaries. It
/// gives `pthread_detach`/`thrd_detach` their prompt ownership transition
/// without asking an exiting worker to unmap the stack and TLS mapping it is
/// still using. A cold unmap failure is fail-closed: the registry remains
/// withdrawn and the private mappings are retained rather than republishing a
/// pointer that might later be reclaimed concurrently.
fn reap_finished_detached_selected_workers() {
    while let Some(control) = claim_finished_detached_selected_worker() {
        // SAFETY: the claim withdrew this zero-child-TID control record under
        // the registry lock, so no selected worker can retain it now.
        let _ = unsafe { reclaim_withdrawn_selected_worker(control) };
    }
}

/// Resolve the current admitted selected worker's private control record.
///
/// The exact `%fs:0`, Linux-TID, and live-child-TID match prevents a foreign
/// thread from turning a copied TLS base into a control record. Once this
/// current task has matched, its positive child-TID keeps join/reaping from
/// withdrawing the mapping before the task finishes its own callback or exit
/// path, so the caller may use the returned pointer after the registry lock is
/// released. It must never be retained past that current-thread operation.
fn current_selected_worker_control() -> Option<*mut ThreadControl> {
    let thread_pointer = pthread_identity::current_thread_pointer() as usize;
    let Some(thread_id) = current_linux_thread_id() else {
        return None;
    };
    if thread_pointer == 0 {
        return None;
    }

    lock_selected_worker_registry();
    let mut current = None;
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
                current = Some(control);
                break;
            }
        }
    }
    unlock_selected_worker_registry();
    current
}

/// Return the current selected pthread worker's private registry slot.
///
/// This deliberately excludes the typed C11 sibling even though its opaque
/// handle shares the x86 Variant-II TP representation. The returned slot is
/// stable until this current worker exits because its positive child-TID keeps
/// join or detached reaping from withdrawing the control mapping.
pub(super) fn current_selected_pthread_worker_slot() -> Option<usize> {
    let control = current_selected_worker_control()?;
    // SAFETY: current-worker resolution above keeps the mapping live for this
    // current task. The start mode is immutable after clone publication.
    if matches!(unsafe { (*control).start }, SelectedWorkerStart::Pthread(_)) {
        Some(unsafe { (*control).registry_slot })
    } else {
        None
    }
}

/// Return the current selected worker's bounded TSD table.
///
/// The selected TSD leaf may use this pointer only during the active current
/// worker call. Its caller never owns or exposes the opaque `ThreadControl`.
pub(super) fn current_selected_worker_tsd_values(
) -> Option<*const pthread_tsd::SelectedTsdValues> {
    let control = current_selected_worker_control()?;
    // SAFETY: current-worker resolution proves the control mapping is live
    // until this current task exits; the TSD leaf retains no pointer after its
    // current get/set/destructor operation completes.
    Some(unsafe { core::ptr::addr_of!((*control).tsd) })
}

/// Clear one key in every still-registry-published selected worker.
///
/// The TSD leaf calls this while holding its private metadata lock. This
/// helper then takes the selected-worker registry lock, preserving the one
/// TSD -> registry lock order. It invokes no user code and never retains a
/// control pointer beyond the scan.
pub(super) fn clear_selected_worker_tsd_key(key: usize) {
    lock_selected_worker_registry();
    for slot in &SELECTED_WORKER_REGISTRY {
        let control = slot.control.load(Ordering::Acquire);
        if control == 0 || control == SELECTED_WORKER_REGISTRY_RESERVING {
            continue;
        }
        let control = control as *mut ThreadControl;
        // SAFETY: this published registry entry remains mapped while its lock
        // is held. The TSD leaf's own metadata lock excludes a concurrent
        // selected set/get for this key.
        unsafe { (*control).tsd.clear_key(key) };
    }
    unlock_selected_worker_registry();
}

/// Publish one result only for one already-validated selected worker.
///
/// A C11 worker may exit only through thrd_exit, and a pthread worker only
/// through pthread_exit. Do not let an accidental cross-mode API call make
/// thrd_join decode a raw pointer (or pthread_join publish a sign-extended C11
/// result) as if it had the selected public representation.
unsafe fn publish_selected_worker_result(
    control: *mut ThreadControl,
    result: SelectedWorkerResult,
) {
    // SAFETY: current-worker resolution or worker_entry proves this control
    // mapping remains live until the current task invokes SYS_exit.
    let expected_kind = unsafe { (*control).start.result_kind() };
    let published = if result.kind() == expected_kind {
        result
    } else {
        SelectedWorkerResult::Invalid
    };
    unsafe { publish_worker_result(control, published) };
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
unsafe fn publish_worker_result(control: *mut ThreadControl, result: SelectedWorkerResult) {
    // SAFETY: the selected worker is the sole result publisher, and its mapping
    // remains live until pthread_join observes the clear-child-tid transition.
    unsafe {
        (*control).result.store(result.encode(), Ordering::Relaxed);
        (*control)
            .result_kind
            .store(result.kind().encode(), Ordering::Relaxed);
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
        unsafe { publish_worker_result(control, SelectedWorkerResult::Invalid) };
        return 0;
    };
    // SAFETY: this child owns initialization before it calls user code; the
    // selected pthread_exit path acquires the release below before it uses
    // this identity to validate the callback's current task.
    unsafe { (*control).worker_tid.store(worker_tid, Ordering::Release) };
    // SAFETY: pthread_create initialized this private record before clone;
    // the child owns the callback invocation and parent only reads result
    // after `finished` is published and the child has exited.
    let result = unsafe { (*control).start.invoke((*control).argument) };
    // SAFETY: this current worker owns its control/TSD mapping until the
    // assembly tail calls SYS_exit. Destructors must finish before its result
    // becomes join-observable.
    unsafe {
        pthread_tsd::run_selected_worker_tsd_destructors(core::ptr::addr_of!((*control).tsd));
        publish_selected_worker_result(control, result);
    }
    0
}

/// Create one default-attribute, joinable x86 pthread worker with Static Initial TLS v1.
///
/// `thread` must designate writable `pthread_t` storage; `start` must be a
/// valid pthread callback and `argument` must remain valid until that function
/// stops reading it. Only a null `attributes` pointer is admitted. The private
/// C11 sibling calls [`create_selected_worker`] with its own typed callback
/// mode instead of reaching this C ABI through an incompatible cast.
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
    start: Option<PthreadStartRoutine>,
    argument: *mut c_void,
) -> c_int {
    // Preserve the existing narrow boundary's invalid-input precedence: a
    // missing output slot or callback is EINVAL even when the caller also
    // supplies an unsupported attribute object.
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
    // SAFETY: the public C boundary validated only the nullable callback; the
    // common selected-worker seam retains the output-pointer and lifetime
    // obligations documented above.
    unsafe { create_selected_worker(thread, SelectedWorkerStart::Pthread(start), argument) }
}

/// Create one selected default-attribute worker for the pthread or C11 leaf.
///
/// This is the one private allocator/clone path shared by the two typed C ABI
/// boundaries.  Its `SelectedWorkerStart` enum preserves the callback ABI
/// through the child trampoline: `Pthread` has a pointer result and `C11` has
/// a signed `int` result.  It returns a POSIX pthread-style positive errno
/// only so each public boundary can apply its own documented status mapping;
/// it never changes the creator's `errno`.
///
/// # Safety
///
/// `thread` must designate writable opaque-handle storage. The typed callback
/// and its argument must remain valid until the callback stops using them. The
/// caller must execute after the private Static Initial TLS v1 bootstrap has
/// retained the final executable template. At most 64 selected workers may be
/// live at once. This is not a general pthread or C11 creation primitive.
pub(super) unsafe fn create_selected_worker(
    thread: *mut *mut c_void,
    start: SelectedWorkerStart,
    argument: *mut c_void,
) -> c_int {
    if thread.is_null() {
        return EINVAL;
    }
    if !static_tls::is_ready() {
        return ENOTSUP;
    }
    // A detached child cannot release its active stack/TLS mappings itself.
    // Reap only here at a later lifecycle boundary, after the kernel's
    // clear-child-tid write proves any selected detached child has stopped
    // using them. Creation remains bounded by the 64-slot registry even when
    // a caller never joins detached workers.
    reap_finished_detached_selected_workers();
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

    // The cancellation leaf is a parallel fixed table keyed by this already
    // reserved registry index. It remains private state rather than a TCB or
    // thread-list extension, and it is initialized before the child can run.
    pthread_cancel::initialize_selected_worker_slot(
        registry_slot,
        matches!(start, SelectedWorkerStart::Pthread(_)),
    );

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
                lifecycle: AtomicU8::new(SelectedWorkerLifecycleState::Joinable.encode()),
                result: AtomicUsize::new(0),
                result_kind: AtomicU8::new(SelectedWorkerResultKind::NONE),
                finished: AtomicU8::new(0),
                worker_tid: AtomicI32::new(0),
                registry_retired: AtomicU8::new(0),
                tls_released: AtomicU8::new(0),
                mapping,
                mapping_size: WORKER_MAPPING_SIZE,
                tls_block,
                tsd: pthread_tsd::SelectedTsdValues::empty(),
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

/// Exit a selected worker and publish its typed result for its admitted joiner.
///
/// This is valid only when called by a callback created through this leaf's
/// null-attribute pthread_create path. It invokes the selected cleanup and
/// worker-TSD destructor phases, but intentionally omits the rest of musl's
/// detach/thread-list state machine. Outside that worker contract, it still
/// performs Linux thread exit but claims no broader pthread behavior.
///
/// # Safety
///
/// The selected callback must not use any object after this call. Its typed
/// result must remain valid until its joining caller consumes it.
#[inline(always)]
unsafe fn exit_selected_worker(result: SelectedWorkerResult) -> ! {
    if let Some(control) = current_selected_worker_control() {
        // SAFETY: the matched current selected worker remains live until this
        // path invokes SYS_exit. Preserve musl's cleanup-before-TSD-before-
        // result ordering without holding the worker-registry lock across user
        // destructors.
        unsafe {
            // Pthread cancellation and pthread_exit unwind active cleanup
            // records before the already-selected TSD destructor phase. The
            // helper independently admits only a pthread-mode current worker,
            // so a C11-to-pthread cross-over remains an invalid result rather
            // than acquiring cleanup ownership.
            if result.kind() == SelectedWorkerResultKind::Pthread {
                pthread_cancel::disable_current_selected_pthread_cancellation_for_exit();
                pthread_cancel::run_current_selected_pthread_cleanup_handlers();
            }
            pthread_tsd::run_selected_worker_tsd_destructors(core::ptr::addr_of!((*control).tsd));
            publish_selected_worker_result(control, result);
        }
    }
    // SAFETY: Linux SYS_exit terminates precisely the calling task and does
    // not return. The CLONE_CHILD_CLEARTID lifecycle attached during clone
    // clears/wakes the joiner's shared child-TID word after this exit.
    unsafe { raw_syscall::syscall_noreturn1(raw_syscall::SYS_EXIT, 0) }
}

/// End one selected pthread-mode worker with its opaque pointer result.
///
/// This tags the result as pthread before the shared publisher checks that the
/// current control record was created in pthread mode.
#[inline(always)]
pub(super) unsafe fn exit_selected_pthread_worker(result: *mut c_void) -> ! {
    // SAFETY: the caller owns the selected pthread-mode exit boundary.
    unsafe { exit_selected_worker(SelectedWorkerResult::Pthread(result as usize)) }
}

/// End one selected C11-mode worker with its signed `int` result.
///
/// This preserves the C11 tag all the way through the shared registry
/// publication. If called from a pthread-mode control record, the publisher
/// records `Invalid` instead of allowing pthread_join to expose a C11 result
/// as a pointer.
#[inline(always)]
pub(super) unsafe fn exit_selected_c11_worker(result: c_int) -> ! {
    // SAFETY: the caller owns the selected C11-mode exit boundary.
    unsafe { exit_selected_worker(SelectedWorkerResult::C11(result)) }
}

/// Exit a selected pthread worker and publish its pointer result for its joiner.
///
/// This is valid only when called by a callback created through this leaf's
/// null-attribute pthread_create path. It invokes the selected cleanup and
/// worker-TSD destructor phases, but intentionally omits the rest of musl's
/// detach/thread-list state machine. Outside that worker contract, it still
/// performs Linux thread exit but claims no broader pthread behavior.
///
/// # Safety
///
/// The selected callback must not use any object after this call. Its result
/// must remain valid until its joining caller consumes it.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn pthread_exit(result: *mut c_void) -> ! {
    // SAFETY: this exported pthread boundary retains the selected worker-only
    // exit contract documented above.
    unsafe { exit_selected_pthread_worker(result) }
}

/// Join one selected worker and return its private pointer-sized result.
///
/// Both the pthread and C11 leaves invoke this ownership/reclamation boundary,
/// then decode the returned word according to their own typed result contract.
/// `thread` must be the still-live opaque TP returned by
/// [`create_selected_worker`]. No caller may use it after `Ok`, because the
/// full TLS and private control mappings have then been released.
///
/// # Safety
///
/// The opaque handle must name one selected live worker. The caller must not
/// concurrently join the same handle; broader pthread/C11 joining semantics
/// remain deliberately outside this slice.
#[inline(always)]
pub(super) unsafe fn join_selected_worker(
    thread: *mut c_void,
) -> Result<SelectedWorkerJoinResult, c_int> {
    if thread.is_null() {
        return Err(EINVAL);
    }
    // A later join boundary may reclaim already-finished detached workers,
    // but never touches a joinable worker or the handle this caller is about
    // to claim.
    reap_finished_detached_selected_workers();
    let Some(control) = claim_selected_worker_by_thread_pointer(
        thread,
        SelectedWorkerLifecycleState::JoinClaimed,
    ) else {
        return Err(EINVAL);
    };

    loop {
        // SAFETY: the handle remains mapped until this joining caller either
        // releases its claim on an error or successfully unmaps it below.
        let child_tid = unsafe { (*control).child_tid.load(Ordering::Acquire) };
        if child_tid == 0 {
            break;
        }
        if child_tid < 0 {
            unsafe { release_join_claim(control) };
            return Err(EINVAL);
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
            unsafe { release_join_claim(control) };
            return Err(error);
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
            unsafe { release_join_claim(control) };
            return Err(EINVAL);
        }
        unsafe { (*control).registry_retired.store(1, Ordering::Release) };
    }

    let worker_result = unsafe { (*control).result.load(Ordering::Relaxed) };
    let worker_result_kind =
        SelectedWorkerResultKind::decode(unsafe { (*control).result_kind.load(Ordering::Relaxed) });
    // The zero child-TID observation plus registry withdrawal above prove that
    // neither a running worker nor the selected pthread_exit scan can retain
    // either private mapping. Once withdrawn, a cold reclaim failure stays
    // fail-closed: there is no safe public retry path that republishes this
    // opaque handle.
    if let Err(error) = unsafe { reclaim_withdrawn_selected_worker(control) } {
        return Err(error);
    }
    Ok(SelectedWorkerJoinResult {
        encoded_result: worker_result,
        kind: worker_result_kind,
    })
}

/// Detach one selected worker without waiting for its callback to finish.
///
/// The state transition is result-representation-neutral, so the typed C11
/// sibling shares this seam without any function-pointer or result cast. A
/// successful call makes `thread` non-joinable immediately. It deliberately
/// performs no syscall or reclamation itself: the worker can still be using
/// its stack and Static Initial TLS v1 mapping. A later selected create/join
/// boundary reaps it only after `CLONE_CHILD_CLEARTID` has cleared the child
/// TID. This is a private bounded lifecycle, not a claim of general pthread
/// detached-thread semantics.
///
/// # Safety
///
/// `thread` must be the opaque TP returned by one selected pthread or C11
/// create call. The caller must not concurrently use that handle for another
/// ownership operation. Following a successful detach, it no longer denotes
/// an admitted joinable lifecycle handle. The candidate fixture's one-winner
/// ownership races exercise this private registry's fail-closed lifetime
/// boundary only; they do not select a concurrent public pthread/C11 contract.
#[inline(always)]
pub(super) unsafe fn detach_selected_worker(thread: *mut c_void) -> c_int {
    if thread.is_null() {
        return EINVAL;
    }
    let Some(_) = claim_selected_worker_by_thread_pointer(
        thread,
        SelectedWorkerLifecycleState::Detached,
    ) else {
        return EINVAL;
    };
    0
}

/// Detach one selected static pthread/C11 worker.
///
/// This boundary has the same private selected-worker requirements as
/// [`pthread_create`] and does not accept detached attributes or arbitrary
/// system pthread handles. It reports a positive errno and never writes the
/// calling thread's `errno` slot.
///
/// # Safety
///
/// `thread` must be one selected opaque thread handle. After a successful
/// return it is no longer valid for an admitted join operation.
#[no_mangle]
pub unsafe extern "C" fn pthread_detach(thread: *mut c_void) -> c_int {
    // SAFETY: this C boundary preserves the selected opaque-handle ownership
    // contract documented above.
    unsafe { detach_selected_worker(thread) }
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
    let worker_result = match unsafe { join_selected_worker(thread) } {
        Ok(worker_result) if worker_result.kind == SelectedWorkerResultKind::Pthread => {
            worker_result.encoded_result
        }
        Ok(_) => return EINVAL,
        Err(error) => return error,
    };
    if !result.is_null() {
        // SAFETY: the caller gave writable pointer-result storage and the
        // local value survives the just-completed worker mapping release.
        unsafe { core::ptr::write(result, worker_result as *mut c_void) };
    }
    0
}
