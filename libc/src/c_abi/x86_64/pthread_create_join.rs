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
//!   cleanup-before-TSD-destructor-before-result ordering, selected list
//!   transitions, initial-thread `pthread_exit`, and the last-thread ordinary
//!   exit decision. The separate deferred cancellation leaf owns active
//!   selected-worker cleanup records, explicit `pthread_testcancel`, and one
//!   paired private `pthread_cond_wait` cancellation point. The owned product
//!   additionally uses SIGCANCEL and its syscall PC window; normal robust
//!   mutex owner death composes through the selected robust-list owner.
//! - `src/thread/x86_64/clone.s::__clone` supplies the seven-argument SysV
//!   entry layout, `clone=56` register shuffle, aligned child-stack callback,
//!   and `exit=60` tail. The assembly below is a lexical private-symbol rename
//!   of that source.
//! - `src/thread/pthread_join.c` supplies the essential wait-before-reclaim
//!   ordering: a joiner waits for `CLONE_CHILD_CLEARTID` to clear the worker
//!   TID before it releases worker-owned memory. Its entry testcancel and
//!   disabled/masked state handling also govern the owned join path. Because
//!   this runtime additionally claims the target, it registers explicit
//!   cancellation cleanup to restore joinability before any user handlers.
//! - `src/thread/pthread_detach.c` supplies the single successful
//!   joinable-to-detached ownership transition. This selected artifact keeps
//!   musl's prompt detach shape but uses its established AArch64-style later
//!   external reaper because a worker cannot unmap its own active stack/TLS.
//!
//! The admitted contract is one selected worker: `pthread_create(NULL)` or an
//! initialized attribute record with a private guarded stack or an aligned
//! caller stack, a normal returning start routine or selected-worker
//! `pthread_exit`, and one `pthread_join` **or** `pthread_detach`. An
//! initialized record may request detached-at-create, but scheduler fields
//! fail closed with `ENOTSUP`; no scheduler transition is silently discarded.
//! The private C11 lifecycle sibling reuses the default allocation/clone/
//! join/detach seam through a distinct typed `int (*)(void *)` start mode; it
//! never reinterprets that callback as the pointer-returning pthread type.
//! The child gets a distinct copy of the
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
//! full pthread parity. It provides selected initial-thread `pthread_exit`
//! in both owned products and static fork child-list/TLS/TSD repair, but not
//! dynamic fork, scheduler application, GNU default attributes,
//! affinity attributes, live-thread inspection, or general pthread semantics.
//! Dynamic workers retain the loader's opaque allocation/release token through
//! the same create/join seam and logical initial/last-task accounting. The
//! dynamic startup owner runs executable/loader finalization for the final
//! task; dynamic fork still requires a separate loader transaction.
//! It
//! leaves caller `errno` untouched because pthread APIs report errors as
//! positive return values. Each selected worker carries its
//! own private mapped list node; creation is limited by actual mapping/TLS
//! allocation, not an artifact-local numeric registry ceiling.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread create/join leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

use super::{
    pthread_cancel, pthread_cond, pthread_identity, pthread_mutex, pthread_tsd, raw_syscall,
    static_tls,
};

const EAGAIN: c_int = 11;
const EINTR: c_int = 4;
const EINVAL: c_int = 22;
const ENOTSUP: c_int = 95;
const LINUX_ERRNO_MAX: i64 = 4_095;

const PROT_NONE: i64 = 0;
const PROT_READ_WRITE: i64 = 0x3;
const MAP_PRIVATE_ANONYMOUS: i64 = 0x22;
const FUTEX_WAIT: i64 = 0;
const PAGE_SIZE: usize = 4_096;

/// Publish the process-main selected cancellation state after its TLS owner
/// established the documented FS+32 cache word.
///
/// The static startup and materialized dynamic startup composition boundaries
/// call this before any constructor or application callback can execute. The
/// backing state is process-lifetime storage, so unlike a worker record it
/// has no registry membership or mapped-control retirement edge. The first
/// cancellation request installs the source handler before delivering through
/// the lifecycle-owned target transaction.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) unsafe fn publish_initial_selected_pthread_cancellation_state() {
    // SAFETY: each selected process startup calls this only after its static
    // or dynamic TLS owner installed the concrete x86 TCB and before it
    // exposes constructor/application execution on this initial task.
    unsafe {
        pthread_identity::publish_current_selected_cancellation_state(
            pthread_cancel::main_cancellation_state(),
        )
    };
    INITIAL_SIGNAL_TARGET_TP.store(pthread_identity::current_thread_pointer() as usize, Ordering::Relaxed);
    INITIAL_SIGNAL_TARGET_CANCELLATION.store(pthread_cancel::main_cancellation_state() as usize, Ordering::Relaxed);
    INITIAL_SIGNAL_TARGET_TID.store(current_linux_thread_id().unwrap_or(0), Ordering::Release);
}

// The initial task has no reclaimable registry mapping. Fork may adopt a
// worker's permanently retained mapping as main, including its cancellation
// state; these identities are republished only by startup or the sole child.
static INITIAL_SIGNAL_TARGET_LOCK: AtomicU8 = AtomicU8::new(0);
static INITIAL_SIGNAL_TARGET_TID: AtomicI32 = AtomicI32::new(0);
static INITIAL_SIGNAL_TARGET_TP: AtomicUsize = AtomicUsize::new(0);
static INITIAL_SIGNAL_TARGET_CANCELLATION: AtomicUsize = AtomicUsize::new(0);

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

/// Static-archive fallback for musl's private membarrier registration hook.
///
/// Musl 1.2.6 `src/thread/pthread_create.c` exposes its inert `dummy_0()`
/// through `weak_alias(dummy_0, __membarrier_init)`. Its separate
/// `src/linux/membarrier.c` object supplies the real strong registration body
/// only when that optional membarrier support is linked. Preserve the weak
/// static binding next to the selected `pthread_create` owner so a stronger
/// application or runtime spelling can replace it.
///
/// This selected worker seam does not call the fallback. It therefore neither
/// invokes Linux `membarrier`, registers a private expedited command, nor
/// selects the public membarrier API, dynamic TLS, loader state, or a general
/// multi-threaded process-startup policy.
#[inline(never)]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __membarrier_init() {}

// Keep the control record in a private page-aligned anonymous mapping. Static
// Initial TLS v1 owns a second exact PT_TLS materialization. A private worker
// stack is a third mapping with an optional inaccessible lower guard; a
// caller-provided stack remains caller-owned. None of these mappings guesses
// an errno offset or overlays user TLS.
const CONTROL_REGION_SIZE: usize = 4_096;

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

/// One task's membership in the private last-thread transition.
///
/// This is deliberately distinct from [`SelectedWorkerLifecycleState`]: the
/// latter chooses join/detach ownership for a control mapping, whereas this
/// state commits a running task to `pthread_exit`.  Keeping both task-state
/// publications under the list lock gives exactly one final selected task the
/// ordinary process-exit route while all earlier tasks use `SYS_exit`.
#[derive(Clone, Copy, Eq, PartialEq)]
enum SelectedRuntimeTaskState {
    Active,
    ExitCommitted,
}

impl SelectedRuntimeTaskState {
    const ACTIVE: u8 = 0;
    const EXIT_COMMITTED: u8 = 1;

    #[inline]
    const fn encode(self) -> u8 {
        match self {
            Self::Active => Self::ACTIVE,
            Self::ExitCommitted => Self::EXIT_COMMITTED,
        }
    }
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

/// Actual usable stack bounds after allocation and the clone alignment rule.
///
/// `top - size` excludes the private lower guard. TLS/control mappings have
/// separate owners and are never included in this application stack range.
#[derive(Clone, Copy)]
pub(super) struct SelectedThreadStackBounds {
    pub(super) top: usize,
    pub(super) size: usize,
    pub(super) guard_size: usize,
}

/// A registry-protected value snapshot for the GNU live-attribute query.
///
/// Only the original kernel-stack task has `stack == None`; its stack grows
/// independently of pthread creation and uses musl's auxv/mremap probe. A
/// fork-adopted worker retains its actual inherited stack bounds instead.
#[derive(Clone, Copy)]
pub(super) struct SelectedThreadAttributes {
    pub(super) stack: Option<SelectedThreadStackBounds>,
    pub(super) detached: bool,
}

// Protected by SELECTED_WORKER_REGISTRY_LOCK. Only the sole fork child changes
// this process-lifetime snapshot when it adopts a worker as its initial task.
static mut INITIAL_THREAD_ATTRIBUTES: SelectedThreadAttributes = SelectedThreadAttributes {
    stack: None,
    detached: false,
};

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
    // A linked detached record begins with a zero child-TID before clone has
    // installed the kernel clear-child-tid ownership. It therefore remains
    // reaper-ineligible until the parent has completed the clone result and
    // published the opaque handle to its caller. This closes both the
    // pre-clone `Detached + child_tid == 0` ambiguity and a fast child's exit
    // before the creating caller receives its handle.
    creator_handoff_pending: AtomicU8,
    // A pthread_cancel caller that found this control under the registry lock
    // may need to wake its mapped condition barrier after that lock is
    // released. This count pins the control mapping for exactly that tiny
    // post-lock syscall interval; join/detached reclamation waits for zero
    // before unmapping. It is not a worker quota or lifecycle state.
    cancellation_wake_leases: AtomicUsize,
    // This is the worker's logical task-list state, not its join/detach
    // ownership. A worker marks ExitCommitted while the registry lock is
    // held, after cleanup/TSD/result publication but before it reaches
    // SYS_exit. The one transition that observes no other Active task owns
    // ordinary process exit through the selected static or dynamic startup
    // owner; loader-owned TLS mappings retain their independent lifetime.
    task_state: AtomicU8,
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
    // Musl's per-thread killlock prevents a caller from targeting a recycled
    // Linux TID while this worker commits to retirement. The syscall-
    // cancellation owner blocks all caller signals before it takes this
    // target lock; an exiting worker clears `worker_tid` under it after
    // the static task-list decision and before its non-final Linux exit. It is neither the registry lock nor a public pthread lock.
    signal_target_lock: AtomicU8,
    // A target syscall starts with a registry-protected lookup, then retains
    // this mapping lease while it acquires `signal_target_lock` and issues its
    // raw `tgkill`. Registry withdrawal closes new leases; reclamation drains
    // existing ones before it can unmap this control record. This is distinct
    // from the condition-wait barrier lease above.
    signal_target_leases: AtomicUsize,
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
    // separately from this control allocation. A failed later-map reclamation
    // retry must not unmap the TLS image twice.
    tls_released: AtomicU8,
    // A private worker stack has a lower guard and is distinct from the
    // control mapping so an initialized pthread_attr_t can select an exact
    // stack size or a caller-owned stack without weakening control lifetime.
    // A null mapping/zero length means caller-owned and therefore never gets
    // unmapped by this lifecycle owner.
    stack_released: AtomicU8,
    stack_mapping: *mut u8,
    stack_mapping_size: usize,
    // Immutable usable bounds are distinct from the mapping span reclaimed
    // by join: caller-provided stacks have bounds but no owned mapping.
    stack_bounds: SelectedThreadStackBounds,
    control_mapping: *mut u8,
    tls_block: static_tls::StaticInitialTlsBlock,
    // The selected TSD leaf owns its values in this private worker mapping,
    // not in the Static Initial TLS v1 `%fs:0` self word. The mapping remains
    // live through the destructor phase and clear-child-tid handoff.
    tsd: pthread_tsd::SelectedTsdValues,
    // Musl's current-thread robust-list record stays in the same private
    // control mapping as this worker's cancellation/TSD state. It remains
    // valid through selected exit's owner-death walk and the later
    // clear-child-tid join/detached reclamation proof.
    robust_list: pthread_mutex::SelectedRobustList,
    // The selected pthread-only condition cancellation point cannot expose a
    // stack waiter to a concurrent pthread_cancel caller. This durable node
    // stays inside the control mapping that already outlives task exit until
    // join/detach reclamation. C11 workers retain ordinary stack waiters.
    condition_waiter: pthread_cond::SelectedPthreadConditionWaiter,
    // Each control allocation contributes its own intrusive list node. The
    // registry lock owns every link update, so this removes the former
    // artifact-only fixed worker ceiling without an allocator or side table.
    registry_previous: *mut ThreadControl,
    registry_next: *mut ThreadControl,
    cancellation: pthread_cancel::SelectedWorkerCancellation,
    start: SelectedWorkerStart,
    argument: *mut c_void,
}

// The head changes only while the registry lock is held. It is atomic solely
// to avoid `static mut`; it does not make lock-free traversal permissible.
static SELECTED_WORKER_REGISTRY_HEAD: AtomicUsize = AtomicUsize::new(0);

// The lock covers every registry mutation and the complete scan-to-publish
// interval. It is deliberately held only for bounded local atomics: never
// across clone, callback execution, futex wait, exit, munmap, or another
// syscall. Signal-handler/reentrant pthread_exit behavior is outside this
// private artifact because a signal interrupting a holder could otherwise
// deadlock here.
static SELECTED_WORKER_REGISTRY_LOCK: AtomicU8 = AtomicU8::new(0);

// The bootstrapped initial task is not backed by a worker control mapping,
// but participates in the same locked last-thread transition in both owned
// products. The static TLS or dynamic loader owner retains its mapping for
// process lifetime, including after this initial Linux task has exited.
static SELECTED_INITIAL_THREAD_TASK_STATE: AtomicU8 =
    AtomicU8::new(SelectedRuntimeTaskState::ACTIVE);

const _: () = {
    assert!(size_of::<AtomicI32>() == size_of::<c_int>());
    assert!(align_of::<AtomicI32>() == align_of::<c_int>());
    assert!(size_of::<usize>() >= size_of::<c_int>());
    assert!(size_of::<ThreadControl>() <= CONTROL_REGION_SIZE);
    assert!(CONTROL_REGION_SIZE == PAGE_SIZE);
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
    let result: i64;
    // SAFETY: SYS_gettid has no arguments and its Linux/x86-64 result is read
    // only as the bounded private worker identity described above. Keeping the
    // instruction adjacent to that identity check avoids relying on a generic
    // raw-syscall wrapper's cross-item inlining in pthread_exit's audited
    // foreign-thread rejection path.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") raw_syscall::SYS_GETTID => result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if is_linux_error(result) || result <= 0 || result > i64::from(c_int::MAX) {
        return None;
    }
    Some(result as c_int)
}

/// Read the current process's Linux thread-group identifier for a targeted
/// signal transaction.
///
/// Linux's `getpid` result is the `tgid` accepted by `tgkill`. Keep this raw
/// scalar observation beside the worker target-lifetime seam: it neither
/// reads the process-global C ABI state nor exposes a public process API.
#[inline(always)]
fn current_linux_thread_group_id() -> Option<c_int> {
    let result = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETPID) };
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

/// Acquire one worker's private source-shaped kill/exit exclusion lock.
///
/// The caller must not hold the selected-worker registry lock. A cancellation
/// requester blocks all signals before this spin acquisition; an exiting
/// worker has disabled cancellation and blocked application signals before it
/// begins the matching retirement transition. Those two admission rules avoid
/// an asynchronously abandoned target lock without turning this into a public
/// signal or pthread synchronization primitive.
#[inline]
unsafe fn lock_selected_worker_signal_target(control: *mut ThreadControl) {
    while unsafe {
        (*control)
            .signal_target_lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
    }
    .is_err()
    {
        while unsafe { (*control).signal_target_lock.load(Ordering::Relaxed) } != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Release one worker's private target kill/exit exclusion lock.
#[inline]
unsafe fn unlock_selected_worker_signal_target(control: *mut ThreadControl) {
    unsafe { (*control).signal_target_lock.store(0, Ordering::Release) };
}

#[inline]
fn current_is_selected_initial_thread() -> bool {
    static_tls::is_initial_thread_pointer(pthread_identity::current_thread_pointer())
}

/// Enter ordinary process exit after the unique final-task transition.
///
/// The pthread registry owns only logical task accounting. The selected
/// startup owner retains atexit/executable/loader finalization and stdio
/// ordering; loader TLS is never released merely because its initial task
/// retired while another worker remained alive.
#[inline(always)]
unsafe fn exit_selected_final_runtime_task() -> ! {
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    unsafe { super::owned_dynamic_runtime::exit(0) }
    #[cfg(not(feature = "x86-owned-dynamic-runtime"))]
    unsafe { super::static_startup::exit(0) }
}

/// Mark the selected initial task committed to exit and report whether it is
/// the unique final task.
///
/// Kernel `child_tid` values cannot make this decision: two workers can both
/// see the other's still-positive TID and each take `SYS_exit`. The logical
/// task-state store and the following scan occur under one list lock, so only
/// the transition that commits the final Active task returns true.
fn selected_initial_thread_is_final_runtime_task() -> bool {
    lock_selected_worker_registry();
    SELECTED_INITIAL_THREAD_TASK_STATE.store(
        SelectedRuntimeTaskState::EXIT_COMMITTED,
        Ordering::Release,
    );
    let mut control = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Acquire) as *mut ThreadControl;
    let mut another_active_task = false;
    while !control.is_null() {
        // SAFETY: the list lock retains this control mapping through the
        // task-state observation. A linked pre-clone control begins Active,
        // so a creating selected worker cannot be lost from this decision.
        if unsafe { (*control).task_state.load(Ordering::Acquire) }
            == SelectedRuntimeTaskState::ACTIVE
        {
            another_active_task = true;
            break;
        }
        control = unsafe { (*control).registry_next };
    }
    unlock_selected_worker_registry();
    !another_active_task
}

/// Commit one selected worker to exit and report whether it is the unique
/// final task.
///
/// The commit follows user cleanup, selected TSD destructors, and result
/// publication. It is therefore the selected analogue of musl's locked
/// thread-list unlink point, but keeps the control mapped for join/detach
/// reclamation. Once committed, a task cannot be counted as another thread's
/// live sibling even if Linux has not yet cleared its child-TID word.
fn selected_worker_is_final_runtime_task(control: *mut ThreadControl) -> bool {
    lock_selected_worker_registry();
    // SAFETY: current-worker identity retains this linked control mapping
    // until its calling task invokes SYS_exit.
    unsafe {
        (*control).task_state.store(
            SelectedRuntimeTaskState::EXIT_COMMITTED,
            Ordering::Release,
        )
    };
    if SELECTED_INITIAL_THREAD_TASK_STATE.load(Ordering::Acquire)
        == SelectedRuntimeTaskState::ACTIVE
    {
        unlock_selected_worker_registry();
        return false;
    }
    let mut cursor = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Acquire) as *mut ThreadControl;
    let mut another_active_task = false;
    while !cursor.is_null() {
        if cursor != control
            // SAFETY: list membership keeps this control live while the
            // transition observes its logical task state under the same lock.
            && unsafe { (*cursor).task_state.load(Ordering::Acquire) }
                == SelectedRuntimeTaskState::ACTIVE
        {
            another_active_task = true;
            break;
        }
        // SAFETY: cursor remains linked/mapped through this locked traversal.
        cursor = unsafe { (*cursor).registry_next };
    }
    unlock_selected_worker_registry();
    !another_active_task
}

/// Whether any selected worker control remains linked.
///
/// The current atfork boundary consumes this as a conservative admission
/// predicate. A creator links its fully initialized control before clone, so
/// every possible child-visible worker has a list node; before that point no
/// child exists and a concurrent parent-side fork needs no stale reservation.
pub(super) fn has_live_selected_workers() -> bool {
    lock_selected_worker_registry();
    let live = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Acquire) != 0;
    unlock_selected_worker_registry();
    live
}

/// Musl needs loader callback exclusion only while another task can own it.
/// Read logical task state under the registry lock, then release this snapshot
/// before acquiring the outer loader transaction. With no other live task,
/// no sibling can race a new creation after this observation.
#[cfg(feature = "x86-owned-dynamic-runtime")]
pub(super) fn fork_has_other_runtime_tasks() -> bool {
    let current = pthread_identity::current_thread_pointer() as usize;
    lock_selected_worker_registry();
    let mut other = current != INITIAL_SIGNAL_TARGET_TP.load(Ordering::Acquire)
        && SELECTED_INITIAL_THREAD_TASK_STATE.load(Ordering::Acquire) == SelectedRuntimeTaskState::ACTIVE;
    let mut node = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Acquire) as *mut ThreadControl;
    while !other && !node.is_null() {
        other = unsafe { (*node).tls_block.thread_pointer() } as usize != current
            && unsafe { (*node).task_state.load(Ordering::Acquire) } == SelectedRuntimeTaskState::ACTIVE;
        node = unsafe { (*node).registry_next };
    }
    unlock_selected_worker_registry();
    other
}

/// Lock the selected worker list for one raw-fork transaction.
///
/// The caller must pair this with exactly one parent or child completion. The
/// lock serializes list publication/withdrawal with the fork snapshot, but is
/// never held across user callbacks, allocation, clone, join wait, or any
/// operation other than the one raw fork syscall.
pub(super) fn pthread_fork_prepare() {
    lock_selected_worker_registry();
}

/// Release the parent-side selected-worker fork transaction.
pub(super) unsafe fn pthread_fork_parent() {
    unlock_selected_worker_registry();
}

/// Install the child's clear-child-TID address inside the all-signal-blocked
/// process-lock transaction, matching musl _Fork::__post_Fork before it unlocks
/// __abort_lock. The copied word has process lifetime in the sole child.
pub(super) unsafe fn register_fork_child_kernel_tid() -> c_int {
    static FORK_CHILD_TID: AtomicI32 = AtomicI32::new(0);
    let tid = unsafe { raw_syscall::syscall1(
        raw_syscall::SYS_SET_TID_ADDRESS, core::ptr::addr_of!(FORK_CHILD_TID) as i64,
    ) } as c_int;
    FORK_CHILD_TID.store(tid, Ordering::Release);
    tid
}

/// Re-root selected worker state in the post-fork child.
///
/// The child retains only its calling task. Every inherited selected worker
/// control represents either a vanished sibling or (when the caller was a
/// worker) the now-main task whose active mapping must not be reclaimed. Make
/// all old handles unreachable without unmapping any inherited live stack/TLS
/// range; the static TLS/TSD owners separately adopt the caller's identity
/// and values before this reset. Future child workers start a fresh list.
pub(super) unsafe fn pthread_fork_child(child_tid: c_int) {
    let thread_pointer = pthread_identity::current_thread_pointer();
    let inherited_worker = selected_worker_by_thread_pointer_locked(thread_pointer as usize);
    unsafe { adopt_process_child(child_tid, inherited_worker) };
}

// A sole child may forget the inherited registry without reading its links.
// A fork caller supplies its locked lookup; clone supplies only its own pinned
// control, so unrelated partially updated links are never traversed.
unsafe fn adopt_process_child(child_tid: c_int, inherited_worker: Option<*mut ThreadControl>) {
    let thread_pointer = pthread_identity::current_thread_pointer();
    if let Some(control) = inherited_worker {
        // SAFETY: fork's locked lookup or clone's caller-owned snapshot
        // retains this mapped control through sole-child adoption.
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!(INITIAL_THREAD_ATTRIBUTES),
                selected_worker_attributes_locked(control),
            );
        }
    }
    let inherited_worker_list = inherited_worker.map(|control| {
        // SAFETY: the copied registry lock keeps this inherited control
        // mapped until this function clears the child list head.
        unsafe { core::ptr::addr_of_mut!((*control).robust_list) }
    });
    if let Some(list) = inherited_worker_list {
        // SAFETY: retain the fork caller's linked robust nodes in its still
        // mapped control record, but force a fresh child kernel registration
        // before its next process-shared robust transition.
        unsafe { pthread_mutex::adopt_selected_initial_robust_list_after_fork(list) };
    } else {
        // SAFETY: a bootstrapped main keeps its process-lifetime list record;
        // musl `_Fork` clears only copied registration/pending state.
        unsafe { pthread_mutex::reset_selected_initial_robust_list_after_fork() };
    }
    INITIAL_SIGNAL_TARGET_LOCK.store(0, Ordering::Relaxed);
    INITIAL_SIGNAL_TARGET_TP.store(thread_pointer as usize, Ordering::Relaxed);
    INITIAL_SIGNAL_TARGET_CANCELLATION.store(
        pthread_identity::current_selected_cancellation_state() as usize,
        Ordering::Relaxed,
    );
    INITIAL_SIGNAL_TARGET_TID.store(child_tid, Ordering::Release);
    SELECTED_WORKER_REGISTRY_HEAD.store(0, Ordering::Release);
    SELECTED_INITIAL_THREAD_TASK_STATE.store(SelectedRuntimeTaskState::ACTIVE, Ordering::Release);
    SELECTED_WORKER_REGISTRY_LOCK.store(0, Ordering::Release);
}

/// The calling task's control is pinned by its own execution, independently
/// of the mutable worker registry. The cancellation cache is installed before
/// user entry and removed only at retirement. This owned-only snapshot lets
/// public clone perform musl's minimal __post_Fork without taking a list lock
/// that could already be held by an interrupted thread.
#[cfg(feature = "x86-owned-static-runtime")]
#[derive(Clone, Copy)]
pub(super) struct CloneCaller(Option<*mut ThreadControl>);

/// # Safety
/// The caller is an initialized owned task with all signals blocked. Its
/// control remains live through the raw clone result and sole-child adoption.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) unsafe fn clone_caller() -> CloneCaller {
    let pointer = pthread_identity::current_thread_pointer();
    if static_tls::is_initial_thread_pointer(pointer) {
        CloneCaller(None)
    } else {
        let cancellation = pthread_identity::current_selected_cancellation_state();
        // SAFETY: every owned non-main caller has its live control's embedded
        // cancellation state in fs:32. Its own execution pins that mapping.
        CloneCaller(Some(unsafe { cancellation.cast::<u8>().sub(
            core::mem::offset_of!(ThreadControl, cancellation),
        ) as *mut ThreadControl }))
    }
}

/// # Safety
/// Call once in the sole non-CLONE_VM child, with every signal still blocked
/// and the copied caller control mapped, before restoring signals or callbacks.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) unsafe fn clone_child(caller: CloneCaller) {
    let tid = unsafe { register_fork_child_kernel_tid() };
    let values = caller.0.map(|control| unsafe { core::ptr::addr_of!((*control).tsd) });
    unsafe { pthread_tsd::adopt_clone_caller_values(values) };
    if !static_tls::adopt_current_thread_after_fork() {
        super::immediate_termination::_Exit(127);
    }
    unsafe { adopt_process_child(tid, caller.0) };
}

/// Return an inherited worker's TSD table during a child fork reset.
///
/// This intentionally omits normal Linux-TID/child-TID validation: fork gave
/// the sole child task a new TID, and the caller holds the copied list lock
/// until it has copied this table into child-main state and unlinked every old
/// worker control.
pub(super) fn current_selected_worker_tsd_values_after_fork(
    thread_pointer: *mut u8,
) -> Option<*const pthread_tsd::SelectedTsdValues> {
    if thread_pointer.is_null() {
        return None;
    }
    let control = selected_worker_by_thread_pointer_locked(thread_pointer as usize)?;
    // SAFETY: the fork coordinator owns the list lock, and this linked control
    // remains mapped until it clears the head in `pthread_fork_child`.
    Some(unsafe { core::ptr::addr_of!((*control).tsd) })
}

/// Link a fully initialized selected control before the child can run.
///
/// The control's release flag follows every non-atomic initialization write.
/// The intrusive node stays linked until join or detached reaping has observed
/// the kernel clear-child-tid handoff and is ready to release its mappings.
fn publish_selected_worker(control: *mut ThreadControl) {
    lock_selected_worker_registry();
    let previous_head = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Relaxed) as *mut ThreadControl;
    // SAFETY: `control` is a fresh private mapping and every linked mapping
    // remains live while it is reachable from this lock-protected list.
    unsafe {
        (*control).registry_previous = core::ptr::null_mut();
        (*control).registry_next = previous_head;
        if !previous_head.is_null() {
            (*previous_head).registry_previous = control;
        }
    }
    SELECTED_WORKER_REGISTRY_HEAD.store(control as usize, Ordering::Release);
    unlock_selected_worker_registry();
}

/// Remove a known linked selected control while the registry lock is held.
///
/// A successful removal proves no registry scanner can retain this mapping
/// beyond the lock. The caller may then reclaim it after its separate kernel
/// child-TID lifetime proof. A missing node is retained fail-closed.
fn release_selected_worker_locked(control: *mut ThreadControl) -> bool {
    let mut cursor = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Acquire) as *mut ThreadControl;
    while !cursor.is_null() {
        if cursor == control {
            // SAFETY: the lock keeps every traversed control mapped. The
            // predecessor/successor fields are changed only in this function
            // or `publish_selected_worker`, under the same lock.
            unsafe {
                let previous = (*control).registry_previous;
                let next = (*control).registry_next;
                if previous.is_null() {
                    SELECTED_WORKER_REGISTRY_HEAD.store(next as usize, Ordering::Release);
                } else {
                    (*previous).registry_next = next;
                }
                if !next.is_null() {
                    (*next).registry_previous = previous;
                }
                (*control).registry_previous = core::ptr::null_mut();
                (*control).registry_next = core::ptr::null_mut();
            }
            return true;
        }
        // SAFETY: cursor is a still-linked mapping for the lock duration.
        cursor = unsafe { (*cursor).registry_next };
    }
    false
}

/// Find a selected worker by its opaque x86 Variant-II thread pointer.
///
/// The caller holds the registry lock and must not retain the result after it
/// releases that lock unless it has independently claimed the lifecycle or is
/// the currently running worker with a positive child-TID.
fn selected_worker_by_thread_pointer_locked(thread_pointer: usize) -> Option<*mut ThreadControl> {
    let mut control = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Acquire) as *mut ThreadControl;
    while !control.is_null() {
        // SAFETY: list membership under the lock proves the control mapping is
        // live; the TLS block's opaque token exposes only its thread pointer.
        if unsafe { (*control).tls_block.thread_pointer() as usize } == thread_pointer {
            return Some(control);
        }
        control = unsafe { (*control).registry_next };
    }
    None
}

/// Copy a linked worker's immutable stack bounds and current detach state.
/// The caller holds the registry lock, which serializes detach and withdrawal.
unsafe fn selected_worker_attributes_locked(control: *mut ThreadControl) -> SelectedThreadAttributes {
    let lifecycle = unsafe { (*control).lifecycle.load(Ordering::Acquire) };
    SelectedThreadAttributes {
        stack: Some(unsafe { (*control).stack_bounds }),
        detached: lifecycle == SelectedWorkerLifecycleState::DETACHED
            || lifecycle == SelectedWorkerLifecycleState::DETACHED_RECLAIMING,
    }
}

/// Observe owned pthread metadata without retaining a mapped-control pointer.
///
/// Registry withdrawal and detach serialize with this copy. The returned
/// integers describe a snapshot, not a lease permitting later stack access.
/// The caller must still own the public handle lifetime while using it.
pub(super) fn selected_thread_attributes(thread: *mut c_void) -> Option<SelectedThreadAttributes> {
    if thread.is_null() {
        return None;
    }
    // A signal handler can reenter the registry, and asynchronous cancellation
    // can exit without unwinding. Neither may interrupt this snapshot lock.
    let mut saved_mask = 0_u64;
    unsafe { super::signal_execution::block_all_signals(&mut saved_mask) };
    lock_selected_worker_registry();
    let attributes = if thread as usize == INITIAL_SIGNAL_TARGET_TP.load(Ordering::Acquire) {
        // SAFETY: this process-lifetime value is written only by the sole
        // fork child under the same copied registry lock.
        Some(unsafe { core::ptr::read(core::ptr::addr_of!(INITIAL_THREAD_ATTRIBUTES)) })
    } else {
        selected_worker_by_thread_pointer_locked(thread as usize)
            .map(|control| unsafe { selected_worker_attributes_locked(control) })
    };
    unlock_selected_worker_registry();
    unsafe { super::signal_execution::restore_application_signals(&saved_mask) };
    attributes
}

/// Mark one live selected pthread worker for deferred cancellation.
///
/// The registry lock covers handle validation, pending-bit update, active
/// condition-barrier lookup, and any wake-lease increment. The paired
/// condition waiter withdraws its barrier under this same lock and drains all
/// pre-withdrawal leases before it resets that mapped storage. No signal is
/// sent: this artifact observes a request at explicit `pthread_testcancel` or
/// the one selected private condition point.
pub(super) fn request_selected_pthread_cancellation(thread: *mut c_void) -> bool {
    if thread.is_null() {
        return false;
    }
    lock_selected_worker_registry();
    let mut wake = None;
    let requested = selected_worker_by_thread_pointer_locked(thread as usize)
        .filter(|control| unsafe { matches!((**control).start, SelectedWorkerStart::Pthread(_)) })
        .map(|control| {
            // SAFETY: list membership holds this control mapping live for the
            // pending store, and only a pthread-mode record is selected. A
            // non-null returned barrier is inside this same mapping; pin it
            // before the lock is released so a completed join/detached reaper
            // cannot unmap it before the post-lock futex wake below.
            let barrier = unsafe { pthread_cancel::mark_selected_worker_pending(&(*control).cancellation) };
            if let Some(barrier) = barrier {
                if !barrier.is_null() {
                    unsafe {
                        (*control)
                            .cancellation_wake_leases
                            .fetch_add(1, Ordering::AcqRel)
                    };
                    wake = Some((control, barrier));
                }
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    unlock_selected_worker_registry();
    if let Some((control, barrier)) = wake {
        // SAFETY: the registry-protected lease keeps this control-mapped
        // barrier valid until the matching decrement. The helper changes the
        // word before waking, so the target cannot lose a request that lands
        // immediately before its futex sleep.
        unsafe { pthread_cond::wake_selected_pthread_condition_waiter(barrier) };
        // SAFETY: the same lease proves the control remains mapped for this
        // final bounded atomic decrement; reclaimers wait for it to reach zero
        // before they release any mapping from this record.
        unsafe {
            (*control)
                .cancellation_wake_leases
                .fetch_sub(1, Ordering::Release)
        };
    }
    requested
}

/// Execute one signal transaction while the target's Linux TID cannot retire.
///
/// Lookup pins the mapping under the registry lock, then drops that lock before
/// acquiring the target kill lock. The callback may update pending state and
/// issue raw `tgkill`; it must not retain the cancellation pointer, invoke user
/// code, or enter another lifecycle transaction. `None` rejects an unknown
/// handle; `Some(0)` accepts an already retired target without invoking the
/// callback. A target that has not entered its trampoline uses the kernel's
/// parent-written child TID until the worker publishes its identity.
///
/// # Safety
/// The caller must block all signals through this entire call, including the
/// lease decrement, so asynchronous cancellation cannot abandon either lock
/// or the mapping lease. The callback must return normally.
pub(super) unsafe fn with_selected_pthread_signal_target(
    thread: *mut c_void,
    callback: impl FnOnce(c_int, c_int, *const pthread_cancel::SelectedWorkerCancellation) -> c_int,
) -> Option<c_int> {
    if thread.is_null() {
        return None;
    }
    let tgid = current_linux_thread_group_id()?;
    if thread as usize == INITIAL_SIGNAL_TARGET_TP.load(Ordering::Acquire) {
        while INITIAL_SIGNAL_TARGET_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        let tid = INITIAL_SIGNAL_TARGET_TID.load(Ordering::Acquire);
        let result = if tid > 0 {
            callback(tgid, tid, INITIAL_SIGNAL_TARGET_CANCELLATION.load(Ordering::Acquire) as *const _)
        } else { 0 };
        INITIAL_SIGNAL_TARGET_LOCK.store(0, Ordering::Release);
        return Some(result);
    }
    lock_selected_worker_registry();
    let control = selected_worker_by_thread_pointer_locked(thread as usize);
    if let Some(control) = control {
        unsafe { (*control).signal_target_leases.fetch_add(1, Ordering::AcqRel) };
    }
    unlock_selected_worker_registry();
    let control = control?;
    // SAFETY: this lease survives withdrawal and pins the target lock and
    // cancellation state until the final decrement below.
    unsafe { lock_selected_worker_signal_target(control) };
    let mut tid = unsafe { (*control).worker_tid.load(Ordering::Acquire) };
    if tid == -1 {
        tid = unsafe { (*control).child_tid.load(Ordering::Acquire) };
    }
    let result = if tid > 0 {
        callback(tgid, tid, unsafe { core::ptr::addr_of!((*control).cancellation) })
    } else { 0 };
    unsafe {
        unlock_selected_worker_signal_target(control);
        (*control).signal_target_leases.fetch_sub(1, Ordering::Release);
    }
    Some(result)
}

/// Withdraw the current target TID before the task can reach Linux exit.
/// Cancellation is disabled and application signals are blocked by the caller.
unsafe fn retire_selected_worker_signal_target(control: *mut ThreadControl) {
    let mut saved_mask = 0_u64;
    unsafe {
        super::signal_execution::block_all_signals(&mut saved_mask);
        lock_selected_worker_signal_target(control);
        (*control).worker_tid.store(0, Ordering::Release);
        unlock_selected_worker_signal_target(control);
        super::signal_execution::restore_application_signals(&saved_mask);
    }
}

unsafe fn retire_initial_signal_target() {
    while INITIAL_SIGNAL_TARGET_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    INITIAL_SIGNAL_TARGET_TID.store(0, Ordering::Release);
    INITIAL_SIGNAL_TARGET_LOCK.store(0, Ordering::Release);
}

/// Resolve one live selected-worker handle to Linux's parent-written TID.
///
/// This is a scalar handoff for the pthread-affinity sibling, not a general
/// thread-list query. The list lock proves the matched mapping is live only
/// while its child-TID word is copied.
pub(super) fn selected_worker_linux_thread_id(thread: *mut c_void) -> Option<c_int> {
    if thread.is_null() {
        return None;
    }
    lock_selected_worker_registry();
    let thread_id = selected_worker_by_thread_pointer_locked(thread as usize).and_then(|control| {
        // SAFETY: lock-protected membership keeps the mapped control live.
        let child_tid = unsafe { (*control).child_tid.load(Ordering::Acquire) };
        (child_tid > 0).then_some(child_tid)
    });
    unlock_selected_worker_registry();
    thread_id
}

/// Withdraw a selected-worker list node without touching its mapping.
fn release_selected_worker(control: *mut ThreadControl) -> bool {
    lock_selected_worker_registry();
    let released = release_selected_worker_locked(control);
    unlock_selected_worker_registry();
    released
}

/// Claim the one selected worker named by its public x86 `pthread_t` value.
///
/// A lifecycle claim under the list lock gives the caller sole ownership until
/// it either releases that claim or completes reclamation, so a withdrawn
/// mapping can never be returned by a stale handle lookup.
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
    lock_selected_worker_registry();
    let claimed = selected_worker_by_thread_pointer_locked(thread as usize).and_then(|control| {
        // SAFETY: the list lock prevents withdrawal/reclamation through this
        // state transition.
        unsafe {
            (*control)
                .lifecycle
                .compare_exchange(
                    SelectedWorkerLifecycleState::Joinable.encode(),
                    claimed_state.encode(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
                .then_some(control)
        }
    });
    unlock_selected_worker_registry();
    claimed
}

/// Release a join claim before the worker has been withdrawn from the list.
unsafe fn release_join_claim(control: *mut ThreadControl) {
    // SAFETY: the joining caller still owns a linked control on every error
    // path reaching this helper.
    let _ = unsafe {
        (*control).lifecycle.compare_exchange(
            SelectedWorkerLifecycleState::JoinClaimed.encode(),
            SelectedWorkerLifecycleState::Joinable.encode(),
            Ordering::Release,
            Ordering::Relaxed,
        )
    };
}

/// Wait for the creator to finish publishing the opaque handle.
///
/// A child can disclose its own `pthread_self()` before `pthread_create`
/// returns. Another selected worker may then claim that handle and observe its
/// clear-child-tid before the creating parent writes its output slot. Keep the
/// linked control unreclaimable through that complete creator handoff.
#[inline]
unsafe fn wait_for_creator_handoff(control: *mut ThreadControl) {
    // SAFETY: a join claim keeps this control linked/mapped. The creator's
    // release follows the C output-store that made the public handle usable.
    while unsafe { (*control).creator_handoff_pending.load(Ordering::Acquire) } != 0 {
        core::hint::spin_loop();
    }
}

/// Wait for post-registry cancellation barrier wakes to finish.
///
/// A join claim or detached-reclamation withdrawal already prevents any new
/// caller from taking a lease. An earlier canceller may still be between its
/// registry unlock and futex wake, so no control/TLS/stack mapping may be
/// released until that short lease drains.
#[inline]
unsafe fn wait_for_cancellation_wake_leases(control: *mut ThreadControl) {
    while unsafe {
        (*control)
            .cancellation_wake_leases
            .load(Ordering::Acquire)
    } != 0
    {
        core::hint::spin_loop();
    }
}

/// Claim one exited detached worker while its control mapping remains linked.
fn claim_finished_detached_selected_worker() -> Option<*mut ThreadControl> {
    lock_selected_worker_registry();
    let mut control = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Acquire) as *mut ThreadControl;
    let mut claimed = None;
    while !control.is_null() {
        // SAFETY: list membership keeps this mapping live for the complete
        // state/clear-child-tid/withdraw transaction below.
        let detached = unsafe {
            (*control).lifecycle.load(Ordering::Acquire)
                == SelectedWorkerLifecycleState::Detached.encode()
        };
        if detached
            && unsafe { (*control).creator_handoff_pending.load(Ordering::Acquire) } == 0
            && unsafe { (*control).child_tid.load(Ordering::Acquire) } == 0
        {
            let claimed_reclamation = unsafe {
                (*control).lifecycle.compare_exchange(
                    SelectedWorkerLifecycleState::Detached.encode(),
                    SelectedWorkerLifecycleState::DetachedReclaiming.encode(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
            };
            if claimed_reclamation.is_ok() {
                // `CLONE_CHILD_CLEARTID` cannot restore a nonzero TID. Keep a
                // second observation adjacent to withdrawal so a future clone
                // change cannot free a stack still used by its child.
                if unsafe { (*control).creator_handoff_pending.load(Ordering::Acquire) } == 0
                    && unsafe { (*control).child_tid.load(Ordering::Acquire) } == 0
                    && release_selected_worker_locked(control)
                {
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
        }
        control = unsafe { (*control).registry_next };
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
#[inline(always)]
unsafe fn reclaim_withdrawn_selected_worker(control: *mut ThreadControl) -> Result<(), c_int> {
    // SAFETY: registry withdrawal admits no new wake lease, and an existing
    // one can still dereference only this control-mapped barrier. Drain it
    // before releasing any mapping that might otherwise invalidate that wake.
    unsafe { wait_for_cancellation_wake_leases(control) };
    // Registry withdrawal closes new target leases before any mapping unmap.
    while unsafe { (*control).signal_target_leases.load(Ordering::Acquire) } != 0 {
        core::hint::spin_loop();
    }

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
    if unsafe { (*control).stack_released.load(Ordering::Acquire) } == 0 {
        let stack_mapping = unsafe { (*control).stack_mapping };
        let stack_mapping_size = unsafe { (*control).stack_mapping_size };
        // A caller stack remains caller-owned even after the worker has
        // stopped. Private stacks are unmapped only after the same clear-tid
        // and registry-withdrawal proof that released the TLS block above.
        if !stack_mapping.is_null() {
            let stack_unmap_result = unsafe { unmap_worker(stack_mapping, stack_mapping_size) };
            if is_linux_error(stack_unmap_result) {
                return Err(positive_linux_error(stack_unmap_result));
            }
        }
        unsafe { (*control).stack_released.store(1, Ordering::Release) };
    }
    let control_mapping = unsafe { (*control).control_mapping };
    let unmap_result = unsafe { unmap_worker(control_mapping, CONTROL_REGION_SIZE) };
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
/// The exact `%fs:0`, Linux-TID, and live-child-TID match rejects a foreign
/// task that copied an owned TLS base. A positive child-TID then prevents join
/// or detached reaping from withdrawing this current mapping before it exits.
#[inline(always)]
fn current_selected_worker_control() -> Option<*mut ThreadControl> {
    let thread_pointer = pthread_identity::current_thread_pointer() as usize;
    let thread_id = current_linux_thread_id()?;
    if thread_pointer == 0 {
        return None;
    }
    lock_selected_worker_registry();
    let current = current_selected_worker_control_locked(thread_pointer, thread_id);
    unlock_selected_worker_registry();
    current
}

/// Resolve one current selected control while the caller owns the registry.
///
/// Keeping the `%fs:0`/Linux-TID/positive-child-TID proof in this helper lets
/// a condition waiter withdraw its published barrier in the same critical
/// section as a canceller's target lookup and wake-lease increment.
fn current_selected_worker_control_locked(
    thread_pointer: usize,
    thread_id: c_int,
) -> Option<*mut ThreadControl> {
    selected_worker_by_thread_pointer_locked(thread_pointer).filter(|control| {
        // SAFETY: lock-protected membership makes this identity observation
        // valid; the positive child-TID retains the current mapping after the
        // lock is released.
        unsafe {
            (**control).worker_tid.load(Ordering::Acquire) == thread_id
                && (**control).child_tid.load(Ordering::Acquire) == thread_id
        }
    })
}

/// Whether the current task is one selected worker that may enter fork.
///
/// This preserves the normal `%fs:0`/Linux-TID/live-child-TID identity check;
/// it is not a general thread admission query. The fork coordinator rechecks
/// and locks the list before raw fork, then uses its separate post-fork helper
/// because Linux assigns the child caller a new TID.
pub(super) fn is_current_selected_worker() -> bool {
    current_selected_worker_control().is_some()
}

/// Return the current selected pthread worker's embedded cancellation state.
pub(super) fn current_selected_pthread_worker_cancellation(
) -> Option<*const pthread_cancel::SelectedWorkerCancellation> {
    let control = current_selected_worker_control()?;
    // SAFETY: current-worker resolution keeps the control mapping live until
    // this task exits; C11 controls are intentionally not cancellation-aware.
    matches!(unsafe { (*control).start }, SelectedWorkerStart::Pthread(_))
        .then(|| unsafe { core::ptr::addr_of!((*control).cancellation) })
}

/// Return the current selected pthread worker's durable condition waiter.
///
/// The pointer is private to the condition cancellation transaction. Current
/// identity validation keeps this control mapping live until the worker exits;
/// the registry keeps it mapped after that exit until join/detach reclamation.
/// C11 workers intentionally return no waiter because their C11 condition
/// path is not a pthread cancellation point.
pub(super) fn current_selected_pthread_condition_waiter(
) -> Option<*const pthread_cond::SelectedPthreadConditionWaiter> {
    let control = current_selected_worker_control()?;
    matches!(unsafe { (*control).start }, SelectedWorkerStart::Pthread(_))
        .then(|| unsafe { core::ptr::addr_of!((*control).condition_waiter) })
}

/// Withdraw and drain the current selected pthread condition waiter's wake
/// leases before its control-mapped storage can be initialized for another
/// wait.
///
/// `pthread_cancel` takes the same registry lock around its active-barrier
/// load and lease increment. Once this function clears publication under that
/// lock, no new stale-barrier lease can begin; only then is it safe to wait
/// outside the lock for all earlier cancellers to finish their CAS/wake.
pub(super) fn withdraw_current_selected_pthread_condition_waiter(barrier: *mut c_int) {
    let thread_pointer = pthread_identity::current_thread_pointer() as usize;
    let Some(thread_id) = current_linux_thread_id() else {
        return;
    };
    if thread_pointer == 0 {
        return;
    }

    lock_selected_worker_registry();
    let control = current_selected_worker_control_locked(thread_pointer, thread_id).filter(|control| {
        // SAFETY: the registry lock keeps this matching control mapped for
        // its start-mode observation and atomic active-barrier withdrawal.
        unsafe { matches!((**control).start, SelectedWorkerStart::Pthread(_)) }
    });
    let withdrew = control
        .map(|control| {
            // SAFETY: the control remains linked and mapped under the held
            // registry lock. This is serialized with every cancellation
            // target lookup, active-barrier load, and lease increment.
            unsafe {
                pthread_cancel::withdraw_selected_pthread_condition_waiter(
                    &(*control).cancellation,
                    barrier,
                )
            }
        })
        .unwrap_or(false);
    unlock_selected_worker_registry();

    if let Some(control) = control {
        // SAFETY: withdrawal closed new leases before the lock release; every
        // earlier lease retains this control mapping until its wake completes.
        // Draining outside the registry lock lets those cancellers complete
        // their post-lock syscall/decrement without lock inversion.
        unsafe { wait_for_cancellation_wake_leases(control) };
        let _ = withdrew;
        debug_assert!(withdrew, "current selected condition waiter lost its active barrier");
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

/// Return the current selected worker's task-local robust-list record.
///
/// The caller may use the raw record only during the current task's robust
/// mutex transition. The same `%fs:0`, Linux-TID, and positive child-TID
/// proof that guards selected TSD state prevents a copied worker TLS base
/// from gaining a list pointer after task-ID reuse.
pub(super) fn current_selected_worker_robust_list(
) -> Option<*mut pthread_mutex::SelectedRobustList> {
    let control = current_selected_worker_control()?;
    // SAFETY: current-worker identity retains this control mapping until the
    // task exits; robust mutex operations retain no pointer after their
    // immediate link/unlink/owner-death transition.
    Some(unsafe { core::ptr::addr_of_mut!((*control).robust_list) })
}

/// Return a Linux task ID only for the bootstrapped selected initial task or
/// a fully validated selected worker.
///
/// The robust-mutex owner word carries this exact TID. Foreign tasks do not
/// receive it merely by calling a public mutex entry, which keeps their
/// caller-owned list links outside this selected lifecycle.
pub(super) fn current_selected_runtime_thread_id() -> Option<c_int> {
    if static_tls::is_initial_thread_pointer(pthread_identity::current_thread_pointer()) {
        return current_linux_thread_id();
    }
    current_selected_worker_control().and_then(|_| current_linux_thread_id())
}

/// Clear one key in every still-registry-published selected worker.
///
/// The TSD leaf calls this while holding its private metadata lock. This
/// helper then takes the selected-worker registry lock, preserving the one
/// TSD -> registry lock order. It invokes no user code and never retains a
/// control pointer beyond the scan.
pub(super) fn clear_selected_worker_tsd_key(key: usize) {
    lock_selected_worker_registry();
    let mut control = SELECTED_WORKER_REGISTRY_HEAD.load(Ordering::Acquire) as *mut ThreadControl;
    while !control.is_null() {
        // SAFETY: a linked control stays mapped under this lock. The TSD
        // metadata lock excludes a concurrent selected set/get for this key.
        unsafe { (*control).tsd.clear_key(key) };
        control = unsafe { (*control).registry_next };
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

/// One selected worker's stack handoff and owned-map reclamation record.
///
/// The bounds' `top` is passed to clone. `mapping`/`mapping_size`
/// are null/zero for a caller-owned stack and otherwise retain the exact
/// private guard-plus-stack map that a later join or reaper must release.
#[derive(Clone, Copy)]
struct SelectedWorkerStack {
    bounds: SelectedThreadStackBounds,
    mapping: *mut u8,
    mapping_size: usize,
}

#[inline]
const fn round_up_to_page(value: usize) -> Option<usize> {
    match value.checked_add(PAGE_SIZE - 1) {
        Some(value) => Some(value & !(PAGE_SIZE - 1)),
        None => None,
    }
}

/// Map one private range without translating `errno`.
unsafe fn map_private_range(length: usize, protection: i64) -> *mut u8 {
    // SAFETY: this fixed anonymous mapping has no caller pointers. The raw
    // syscall result stays private so pthread_create can return a positive
    // error without mutating the creator's C errno slot.
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_MMAP,
            0,
            length as i64,
            protection,
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

/// Materialize a selected private guarded stack or admit one caller stack.
///
/// This preserves musl's creation choices relevant to an initialized attr
/// record: a caller stack receives no private guard/map ownership; an owned
/// stack rounds both its requested stack and its guard to the Linux page
/// boundary before only the stack portion becomes read/write. The selected
/// static TLS block remains a separate exact final-image allocation in both
/// cases.
unsafe fn allocate_selected_worker_stack(
    attributes: super::pthread_attr::SelectedWorkerAttributes,
) -> Option<SelectedWorkerStack> {
    if let Some(requested_top) = attributes.caller_stack_top {
        let stack_base = requested_top.checked_sub(attributes.stack_size)?;
        let stack_top = requested_top & !0xf;
        let stack_size = stack_top.checked_sub(stack_base)?;
        if stack_top == 0 || stack_size == 0 {
            return None;
        }
        return Some(SelectedWorkerStack {
            bounds: SelectedThreadStackBounds { top: stack_top, size: stack_size, guard_size: 0 },
            mapping: core::ptr::null_mut(),
            mapping_size: 0,
        });
    }

    let guard_size = round_up_to_page(attributes.guard_size)?;
    let stack_size = round_up_to_page(attributes.stack_size)?;
    let mapping_size = guard_size.checked_add(stack_size)?;
    // SAFETY: this lifecycle owns the newly mapped anonymous range until a
    // failed create or later join/reaper releases it.
    let mapping = unsafe { map_private_range(mapping_size, PROT_NONE) };
    if mapping.is_null() {
        return None;
    }
    // SAFETY: the upper portion belongs to the private map just made above;
    // the lower rounded guard remains PROT_NONE for the worker lifetime.
    let protection_result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MPROTECT,
            mapping.add(guard_size) as usize as i64,
            stack_size as i64,
            PROT_READ_WRITE,
        )
    };
    if is_linux_error(protection_result) {
        let _ = unsafe { unmap_worker(mapping, mapping_size) };
        return None;
    }
    Some(SelectedWorkerStack {
        // `mapping_size` has already checked the sum, so this points one byte
        // past the owned writable stack. The clone assembly realigns it before
        // reserving its one callback argument word.
        bounds: SelectedThreadStackBounds {
            top: unsafe { mapping.add(mapping_size) } as usize,
            size: stack_size,
            guard_size,
        },
        mapping,
        mapping_size,
    })
}

/// Release one completed worker mapping without translating `errno`.
#[inline(always)]
unsafe fn unmap_worker(mapping: *mut u8, mapping_size: usize) -> i64 {
    // SAFETY: the caller proves that no child can still access this exact
    // range, through a zero child TID after CLONE_CHILD_CLEARTID.
    let result: i64;
    // SAFETY: this is the direct Linux x86-64 munmap register contract. Keep
    // it at the selected lifecycle release boundary so join/reaper auditing
    // cannot depend on cross-item inlining of the generic syscall wrapper.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") raw_syscall::SYS_MUNMAP => result,
            in("rdi") mapping as usize as i64,
            in("rsi") mapping_size as i64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
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

/// End precisely the current Linux task after a selected worker publication.
///
/// Keep this x86 syscall at the selected lifecycle boundary rather than
/// depending on cross-item code generation to inline the generic raw-syscall
/// helper. A worker must leave no reachable continuation after it has exposed
/// its result and cleanup/TSD teardown, and the direct instruction preserves
/// that auditable `pthread_exit`/`thrd_exit` boundary in both installed modes.
#[inline(always)]
unsafe fn exit_selected_linux_task() -> ! {
    // SAFETY: SYS_exit terminates exactly the calling Linux task and cannot
    // return. The selected lifecycle requires this only after the result
    // publication described by its caller.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") raw_syscall::SYS_EXIT,
            in("rdi") 0_i64,
            options(noreturn, nostack),
        )
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
    // SAFETY: this selected worker's fully initialized cancellation state is
    // embedded in the control mapping. It remains mapped through task exit
    // until join/detached reclamation, and the x86 TLS owner supplied the
    // aligned FS+32 opaque cache before this callback can receive SIGCANCEL.
    unsafe {
        pthread_identity::publish_current_selected_cancellation_state(
            core::ptr::addr_of!((*control).cancellation),
        )
    };
    // Musl pthread_create.c clears SIGCANCEL (33, not SIGTIMER 32)
    // in the child's inherited mask. Publish FS+32 first: delivery may begin
    // immediately after this syscall, before the application callback.
    let cancellation_signal = 1_u64 << 32;
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            1, // SIG_UNBLOCK
            core::ptr::addr_of!(cancellation_signal) as usize as i64,
            0,
            8,
        )
    };
    // SAFETY: pthread_create initialized this private record before clone;
    // the child owns the callback invocation and parent only reads result
    // after `finished` is published and the child has exited.
    let result = unsafe { (*control).start.invoke((*control).argument) };
    #[cfg(not(feature = "x86-owned-dynamic-runtime"))]
    if current_is_selected_initial_thread() {
        // This callback called fork and became the static child main task.
        // Its inherited worker control was intentionally unlinked in the
        // child, so a normal trampoline return must become the child main
        // task's pthread_exit transition. That path retains any worker the
        // child created after fork; directly calling ordinary exit here would
        // terminate it before its final-task/atexit transition.
        unsafe { exit_selected_worker(result) }
    }
    // SAFETY: this current worker owns its control/TSD mapping until the
    // assembly tail calls SYS_exit. Destructors must finish before its result
    // becomes join-observable.
    unsafe {
        // A normal callback return commits this task to retirement too. Disable
        // its selected cancellation state before any later exit transition;
        // the helper leaves C11 state untouched.
        pthread_cancel::disable_current_selected_pthread_cancellation_for_exit();
        pthread_tsd::run_selected_worker_tsd_destructors(core::ptr::addr_of!((*control).tsd));
        pthread_mutex::mark_current_selected_robust_mutexes_owner_dead();
        publish_selected_worker_result(control, result);
    }
    {
        let mut saved_signal_mask = 0_u64;
        // SAFETY: this is musl's application-signal exclusion around the
        // locked final-task decision. Earlier cleanup/TSD/result work is
        // already complete, and a non-final worker leaves with this mask
        // blocked through SYS_exit just as musl does.
        unsafe { super::signal_execution::block_application_signals(&mut saved_signal_mask) };
        if selected_worker_is_final_runtime_task(control) {
            // SAFETY: a final ordinary process exit must restore the caller's
            // prior application mask before it runs atexit callbacks.
            unsafe { super::signal_execution::restore_application_signals(&saved_signal_mask) };
            // SAFETY: the initial selected task already called pthread_exit
            // and this locked task-state transition is uniquely final.
            unsafe { exit_selected_final_runtime_task() }
        }
    }
    unsafe { retire_selected_worker_signal_target(control) };
    // SAFETY: a non-final worker has completed its selected state users and
    // returns only to the private clone tail that ends this Linux task.
    // Mark explicit FILE locks before retiring their FS+32 list owner.
    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe { pthread_cancel::orphan_current_stdio_locks() };
    unsafe { pthread_identity::clear_current_selected_cancellation_state() };
    0
}

/// Create one selected x86 pthread worker with Static Initial TLS v1.
///
/// `thread` must designate writable `pthread_t` storage; `start` must be a
/// valid pthread callback and `argument` must remain valid until that function
/// stops reading it. A null `attributes` pointer selects the musl-shaped 128
/// KiB private stack with its 8 KiB guard. An initialized record may select a guarded
/// private stack, a caller-owned stack, or detached-at-create. Explicit
/// scheduler fields return `ENOTSUP` because this bounded seam has no
/// scheduler transition. The private C11 sibling calls
/// [`create_selected_worker`] with its own typed callback mode instead of
/// reaching this C ABI through an incompatible cast.
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
    // Preserve the existing invalid-input precedence: a missing output slot
    // or callback is EINVAL even when the caller also supplies an invalid or
    // unsupported attribute record.
    if thread.is_null() || start.is_none() {
        return EINVAL;
    }
    let attributes = if attributes.is_null() {
        super::pthread_attr::selected_worker_default_attributes()
    } else {
        // SAFETY: pthread_create's C boundary requires an initialized,
        // readable pthread_attr_t whenever the pointer is non-null. The attr
        // owner keeps its exact public-layout decode separate from this clone
        // lifecycle owner.
        unsafe { super::pthread_attr::selected_worker_attributes(attributes) }
    };
    if attributes.scheduler_requested {
        return ENOTSUP;
    }
    let start = match start {
        Some(start) => start,
        None => return EINVAL,
    };
    // SAFETY: the public C boundary validated only the nullable callback; the
    // common selected-worker seam retains the output-pointer and lifetime
    // obligations documented above.
    unsafe {
        create_selected_worker_with_attributes(
            thread,
            SelectedWorkerStart::Pthread(start),
            argument,
            attributes,
        )
    }
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
/// retained the final executable template. Each live worker owns one mapped
/// control-list node; no artifact-only numeric worker ceiling remains. This
/// is not a general pthread or C11 creation primitive.
pub(super) unsafe fn create_selected_worker(
    thread: *mut *mut c_void,
    start: SelectedWorkerStart,
    argument: *mut c_void,
) -> c_int {
    // C11 has no public pthread_attr_t input. Use the same musl-shaped owned
    // default stack/guard policy as a null pthread attribute pointer.
    let attributes = super::pthread_attr::selected_worker_default_attributes();
    unsafe { create_selected_worker_with_attributes(thread, start, argument, attributes) }
}

/// Create one selected worker after its public attribute record was decoded.
///
/// The caller must retain the ordinary selected-worker output/callback
/// obligations and pass only a decoded record whose scheduler request has
/// already been rejected. This private helper keeps stack ownership and
/// detached-at-create state in the same registry transaction as TLS/control
/// allocation and clone publication.
unsafe fn create_selected_worker_with_attributes(
    thread: *mut *mut c_void,
    start: SelectedWorkerStart,
    argument: *mut c_void,
    attributes: super::pthread_attr::SelectedWorkerAttributes,
) -> c_int {
    if thread.is_null() {
        return EINVAL;
    }
    if attributes.scheduler_requested {
        return ENOTSUP;
    }
    if !static_tls::is_ready() {
        return ENOTSUP;
    }
    // A detached child cannot release its active stack/TLS mappings itself.
    // Reap only here at a later lifecycle boundary, after the kernel's
    // clear-child-tid write proves any selected detached child has stopped
    // using them. Each remaining live control carries its own list node.
    reap_finished_detached_selected_workers();
    let tls_block = match unsafe { static_tls::allocate_thread() } {
        Some(block) => block,
        // The retained template stays immutable after `is_ready`; a later
        // failure therefore means allocation pressure, not an unselected TLS
        // fallback or an attempt to derive an errno-only image.
        None => return EAGAIN,
    };
    let control_mapping = unsafe { map_private_range(CONTROL_REGION_SIZE, PROT_READ_WRITE) };
    if control_mapping.is_null() {
        let _ = unsafe { static_tls::release_thread(tls_block) };
        return EAGAIN;
    }
    let worker_stack = match unsafe { allocate_selected_worker_stack(attributes) } {
        Some(stack) => stack,
        None => {
            let _ = unsafe { unmap_worker(control_mapping, CONTROL_REGION_SIZE) };
            let _ = unsafe { static_tls::release_thread(tls_block) };
            return EAGAIN;
        }
    };

    let control = control_mapping.cast::<ThreadControl>();

    // SAFETY: mmap returned a private page-aligned zeroed control allocation;
    // the selected stack is either another private mapping or caller-owned as
    // documented by pthread_attr_setstack. Static Initial TLS v1 already
    // copied the final executable's exact initialized and TBSS TLS image and
    // wrote its minimal Variant-II self word before this record becomes
    // visible.
    unsafe {
        core::ptr::write(
            control,
            ThreadControl {
                child_tid: AtomicI32::new(0),
                start_ready: AtomicU8::new(0),
                creator_handoff_pending: AtomicU8::new(1),
                cancellation_wake_leases: AtomicUsize::new(0),
                task_state: AtomicU8::new(SelectedRuntimeTaskState::ACTIVE),
                lifecycle: AtomicU8::new(
                    if attributes.detached {
                        SelectedWorkerLifecycleState::Detached
                    } else {
                        SelectedWorkerLifecycleState::Joinable
                    }
                    .encode(),
                ),
                result: AtomicUsize::new(0),
                result_kind: AtomicU8::new(SelectedWorkerResultKind::NONE),
                finished: AtomicU8::new(0),
                signal_target_lock: AtomicU8::new(0),
                signal_target_leases: AtomicUsize::new(0),
                worker_tid: AtomicI32::new(-1),
                registry_retired: AtomicU8::new(0),
                tls_released: AtomicU8::new(0),
                stack_released: AtomicU8::new(worker_stack.mapping.is_null() as u8),
                stack_mapping: worker_stack.mapping,
                stack_mapping_size: worker_stack.mapping_size,
                stack_bounds: worker_stack.bounds,
                control_mapping,
                tls_block,
                tsd: pthread_tsd::SelectedTsdValues::empty(),
                robust_list: pthread_mutex::SelectedRobustList::empty(),
                condition_waiter: pthread_cond::SelectedPthreadConditionWaiter::new(),
                registry_previous: core::ptr::null_mut(),
                registry_next: core::ptr::null_mut(),
                cancellation: pthread_cancel::SelectedWorkerCancellation::new(matches!(
                    start,
                    SelectedWorkerStart::Pthread(_)
                )),
                start,
                argument,
            },
        );
        // The self-referential robust-list sentinel must be established only
        // after this control has its final mapping address, before the child
        // can observe `start_ready` or any C callback can acquire a mutex.
        pthread_mutex::initialize_selected_robust_list(core::ptr::addr_of_mut!(
            (*control).robust_list
        ));
        (*control).start_ready.store(1, Ordering::Release);
    }
    publish_selected_worker(control);
    let child_tid = unsafe { core::ptr::addr_of_mut!((*control).child_tid).cast::<c_int>() };
    // The child must inherit SIGCANCEL blocked: an externally delivered
    // cancellation signal must not run between clone installing FS and the
    // trampoline publishing FS+32. Preserve every other inherited mask bit;
    // the parent restores its exact mask immediately after clone returns.
    let cancellation_signal = 1_u64 << 32;
    let mut creator_signal_mask = 0_u64;
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            0, // SIG_BLOCK
            core::ptr::addr_of!(cancellation_signal) as usize as i64,
            core::ptr::addr_of_mut!(creator_signal_mask) as usize as i64,
            8,
        )
    };
    // SAFETY: the private clone seam uses musl's exact x86 argument shuffle.
    // The selected stack is either caller-owned or the writable upper portion
    // of a private guarded map; the separate control and v1 blocks retain the
    // live record and full fresh final-image TLS copy.
    let clone_result = unsafe {
        __crabc_x86_pthread_clone(
            worker_entry,
            worker_stack.bounds.top as *mut u8,
            PTHREAD_CLONE_FLAGS,
            control.cast(),
            child_tid,
            tls_block.thread_pointer().cast(),
            child_tid,
        )
    };
    // SAFETY: paired restoration is required on success and clone failure.
    unsafe { super::signal_execution::restore_application_signals(&creator_signal_mask) };
    if is_linux_error(clone_result) {
        if !release_selected_worker(control) {
            // The private list can still expose `control` to the selected
            // pthread_exit scanner.  Fail closed by retaining both mappings
            // rather than unmapping a pointer that a failed withdrawal left
            // published. This impossible-under-contract corruption path leaks
            // one private control allocation but cannot manufacture a
            // dangling list pointer.
            return EAGAIN;
        }
        if !worker_stack.mapping.is_null() {
            let _ = unsafe { unmap_worker(worker_stack.mapping, worker_stack.mapping_size) };
        }
        let _ = unsafe { unmap_worker(control_mapping, CONTROL_REGION_SIZE) };
        let _ = unsafe { static_tls::release_thread(tls_block) };
        // Musl intentionally translates every clone failure to EAGAIN.
        return EAGAIN;
    }

    // SAFETY: clone succeeded, so the selected child's complete Static Initial
    // TLS v1 TP stays live until the one admitted join reclaims it. On x86
    // musl this TP is the opaque pthread_t returned by pthread_self, and the
    // C header's pthread_equal macro therefore requires it to be the same
    // creator-visible handle rather than this private control-record address.
    // Write it before opening detached reaping: a fast child may already have
    // reached the kernel clear-child-tid edge, but no concurrent reaper may
    // withdraw its list node until this complete creator handoff is visible.
    unsafe { core::ptr::write(thread, tls_block.thread_pointer().cast()) };
    unsafe {
        (*control)
            .creator_handoff_pending
            .store(0, Ordering::Release)
    };
    0
}

/// Exit a selected worker and publish its typed result for its admitted joiner.
///
/// This is valid only when called by a callback created through this leaf's
/// selected pthread_create path. It invokes the selected cleanup and worker-
/// TSD destructor phases, but intentionally omits the rest of musl's
/// detach/thread-list state machine. Outside that worker contract, it still
/// performs Linux thread exit but claims no broader pthread behavior.
///
/// # Safety
///
/// The selected callback must not use any object after this call. Its typed
/// result must remain valid until its joining caller consumes it.
#[inline(always)]
unsafe fn exit_selected_worker(result: SelectedWorkerResult) -> ! {
    if current_is_selected_initial_thread() {
        // SAFETY: selected pthread-exit disables cancellation before any
        // cleanup/TSD or final-task transition. The current implementation
        // retains no C11 cancellation state.
        unsafe {
            pthread_cancel::disable_current_selected_pthread_cancellation_for_exit();
            pthread_cancel::run_current_selected_pthread_cleanup_handlers();
        }
        // SAFETY: this is the bootstrapped task's process-lifetime TSD
        // table. Destructors run before the musl-shaped list/last-thread
        // decision, so they may still use selected lifecycle operations.
        unsafe { pthread_tsd::run_selected_main_tsd_destructors() };
        // SAFETY: robust owner death follows user cleanup/TSD destruction
        // while this selected initial task still owns its linked list and all
        // held caller mutexes remain live under the C pthread contract.
        unsafe { pthread_mutex::mark_current_selected_robust_mutexes_owner_dead() };
        let mut saved_signal_mask = 0_u64;
        // SAFETY: match musl's block-before-thread-list-transition rule. A
        // signal handler cannot enter a competing selected lifecycle path
        // after this task begins its final-task decision.
        unsafe { super::signal_execution::block_application_signals(&mut saved_signal_mask) };
        if selected_initial_thread_is_final_runtime_task() {
            // SAFETY: restore before ordinary exit invokes application atexit
            // callbacks, exactly as musl restores after its one-thread check.
            unsafe { super::signal_execution::restore_application_signals(&saved_signal_mask) };
            // SAFETY: no selected worker remains after the locked logical
            // task-state transition, so pthread_exit is ordinary process exit.
            unsafe { exit_selected_final_runtime_task() }
        }
        unsafe { retire_initial_signal_target() };
        // SAFETY: only a non-final initial task reaches this point. Its
        // cancellation state is disabled and no ordinary-exit callback will
        // run; orphan explicit FILE locks before retiring their FS+32 owner.
        #[cfg(feature = "x86-owned-static-runtime")]
        unsafe { pthread_cancel::orphan_current_stdio_locks() };
        unsafe { pthread_identity::clear_current_selected_cancellation_state() };
        // SAFETY: another selected worker remains. End only this initial task;
        // the final worker takes the ordinary process-exit path above.
        unsafe { exit_selected_linux_task() }
    }
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
            pthread_mutex::mark_current_selected_robust_mutexes_owner_dead();
            publish_selected_worker_result(control, result);
        }
        {
            let mut saved_signal_mask = 0_u64;
            // SAFETY: no user cleanup remains. Block application signals
            // before the locked logical withdrawal, leaving them blocked for
            // the non-final SYS_exit path.
            unsafe { super::signal_execution::block_application_signals(&mut saved_signal_mask) };
            if selected_worker_is_final_runtime_task(control) {
                // SAFETY: only the unique final task restores this mask before
                // ordinary process exit and its atexit callbacks.
                unsafe { super::signal_execution::restore_application_signals(&saved_signal_mask) };
                unsafe { exit_selected_final_runtime_task() }
            }
        }
        unsafe { retire_selected_worker_signal_target(control) };
    }
    // SAFETY: a selected non-final worker reaches only the immediate Linux
    // task exit below after cancellation is disabled for pthread-mode exits
    // and cleanup/TSD users have completed. FILE retirement still needs the
    // current FS+32 list even though its signal target is already retired.
    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe { pthread_cancel::orphan_current_stdio_locks() };
    unsafe { pthread_identity::clear_current_selected_cancellation_state() };
    // SAFETY: Linux SYS_exit terminates precisely the calling task and does
    // not return. The CLONE_CHILD_CLEARTID lifecycle attached during clone
    // clears/wakes the joiner's shared child-TID word after this exit.
    unsafe { exit_selected_linux_task() }
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
/// selected pthread_create path. It invokes the selected cleanup and worker-
/// TSD destructor phases, but intentionally omits the rest of musl's
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
    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe {
        pthread_cancel::pthread_testcancel();
        let mut original_state = 0;
        pthread_cancel::pthread_setcancelstate(JOIN_CANCEL_DISABLE, &mut original_state);
        let mut cleanup = core::mem::MaybeUninit::<pthread_cancel::CleanupNode>::uninit();
        let mut registered = false;
        let result = join_selected_worker_inner(thread, cleanup.as_mut_ptr(), &mut registered, original_state);
        pthread_cancel::pthread_setcancelstate(JOIN_CANCEL_DISABLE, core::ptr::null_mut());
        if registered { pthread_cancel::_pthread_cleanup_pop(cleanup.as_mut_ptr(), 0); }
        pthread_cancel::pthread_setcancelstate(original_state, core::ptr::null_mut());
        return result;
    }
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    unsafe { join_selected_worker_inner(thread) }
}

#[cfg(feature = "x86-owned-static-runtime")]
const JOIN_CANCEL_ENABLE: c_int = 0;
#[cfg(feature = "x86-owned-static-runtime")]
const JOIN_CANCEL_DISABLE: c_int = 1;

/// Cancellation abandons Rust frames; explicitly restore the target before
/// invoking the joining task's outer user cleanup handlers. The target stays
/// linked and mapped throughout the cancellable wait.
#[cfg(feature = "x86-owned-static-runtime")]
unsafe extern "C" fn cancel_selected_worker_join(argument: *mut c_void) {
    unsafe { release_join_claim(argument.cast::<ThreadControl>()) };
}

#[inline(always)]
unsafe fn join_selected_worker_inner(
    thread: *mut c_void,
    #[cfg(feature = "x86-owned-static-runtime")] cleanup: *mut pthread_cancel::CleanupNode,
    #[cfg(feature = "x86-owned-static-runtime")] registered: &mut bool,
    #[cfg(feature = "x86-owned-static-runtime")] original_state: c_int,
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

    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe {
        pthread_cancel::_pthread_cleanup_push(cleanup, Some(cancel_selected_worker_join), control.cast());
        *registered = true;
        // Musl pthread_join keeps DISABLE and MASKED callers disabled while
        // waiting, and restores their original state on return.
        if original_state == JOIN_CANCEL_ENABLE { pthread_cancel::pthread_setcancelstate(JOIN_CANCEL_ENABLE, core::ptr::null_mut()); }
    }

    // SAFETY: the lifecycle claim keeps this linked control mapped. Do not
    // reclaim a fast child that disclosed pthread_self() to another worker
    // before its creating parent has written the caller-visible handle.
    unsafe { wait_for_creator_handoff(control) };

    loop {
        // SAFETY: the handle remains mapped until this joining caller either
        // releases its claim on an error or successfully unmaps it below.
        let child_tid = unsafe { (*control).child_tid.load(Ordering::Acquire) };
        if child_tid == 0 {
            break;
        }
        if child_tid < 0 {
            #[cfg(feature = "x86-owned-static-runtime")]
            unsafe { pthread_cancel::pthread_setcancelstate(JOIN_CANCEL_DISABLE, core::ptr::null_mut()); }
            unsafe { release_join_claim(control) };
            return Err(EINVAL);
        }
        // CLONE_CHILD_CLEARTID wakes this shared (not FUTEX_PRIVATE) word as
        // the last kernel action on normal child exit. EAGAIN and EINTR only
        // request another load; no C errno translation is selected here.
        #[cfg(feature = "x86-owned-static-runtime")]
        let wait_result = unsafe {
            pthread_cancel::syscall_cp(raw_syscall::SYS_FUTEX,
                core::ptr::addr_of_mut!((*control).child_tid) as usize as i64,
                FUTEX_WAIT, i64::from(child_tid), 0, 0, 0)
        };
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        let wait_result: i64;
        // SAFETY: the shared child-TID word, expected value, and null timeout
        // satisfy Linux FUTEX_WAIT. Keeping this syscall at the selected join
        // boundary gives the lifecycle's wait-before-reclaim proof a direct
        // machine-code witness rather than depending on generic-wrapper
        // inlining after the worker attribute path grew.
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") raw_syscall::SYS_FUTEX => wait_result,
                in("rdi") core::ptr::addr_of_mut!((*control).child_tid).cast::<c_int>()
                    as usize as i64,
                in("rsi") FUTEX_WAIT,
                in("rdx") i64::from(child_tid),
                in("r10") 0_i64,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if is_linux_error(wait_result) {
            let error = positive_linux_error(wait_result);
            if error == EAGAIN || error == EINTR {
                continue;
            }
            #[cfg(feature = "x86-owned-static-runtime")]
            unsafe { pthread_cancel::pthread_setcancelstate(JOIN_CANCEL_DISABLE, core::ptr::null_mut()); }
            unsafe { release_join_claim(control) };
            return Err(error);
        }
    }

    // From this point the target may be withdrawn and unmapped: cancellation
    // must not run the claim cleanup against retired storage.
    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe { pthread_cancel::pthread_setcancelstate(JOIN_CANCEL_DISABLE, core::ptr::null_mut()); }

    // A normal returning worker publishes `finished` after its result before
    // its assembly tail invokes exit. The acquire pairs with that release;
    // it avoids treating the kernel's clear-tid write as a Rust memory-order
    // edge for the separate result word.
    while unsafe { (*control).finished.load(Ordering::Acquire) } == 0 {
        core::hint::spin_loop();
    }
    let registry_retired = unsafe { (*control).registry_retired.load(Ordering::Acquire) };
    if registry_retired == 0 {
        // Withdraw under the same lock used by pthread_exit's complete
        // scan-to-publish interval. No raw registry pointer can survive this
        // call into the following munmap, and a retry after a failed munmap
        // intentionally leaves the worker withdrawn.
        if !release_selected_worker(control) {
            #[cfg(feature = "x86-owned-static-runtime")]
            unsafe { pthread_cancel::pthread_setcancelstate(JOIN_CANCEL_DISABLE, core::ptr::null_mut()); }
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
/// [`pthread_create`]. Detached-at-create records already own the detached
/// state, so this function admits only a still-joinable selected handle; it
/// never accepts an arbitrary system pthread handle. It reports a positive
/// errno and never writes the calling thread's `errno` slot.
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
