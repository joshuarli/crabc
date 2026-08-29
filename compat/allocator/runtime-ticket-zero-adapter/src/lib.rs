//! Test-only prefixed C ABI for the private ticket-zero runtime page owner.
//!
//! This crate is deliberately outside `crabc-libc` and is linked only by the
//! allocator evidence harness. Its ten `crabc_ticket_zero_test_*` exports
//! exercise one process's original thread plus one fresh scoped worker through
//! the hidden Rust runtime seam; they are neither `malloc`/`free`
//! interposition symbols nor a production backend-selection mechanism.
//!
//! The caller must initialize exactly once from its original Linux thread,
//! serialize all later calls on that same thread, and pass only current
//! adapter allocations to `realloc` and `free`. There is no shutdown entry:
//! the underlying source-shaped page owner is intentionally process-lifetime.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_int, c_void};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU8, Ordering};

use crabc_mimalloc::__crabc_runtime::{
    TicketZeroLaterThreadPageResult, TicketZeroPageAllocationResult,
    TicketZeroPageFreeResult, TicketZeroOwnerExitFreeOutcome,
    TicketZeroOwnerExitFreeRoute, TicketZeroOwnerExitRemoteFreeProducer,
    TicketZeroOwnerExitReclaimOutcome,
    TicketZeroOwnerExitReclaimRoute, TicketZeroRemoteFreeProducer,
    TicketZeroRemoteFreeProducerPair, initialize_process,
    ticket_zero_allocate, ticket_zero_free, ticket_zero_later_thread_page_roundtrip,
    ticket_zero_later_thread_direct_small_owner_exit_reclaim_through_normal_finish,
    ticket_zero_later_thread_mapped_regular_owner_exit_through_normal_finish,
    ticket_zero_later_thread_mapped_regular_owner_exit_reclaim_through_normal_finish,
    ticket_zero_later_thread_persistent_local_workload,
    ticket_zero_later_thread_remote_free_roundtrip, ticket_zero_reallocate,
};

const ENOMEM: c_int = 12;
const EBUSY: c_int = 16;
const EINVAL: c_int = 22;

const ADAPTER_COLD: u8 = 0;
const ADAPTER_INITIALIZING: u8 = 1;
const ADAPTER_READY: u8 = 2;
const ADAPTER_RETAINED: u8 = 3;

// This state is only the evidence adapter's C-call boundary. The allocator's
// permanent owner and non-reentrant READY -> BUSY transition remain in
// `crabc_mimalloc::runtime_lifecycle`.
static ADAPTER_STATE: AtomicU8 = AtomicU8::new(ADAPTER_COLD);

// The one existing reclamation export alternates the two already source-valid
// predecessors. This keeps the C churn seam geometry-neutral: neither the
// fixture nor its ABI gets a new symbol just because a direct-small source
// drain differs from the aggregate sole-medium result. The C caller serializes
// the adapter by contract; the atomic keeps this test-only process state sound
// if an unexpected observer reads it concurrently.
static OWNER_EXIT_RECLAIM_PREDECESSOR: AtomicU8 = AtomicU8::new(0);

// Linux/AArch64 musl's opaque `pthread_t` is one pointer-sized value. The
// adapter never inspects it; it writes exactly one native C ABI value for the
// create call and gives that unchanged value back to join. This test-only
// bridge remains in the adapter rather than making the no_std engine depend
// on pthread APIs or a public thread abstraction.
type Pthread = *mut c_void;

struct RemotePublishContext<'owner> {
    producer: Option<TicketZeroRemoteFreeProducer<'owner>>,
    published: bool,
}

/// Stack-owned C-side publication capability issued inside B's one bounded
/// post-exit source decision. C can only append its private client to B's
/// held remote head; neither pthread receives a client address, PageMap, or
/// collector/release capability.
struct OwnerExitRemotePublishContext<'owner> {
    producer: Option<TicketZeroOwnerExitRemoteFreeProducer<'owner>>,
    published: bool,
}

/// Stack-owned handoff between A and the joined B that consumes its private
/// post-exit route. B sees neither a client address nor allocator internals;
/// it can only return the opaque route outcome to A's runtime callback.
struct OwnerExitFreeContext<'owner> {
    route: Option<TicketZeroOwnerExitFreeRoute<'owner>>,
    outcome: Option<TicketZeroOwnerExitFreeOutcome<'owner>>,
}

/// Stack-owned handoff between A and a joined B that reclaims one opaque
/// source-valid mapped-regular route. B sees neither a client address nor the
/// static process pair; it can only return the typed lifecycle outcome.
struct OwnerExitReclaimContext {
    route: Option<TicketZeroOwnerExitReclaimRoute>,
    outcome: Option<TicketZeroOwnerExitReclaimOutcome>,
}

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
    fn abort() -> !;
    fn pthread_create(
        thread: *mut Pthread,
        attributes: *const c_void,
        start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        argument: *mut c_void,
    ) -> c_int;
    fn pthread_join(thread: Pthread, result: *mut *mut c_void) -> c_int;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // This test-only staticlib has no Rust unwinding boundary. Preserve the
    // workspace's abort profile should an internal invariant ever fail.
    unsafe { abort() }
}

#[inline]
fn errno_value() -> c_int {
    // SAFETY: Linux/musl exposes the current thread's errno cell through this
    // ABI. The adapter neither retains nor shares the returned pointer.
    unsafe { *__errno_location() }
}

#[inline]
fn set_errno(value: c_int) {
    // SAFETY: see `errno_value`; only the calling thread's errno cell changes.
    unsafe { *__errno_location() = value };
}

#[inline]
fn preserve_errno<T>(saved_errno: c_int, value: T) -> T {
    set_errno(saved_errno);
    value
}

#[inline]
fn is_ready() -> bool {
    ADAPTER_STATE.load(Ordering::Acquire) == ADAPTER_READY
}

#[inline]
fn allocation_result(saved_errno: c_int, result: TicketZeroPageAllocationResult) -> *mut c_void {
    match result {
        TicketZeroPageAllocationResult::Allocated(block) => {
            preserve_errno(saved_errno, block.as_ptr().cast())
        }
        TicketZeroPageAllocationResult::AllocationFailed => {
            set_errno(ENOMEM);
            ptr::null_mut()
        }
        TicketZeroPageAllocationResult::Unavailable | TicketZeroPageAllocationResult::Retained => {
            set_errno(EBUSY);
            ptr::null_mut()
        }
    }
}

#[cold]
#[inline(never)]
fn fail_stop_pointer_contract() -> ! {
    // SAFETY: an invalid/stale/foreign pointer is outside this test ABI. The
    // no-return C boundary makes failure explicit instead of routing it to
    // libc's unrelated mimalloc backend.
    unsafe { abort() }
}

/// The private B-side C thread entry receives only a pointer to its opaque
/// publication capability. It never receives a client allocation pointer or
/// touches owner A's attachment, page engine, map, or arena.
unsafe extern "C" fn publish_remote_free_from_pthread(argument: *mut c_void) -> *mut c_void {
    let context = match unsafe { argument.cast::<RemotePublishContext<'_>>().as_mut() } {
        Some(context) => context,
        None => return ptr::null_mut(),
    };
    let Some(producer) = context.producer.take() else {
        return ptr::null_mut();
    };
    match producer.publish() {
        Ok(()) => context.published = true,
        Err(producer) => context.producer = Some(producer),
    }
    ptr::null_mut()
}

/// C-side atomic publication issued only after B has claimed the source
/// abandoned-page low owner bit for its direct post-exit client free.
unsafe extern "C" fn publish_owner_exit_remote_free_from_pthread(
    argument: *mut c_void,
) -> *mut c_void {
    let context = match unsafe { argument.cast::<OwnerExitRemotePublishContext<'_>>().as_mut() } {
        Some(context) => context,
        None => return ptr::null_mut(),
    };
    let Some(producer) = context.producer.take() else {
        return ptr::null_mut();
    };
    match producer.publish() {
        Ok(()) => context.published = true,
        Err(producer) => context.producer = Some(producer),
    }
    ptr::null_mut()
}

/// B-side source finalizer for A's opaque post-exit route. B first creates and
/// later finishes its own fresh no-page runtime attachment; it never tries to
/// finish A's already-detached attachment. The result remains in the joined
/// stack context so A can consume its terminal proof before it releases A's
/// lifecycle admission claim.
unsafe extern "C" fn free_owner_exit_route_from_pthread(argument: *mut c_void) -> *mut c_void {
    let context = match unsafe { argument.cast::<OwnerExitFreeContext<'_>>().as_mut() } {
        Some(context) => context,
        None => return ptr::null_mut(),
    };
    let Some(route) = context.route.take() else {
        return ptr::null_mut();
    };
    context.outcome = Some(
        route.free_remaining_in_fresh_runtime_worker_with_post_exit_publisher(
            publish_owner_exit_remote_free_in_joined_pthread,
        ),
    );
    ptr::null_mut()
}

/// B-side source reclamation for A's opaque mapped-regular route. This performs
/// B's normal attachment/engine teardown only after it has adopted and drained
/// the exact sole-medium or direct-small page; A's admission proof remains in
/// the joined stack context.
unsafe extern "C" fn reclaim_owner_exit_route_from_pthread(argument: *mut c_void) -> *mut c_void {
    let context = match unsafe { argument.cast::<OwnerExitReclaimContext>().as_mut() } {
        Some(context) => context,
        None => return ptr::null_mut(),
    };
    let Some(route) = context.route.take() else {
        return ptr::null_mut();
    };
    context.outcome = Some(route.reclaim_and_finish());
    ptr::null_mut()
}

/// Moves the exact typed post-exit route into joined B. B returns only a
/// completed proof, retained route, or poisoned outcome; it cannot receive a
/// client pointer. Its route method may run the normal finalizer only for B's
/// own fresh no-page attachment, never for A's detached owner.
fn free_owner_exit_route_in_joined_pthread<'owner>(
    route: TicketZeroOwnerExitFreeRoute<'owner>,
) -> TicketZeroOwnerExitFreeOutcome<'owner> {
    let mut context = OwnerExitFreeContext {
        route: Some(route),
        outcome: None,
    };
    let mut thread = ptr::null_mut();
    if unsafe {
        pthread_create(
            &mut thread,
            ptr::null(),
            free_owner_exit_route_from_pthread,
            core::ptr::from_mut(&mut context).cast(),
        )
    } != 0
    {
        // SAFETY: returning the typed route would be possible in Rust but is
        // not expressible through this C pthread-create callback boundary.
        // Stop rather than discard the only terminal-release authority.
        unsafe { abort() }
    }
    let mut ignored_result = ptr::null_mut();
    if unsafe { pthread_join(thread, &mut ignored_result) } != 0 {
        // SAFETY: a failed join cannot prove that B stopped accessing the
        // route context or whether it consumed a final client free.
        unsafe { abort() }
    }
    context
        .outcome
        .take()
        .expect("joined B consumes exactly one opaque post-exit route")
}

/// Creates and joins C while B holds the source abandoned-page low owner bit
/// for its direct post-exit free. The callback returns the opaque token on a
/// clean publication refusal so B's route can retain its exact terminal state;
/// a failed join cannot prove that C stopped touching the stack context and
/// therefore stops the test process rather than guessing at ownership.
fn publish_owner_exit_remote_free_in_joined_pthread<'owner>(
    producer: TicketZeroOwnerExitRemoteFreeProducer<'owner>,
) -> Result<(), TicketZeroOwnerExitRemoteFreeProducer<'owner>> {
    let mut context = OwnerExitRemotePublishContext {
        producer: Some(producer),
        published: false,
    };
    let mut thread = ptr::null_mut();
    if unsafe {
        pthread_create(
            &mut thread,
            ptr::null(),
            publish_owner_exit_remote_free_from_pthread,
            core::ptr::from_mut(&mut context).cast(),
        )
    } != 0
    {
        return Err(
            context
                .producer
                .take()
                .expect("an unstarted C publisher returns its opaque capability"),
        );
    }
    let mut ignored_result = ptr::null_mut();
    if unsafe { pthread_join(thread, &mut ignored_result) } != 0 {
        // SAFETY: a failed join cannot prove that C stopped accessing its
        // callback-local producer or whether it reached the atomic head.
        unsafe { abort() }
    }
    if context.published {
        debug_assert!(context.producer.is_none());
        Ok(())
    } else {
        Err(
            context
                .producer
                .take()
                .expect("a joined failed C publisher returns its opaque capability"),
        )
    }
}

/// Moves the exact source-valid post-exit reclamation route into a joined B.
/// B cannot retain a raw client, route internals, or A's admission token
/// outside this stack-owned callback context.
fn reclaim_owner_exit_route_in_joined_pthread(
    route: TicketZeroOwnerExitReclaimRoute,
) -> TicketZeroOwnerExitReclaimOutcome {
    let mut context = OwnerExitReclaimContext {
        route: Some(route),
        outcome: None,
    };
    let mut thread = ptr::null_mut();
    if unsafe {
        pthread_create(
            &mut thread,
            ptr::null(),
            reclaim_owner_exit_route_from_pthread,
            core::ptr::from_mut(&mut context).cast(),
        )
    } != 0
    {
        // The source route is linear and the C pthread-create ABI cannot
        // return it through this callback boundary. Stop rather than discard
        // the only reclamation/terminal-release authority.
        unsafe { abort() }
    }
    let mut ignored_result = ptr::null_mut();
    if unsafe { pthread_join(thread, &mut ignored_result) } != 0 {
        // A failed join cannot prove that B stopped touching the route or
        // whether it consumed the source route into a retained engine.
        unsafe { abort() }
    }
    context
        .outcome
        .take()
        .expect("joined B consumes exactly one opaque post-exit reclaim route")
}

/// Creates and joins B/C while A's runtime callback still holds its exclusive
/// engine borrow. The two source publications may originate from one page or
/// two source-distinct pages; they may race in their independent or shared
/// atomic heads. Once either pthread starts, a create/join/publication failure
/// has no safe token-reassembly continuation, so this test-only process stops
/// rather than guessing at remote ownership.
fn publish_remote_frees_in_joined_pthreads<'owner>(
    producers: TicketZeroRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>> {
    let (first, second) = producers.split();
    let mut first_context = RemotePublishContext {
        producer: Some(first),
        published: false,
    };
    let mut second_context = RemotePublishContext {
        producer: Some(second),
        published: false,
    };
    let mut first_thread = ptr::null_mut();
    let created = unsafe {
        pthread_create(
            &mut first_thread,
            ptr::null(),
            publish_remote_free_from_pthread,
            core::ptr::from_mut(&mut first_context).cast(),
        )
    };
    if created != 0 {
        // SAFETY: no producer thread began, but the split pair cannot be
        // reconstructed at this C-only test boundary.
        unsafe { abort() }
    }
    let mut second_thread = ptr::null_mut();
    let created = unsafe {
        pthread_create(
            &mut second_thread,
            ptr::null(),
            publish_remote_free_from_pthread,
            core::ptr::from_mut(&mut second_context).cast(),
        )
    };
    if created != 0 {
        // SAFETY: first_thread may already access its stack context.
        unsafe { abort() }
    }
    let mut ignored_first_result = ptr::null_mut();
    let mut ignored_second_result = ptr::null_mut();
    if unsafe { pthread_join(first_thread, &mut ignored_first_result) } != 0
        || unsafe { pthread_join(second_thread, &mut ignored_second_result) } != 0
    {
        // SAFETY: a failed join cannot prove that its publisher stopped
        // touching the corresponding stack context.
        unsafe { abort() }
    }
    if first_context.published && second_context.published {
        debug_assert!(first_context.producer.is_none());
        debug_assert!(second_context.producer.is_none());
        Ok(())
    } else {
        // SAFETY: a protocol failure can leave one publisher consumed and the
        // other local; do not invent a partial remote-free recovery route.
        unsafe { abort() }
    }
}

/// Initializes the one process-lifetime ticket-zero test owner.
///
/// # Safety
///
/// The C caller must supply the validated nonzero `AT_PAGESZ` value on the
/// original process thread, serialize this call with every other adapter call,
/// and call it exactly once before allocation. A failure permanently disables
/// this one-shot evidence process; it does not change `crabc-libc`.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_init(page_size: usize) -> c_int {
    let saved_errno = errno_value();
    if ADAPTER_STATE
        .compare_exchange(
            ADAPTER_COLD,
            ADAPTER_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return preserve_errno(saved_errno, EBUSY);
    }
    if page_size == 0 {
        ADAPTER_STATE.store(ADAPTER_RETAINED, Ordering::Release);
        return preserve_errno(saved_errno, EINVAL);
    }
    if !initialize_process(page_size) {
        ADAPTER_STATE.store(ADAPTER_RETAINED, Ordering::Release);
        return preserve_errno(saved_errno, EBUSY);
    }
    ADAPTER_STATE.store(ADAPTER_READY, Ordering::Release);
    preserve_errno(saved_errno, 0)
}

/// Allocates one uninitialized private ticket-zero page-owner block.
///
/// # Safety
///
/// The caller must use the original initializing thread and serialize every
/// adapter call. The successful pointer belongs solely to this evidence ABI.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_malloc(size: usize) -> *mut c_void {
    let saved_errno = errno_value();
    if !is_ready() {
        set_errno(EBUSY);
        return ptr::null_mut();
    }
    allocation_result(saved_errno, ticket_zero_allocate(size, false))
}

/// Allocates one zeroed private ticket-zero page-owner block.
///
/// # Safety
///
/// The caller obligations are the same as `crabc_ticket_zero_test_malloc`.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_zalloc(size: usize) -> *mut c_void {
    let saved_errno = errno_value();
    if !is_ready() {
        set_errno(EBUSY);
        return ptr::null_mut();
    }
    allocation_result(saved_errno, ticket_zero_allocate(size, true))
}

/// Reallocates one current private ticket-zero allocation.
///
/// # Safety
///
/// `block` must be null or one current, uniquely held result from this exact
/// adapter. The caller must remain on the original thread and serialize calls.
/// On null failure a non-null old block remains live, as in C `realloc`.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_realloc(
    block: *mut c_void,
    size: usize,
) -> *mut c_void {
    let saved_errno = errno_value();
    if !is_ready() {
        set_errno(EBUSY);
        return ptr::null_mut();
    }
    let block = NonNull::new(block.cast::<u8>());
    // SAFETY: this export repeats the runtime seam's exact-current-block,
    // single-thread, no-alias caller obligation.
    allocation_result(saved_errno, unsafe { ticket_zero_reallocate(block, size) })
}

/// Releases one current private ticket-zero allocation.
///
/// # Safety
///
/// `block` must be null or one current, uniquely held result from this exact
/// adapter, passed once on the original initializing thread. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_free(block: *mut c_void) {
    if block.is_null() {
        return;
    }
    if !is_ready() {
        fail_stop_pointer_contract();
    }
    let saved_errno = errno_value();
    // SAFETY: `block` is non-null and the C caller contract establishes that
    // it is the exact current allocation from this ticket-zero owner.
    let block = unsafe { NonNull::new_unchecked(block.cast::<u8>()) };
    // SAFETY: forwarded unchanged from this export's exact allocation contract.
    match unsafe { ticket_zero_free(block) } {
        TicketZeroPageFreeResult::Freed => set_errno(saved_errno),
        TicketZeroPageFreeResult::Unavailable
        | TicketZeroPageFreeResult::InvalidPointer
        | TicketZeroPageFreeResult::Retained => fail_stop_pointer_contract(),
    }
}

/// Attaches this fresh worker for one scoped page allocation/free round trip.
///
/// # Safety
///
/// The caller must invoke this only on one fresh pthread after init and after
/// every ticket-zero adapter allocation has freed. It may call the function
/// once per worker; the worker must not use any other adapter operation.
/// Success preserves its incoming `errno`. This remains a test-only page
/// lifecycle witness, not a C allocator operation or backend selector.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_worker_roundtrip(size: usize) -> c_int {
    let saved_errno = errno_value();
    if !is_ready() {
        set_errno(EBUSY);
        return -1;
    }
    match ticket_zero_later_thread_page_roundtrip(size, false) {
        TicketZeroLaterThreadPageResult::Completed => preserve_errno(saved_errno, 0),
        TicketZeroLaterThreadPageResult::AllocationFailed => {
            set_errno(ENOMEM);
            -1
        }
        TicketZeroLaterThreadPageResult::Unavailable | TicketZeroLaterThreadPageResult::Retained => {
            set_errno(EBUSY);
            -1
        }
    }
}

/// Attaches this fresh worker for one persistent mixed local page-engine
/// workload and normal teardown.
///
/// # Safety
///
/// The caller must invoke this only on one fresh pthread after init and after
/// every ticket-zero adapter allocation has freed. The worker must not use any
/// other adapter operation. The pointer-private Rust workload retains one
/// engine while it allocates, checks, locally frees, and locally reuses small,
/// medium, large, singleton, and multi-page singleton blocks. Success
/// preserves its incoming `errno`. This is a test-only lifecycle witness, not
/// a C allocator operation or backend selector.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_worker_mixed_roundtrip() -> c_int {
    let saved_errno = errno_value();
    if !is_ready() {
        set_errno(EBUSY);
        return -1;
    }
    match ticket_zero_later_thread_persistent_local_workload() {
        TicketZeroLaterThreadPageResult::Completed => preserve_errno(saved_errno, 0),
        TicketZeroLaterThreadPageResult::AllocationFailed => {
            set_errno(ENOMEM);
            -1
        }
        TicketZeroLaterThreadPageResult::Unavailable | TicketZeroLaterThreadPageResult::Retained => {
            set_errno(EBUSY);
            -1
        }
    }
}

/// Attaches this fresh worker as remote-free owner A, starts and joins one
/// private publisher pthread B, then collects and reuses B's handoff before
/// normal A teardown.
///
/// # Safety
///
/// The caller must invoke this only on one fresh pthread after init and after
/// every ticket-zero adapter allocation has freed. The caller receives no
/// allocation pointer; the adapter transports only its opaque logical
/// publication capability to B while A's engine remains borrowed. B finishes
/// before A collects, allocates again, or tears down. Success preserves errno.
/// This is a test-only live-owner remote-free witness, not a public allocator
/// operation, concurrent allocator route, or owner-exit path.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_worker_remote_free_roundtrip() -> c_int {
    let saved_errno = errno_value();
    if !is_ready() {
        set_errno(EBUSY);
        return -1;
    }
    match ticket_zero_later_thread_remote_free_roundtrip(publish_remote_frees_in_joined_pthreads) {
        TicketZeroLaterThreadPageResult::Completed => preserve_errno(saved_errno, 0),
        TicketZeroLaterThreadPageResult::AllocationFailed => {
            set_errno(ENOMEM);
            -1
        }
        TicketZeroLaterThreadPageResult::Unavailable | TicketZeroLaterThreadPageResult::Retained => {
            set_errno(EBUSY);
            -1
        }
    }
}

/// Attaches this fresh worker as owner A of a mixed regular Theap, fills two
/// `BIN_FULL` medium pages, and gives joined B/C one opaque pre-exit remote
/// free from the first medium plus the sole client from a distinct large page.
/// Source collection maps the first medium, releases the now-empty large page,
/// and leaves the second medium source-unmapped. A then transfers the opaque
/// post-exit route to a second fresh joined B. After B claims the source low
/// owner bit for its first direct free of that unchanged medium, joined C can
/// atomically publish only one scoped same-page private client; B's existing
/// collector consumes both before B releases the route's remaining clients.
/// B then completes only B's own no-page attachment; its completed proof
/// returns to A before the runtime releases A's worker-admission claim.
///
/// # Safety
///
/// The caller must invoke this only on one fresh pthread after init and after
/// every ticket-zero adapter allocation has freed. The caller sees no client
/// pointer, route, or admission capability. Success preserves `errno`. This
/// is a test-only Gate 5C lifecycle witness, not a public allocator route or
/// libc backend selector.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_worker_owner_exit_roundtrip() -> c_int {
    let saved_errno = errno_value();
    if !is_ready() {
        set_errno(EBUSY);
        return -1;
    }
    match ticket_zero_later_thread_mapped_regular_owner_exit_through_normal_finish(
        publish_remote_frees_in_joined_pthreads,
        free_owner_exit_route_in_joined_pthread,
    ) {
        TicketZeroLaterThreadPageResult::Completed => preserve_errno(saved_errno, 0),
        TicketZeroLaterThreadPageResult::AllocationFailed => {
            set_errno(ENOMEM);
            -1
        }
        TicketZeroLaterThreadPageResult::Unavailable | TicketZeroLaterThreadPageResult::Retained => {
            set_errno(EBUSY);
            -1
        }
    }
}

/// Alternates the existing source-valid nonfull-medium and direct-small A
/// predecessors, then starts and joins B to reclaim and drain that exact
/// abandoned page before A's admission is released. The direct-small branch
/// remains its own source drain; this C wrapper only reuses the existing
/// pointer-private post-exit capability.
///
/// # Safety
///
/// The caller has the same fresh-worker/process-idle obligations as the
/// aggregate owner-exit witness. It receives no client pointer or allocator
/// capability, and this remains a test-only Gate 5C route plus bounded Gate 5D
/// stability evidence.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_worker_owner_exit_reclaim_roundtrip() -> c_int {
    let saved_errno = errno_value();
    if !is_ready() {
        set_errno(EBUSY);
        return -1;
    }
    let result = if OWNER_EXIT_RECLAIM_PREDECESSOR.fetch_add(1, Ordering::Relaxed) & 1 == 0 {
        ticket_zero_later_thread_mapped_regular_owner_exit_reclaim_through_normal_finish(
            reclaim_owner_exit_route_in_joined_pthread,
        )
    } else {
        ticket_zero_later_thread_direct_small_owner_exit_reclaim_through_normal_finish(
            reclaim_owner_exit_route_in_joined_pthread,
        )
    };
    match result {
        TicketZeroLaterThreadPageResult::Completed => preserve_errno(saved_errno, 0),
        TicketZeroLaterThreadPageResult::AllocationFailed => {
            set_errno(ENOMEM);
            -1
        }
        TicketZeroLaterThreadPageResult::Unavailable | TicketZeroLaterThreadPageResult::Retained => {
            set_errno(EBUSY);
            -1
        }
    }
}
