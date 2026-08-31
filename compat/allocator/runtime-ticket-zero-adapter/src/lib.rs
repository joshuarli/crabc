//! Test-only prefixed C ABI for the private ticket-zero runtime page owner.
//!
//! This crate is deliberately outside `crabc-libc` and is linked only by the
//! allocator evidence harness. Its eleven `crabc_ticket_zero_test_*` exports
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
    TicketZeroPageFreeResult, TicketZeroRemoteFreeProducer,
    TicketZeroRemoteFreeProducerPair, NativeRuntimeLifecycleAudit,
    initialize_process, native_runtime_lifecycle_test_audit,
    ticket_zero_allocate, ticket_zero_free, ticket_zero_later_thread_page_roundtrip,
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

/// Scalar-only lifecycle snapshot for the test adapter's C soak fixture.
///
/// Its fields deliberately expose no pointer, route, page identity, allocator,
/// or release capability. They may be sampled only by the original serialized
/// C caller after every worker from the bounded schedule has joined.
#[repr(C)]
pub struct CrabcTicketZeroTestLifecycleAudit {
    pub process_active: usize,
    pub page_owner_ready: usize,
    pub page_map_registered_entry_count: usize,
    pub page_map_published_submap_count: usize,
    pub page_map_lazy_submap_allocation_count: usize,
    pub arena_registry_count: usize,
    pub live_thread_count: usize,
    pub metadata_live_capability_count: usize,
    pub metadata_high_water_capability_count: usize,
    pub shared_later_theap_count: usize,
    pub main_heap_abandoned_page_count: usize,
    pub main_heap_os_abandoned_pages_empty: usize,
}

impl From<NativeRuntimeLifecycleAudit> for CrabcTicketZeroTestLifecycleAudit {
    fn from(audit: NativeRuntimeLifecycleAudit) -> Self {
        Self {
            process_active: audit.process_active,
            page_owner_ready: audit.page_owner_ready,
            page_map_registered_entry_count: audit.page_map_registered_entry_count,
            page_map_published_submap_count: audit.page_map_published_submap_count,
            page_map_lazy_submap_allocation_count: audit.page_map_lazy_submap_allocation_count,
            arena_registry_count: audit.arena_registry_count,
            live_thread_count: audit.live_thread_count,
            metadata_live_capability_count: audit.metadata_live_capability_count,
            metadata_high_water_capability_count: audit.metadata_high_water_capability_count,
            shared_later_theap_count: audit.shared_later_theap_count,
            main_heap_abandoned_page_count: audit.main_heap_abandoned_page_count,
            main_heap_os_abandoned_pages_empty: audit.main_heap_os_abandoned_pages_empty,
        }
    }
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

/// Copies one scalar-only quiescent runtime snapshot into caller-owned C
/// storage.
///
/// # Safety
///
/// `audit` must be non-null, valid for one complete
/// [`CrabcTicketZeroTestLifecycleAudit`] write, and suitably aligned. The
/// original initializing thread must serialize this call after every bounded
/// worker has joined; this export is evidence-only and does not grant any
/// allocator, page, route, or release authority.
#[no_mangle]
pub unsafe extern "C" fn crabc_ticket_zero_test_lifecycle_audit(
    audit: *mut CrabcTicketZeroTestLifecycleAudit,
) -> c_int {
    let saved_errno = errno_value();
    let Some(audit) = NonNull::new(audit) else {
        set_errno(EINVAL);
        return -1;
    };
    if !is_ready() {
        set_errno(EBUSY);
        return -1;
    }
    let Some(snapshot) = native_runtime_lifecycle_test_audit() else {
        set_errno(EBUSY);
        return -1;
    };
    // SAFETY: the caller contract above grants one complete typed C-image
    // write to the non-null, aligned output slot. The snapshot is scalar-only.
    unsafe { audit.as_ptr().write(snapshot.into()) };
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
