//! Evidence-only unprefixed `mi_*` C ABI over the native crabc-mimalloc
//! runtime.
//!
//! This static library lets an unmodified C program written against the
//! pinned mimalloc v3.5.0 `mimalloc.h` run on the Rust port inside a musl
//! process: the allocator differential links its shared C driver once
//! against the pinned C sources and once against this library, and the
//! upstream `test/test-api.c` links against it. It is not a production
//! allocator: it neither interposes `malloc` nor enters crabc libc, and the
//! C backend remains selected everywhere else.
//!
//! Each exported function is a thin projection of the same-named
//! `crabc_mimalloc::source_api` entry, applying the returned errno effect to
//! musl's `errno`.
//!
//! Process and thread binding follow the selected Linux primitives of pinned
//! `src/prim/unix/prim.c` and `src/init.c`: a load-time constructor publishes
//! the host's startup facts and starts the process (`mi_process_load`), and a
//! worker's first free registers it without attaching a Theap; its first
//! Theap-requiring entry attaches it. A `pthread_key_t` destructor finishes it
//! (`_mi_prim_thread_associate_default_theap` / `mi_pthread_done`).

#![no_std]
#![feature(linkage)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crabc_mimalloc::__crabc_runtime::source_api::{
    self as api, Block, FreeOutcome, ReallocarrStore, SourceCRuntime, SourceErrno, Sourced,
};
use crabc_mimalloc::__crabc_runtime::{
    NativeProcessStartupFacts, SourceErrnoStore, RuntimeStderrOutput, ThreadAttachResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, initialize_process,
    prepare_native_initial_thread_owner, publish_native_process_startup_facts,
    register_current_native_allocator_worker_descriptor,
};

type PthreadKey = c_uint;
type Pthread = c_ulong;
type WideChar = i32;

const AT_PAGESZ: c_ulong = 6;
const PC_PATH_MAX: c_int = 4;

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
    fn abort() -> !;
    fn fputs(message: *const c_char, stream: *mut c_void) -> c_int;
    static mut stderr: *mut c_void;
    static mut stdout: *mut c_void;
    static mut environ: *mut *mut c_char;
    fn getauxval(tag: c_ulong) -> c_ulong;
    fn getenv(name: *const c_char) -> *mut c_char;
    fn realpath(name: *const c_char, resolved: *mut c_char) -> *mut c_char;
    fn pathconf(path: *const c_char, name: c_int) -> c_long;
    fn pthread_self() -> Pthread;
    fn pthread_equal(left: Pthread, right: Pthread) -> c_int;
    fn pthread_key_create(key: *mut PthreadKey, destructor: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int;
    fn pthread_getspecific(key: PthreadKey) -> *mut c_void;
    fn pthread_setspecific(key: PthreadKey, value: *const c_void) -> c_int;
}

unsafe extern "C" {
    // Pinned `alloc.c:729-731` gives this a weak default returning null; a
    // linked C++ runtime supplies the real `std::get_new_handler`.
    #[linkage = "extern_weak"]
    static _ZSt15get_new_handlerv: Option<unsafe extern "C" fn() -> Option<unsafe extern "C" fn()>>;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: musl `abort` never returns.
    unsafe { abort() }
}

// ---------------------------------------------------------------------------
// Process and thread binding
// ---------------------------------------------------------------------------

const PROCESS_COLD: u8 = 0;
const PROCESS_READY: u8 = 1;
const PROCESS_FAILED: u8 = 2;
static PROCESS: AtomicU8 = AtomicU8::new(PROCESS_COLD);
static INITIAL_THREAD: AtomicUsize = AtomicUsize::new(0);
static THREAD_KEY: AtomicUsize = AtomicUsize::new(0);

// The free-only marker holds descriptor registration without initializing a
// Theap. A later allocation still attaches; either worker marker runs finish.
const THREAD_INITIAL: usize = 1;
const THREAD_ATTACHED: usize = 2;
const THREAD_FREE_ONLY: usize = 3;

unsafe extern "C" fn host_stderr(message: *const c_char) {
    // SAFETY: musl's permanent `stderr` receives the owner's NUL-terminated
    // fragment; pinned `_mi_prim_out_stderr` ignores the result.
    unsafe {
        let _ = fputs(message, stderr);
    }
}

unsafe fn host_environment() -> *const *const c_char {
    // SAFETY: a raw word read of the musl process's `environ`.
    unsafe { core::ptr::read(core::ptr::addr_of!(environ)).cast_const().cast() }
}

/// Publishes to musl's calling-thread errno slot without retaining its pointer.
unsafe fn host_source_errno_store(value: c_int) {
    // SAFETY: the host installed TLS before constructors, and musl resolves
    // the calling thread's slot for this immediate, nonallocating write.
    unsafe { *__errno_location() = value };
}

/// Applies an unhandled source error only while musl's current errno is zero.
unsafe fn host_source_errno_default_store(value: c_int) {
    // SAFETY: musl installed TLS before constructors. This immediate raw
    // projection neither escapes nor runs allocation or foreign callbacks.
    unsafe {
        let slot = __errno_location();
        if *slot == 0 { *slot = value; }
    }
}

/// Pinned `mi_process_load`: publish the host facts, start the process, and
/// install the initial thread owner. With default options, an arena is
/// reserved later when allocation needs one. Runs before `main`.
extern "C" fn process_load() {
    // SAFETY: the loader runs constructors on the initial thread.
    INITIAL_THREAD.store(unsafe { pthread_self() } as usize, Ordering::Release);
    let mut key: PthreadKey = 0;
    // SAFETY: `thread_done` has the destructor signature.
    if unsafe { pthread_key_create(&mut key, Some(thread_done)) } != 0 {
        PROCESS.store(PROCESS_FAILED, Ordering::Release);
        return;
    }
    THREAD_KEY.store(key as usize, Ordering::Release);
    // SAFETY: both providers stay valid for the process lifetime.
    let facts = unsafe {
        NativeProcessStartupFacts::new(
            getauxval(AT_PAGESZ) as usize,
            host_environment,
            RuntimeStderrOutput::new(host_stderr),
        )
    };
    let ready = match facts {
        Some(facts) => {
            // SAFETY: both permanent providers access only current-thread TLS
            // without allocation, unwinding, or a retained pointer. The default
            // provider checks zero before writing any diagnostic error.
            let facts = facts.with_source_errno_store(unsafe {
                SourceErrnoStore::new(host_source_errno_store)
                    .with_default_store(host_source_errno_default_store)
            });
            publish_native_process_startup_facts(facts) && initialize_process()
                && prepare_native_initial_thread_owner()
        }
        None => false,
    };
    PROCESS.store(if ready { PROCESS_READY } else { PROCESS_FAILED }, Ordering::Release);
    if ready {
        // SAFETY: the key was created above; the marker is not a pointer.
        unsafe { pthread_setspecific(key, THREAD_INITIAL as *const c_void) };
    }
}

#[used]
#[link_section = ".init_array"]
static PROCESS_LOAD: extern "C" fn() = process_load;

/// `mi_pthread_done`: retire a registered worker after its user destructors.
unsafe extern "C" fn thread_done(value: *mut c_void) {
    if matches!(value as usize, THREAD_ATTACHED | THREAD_FREE_ONLY) {
        let result = finish_current_thread_native_after_user_destructors();
        #[cfg(crabc_native_thread_done_audit)]
        {
            use crabc_mimalloc::__crabc_runtime::ThreadFinishResult;
            let code = match result {
                ThreadFinishResult::Finished => 0,
                ThreadFinishResult::NotAttached => 1,
                ThreadFinishResult::AlreadyFinished => 2,
                ThreadFinishResult::Retained => 3,
                ThreadFinishResult::ProcessDoneFinalTaskDecisionPending => 4,
            };
            THREAD_FINISH_RESULTS[code].fetch_add(1, Ordering::Relaxed);
        }
        #[cfg(not(crabc_native_thread_done_audit))]
        let _ = result;
    }
}

// Test-only joined-worker observations. Results are Finished, NotAttached,
// AlreadyFinished, Retained, and process-done decision pending, in that order.
// Branches describe auxiliary teardown refusal; the native owner is retained
// after any refusal. These exports are absent from the ordinary adapter.
#[cfg(crabc_native_thread_done_audit)]
static THREAD_FINISH_RESULTS: [AtomicUsize; 5] = [const { AtomicUsize::new(0) }; 5];
#[cfg(crabc_native_thread_done_audit)]
static THREAD_DONE_BRANCHES: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];

#[cfg(crabc_native_thread_done_audit)]
#[no_mangle]
pub extern "C" fn crabc_test_record_thread_done_branch(code: usize) {
    if let Some(counter) = THREAD_DONE_BRANCHES.get(code) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(crabc_native_thread_done_audit)]
#[no_mangle]
pub extern "C" fn crabc_test_thread_done_observation(kind: usize, code: usize) -> usize {
    let counters = if kind == 0 { &THREAD_FINISH_RESULTS[..] } else { &THREAD_DONE_BRANCHES[..] };
    counters.get(code).map_or(0, |counter| counter.load(Ordering::Relaxed))
}

// A single isolated worker may park after its auxiliary session opens.
// The driver releases it after observing the competing Heap destroy boundary.
#[cfg(crabc_native_thread_done_audit)]
static THREAD_DONE_DRAIN_GATE: AtomicUsize = AtomicUsize::new(0);

#[cfg(crabc_native_thread_done_audit)]
#[no_mangle]
pub extern "C" fn crabc_test_thread_done_drain_gate_control(action: usize) -> usize {
    if action == 1 { THREAD_DONE_DRAIN_GATE.store(1, Ordering::Release); }
    if action == 3 { THREAD_DONE_DRAIN_GATE.store(3, Ordering::Release); }
    THREAD_DONE_DRAIN_GATE.load(Ordering::Acquire)
}

#[cfg(crabc_native_thread_done_audit)]
#[no_mangle]
pub extern "C" fn crabc_test_thread_done_drain_gate() {
    if THREAD_DONE_DRAIN_GATE.compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        while THREAD_DONE_DRAIN_GATE.load(Ordering::Acquire) == 2 {
            core::hint::spin_loop();
        }
    }
}

/// Attaches the calling thread before an operation that needs its default Theap.
#[inline]
fn bind_thread() {
    // Key creation can fail or still be pending while the process is cold.
    if PROCESS.load(Ordering::Acquire) != PROCESS_READY {
        return;
    }
    let key = THREAD_KEY.load(Ordering::Acquire) as PthreadKey;
    // SAFETY: the key exists once the process is ready.
    let marker = unsafe { pthread_getspecific(key) } as usize;
    if marker != 0 && marker != THREAD_FREE_ONLY {
        return;
    }
    bind_thread_cold(key);
}

#[cold]
#[inline(never)]
fn bind_thread_cold(key: PthreadKey) {
    // SAFETY: plain musl thread identity calls.
    let initial = unsafe { pthread_equal(pthread_self(), INITIAL_THREAD.load(Ordering::Acquire) as Pthread) } != 0;
    let marker = if initial {
        THREAD_INITIAL
    } else {
        // SAFETY: this musl thread's allocator TLS stays mapped until its key
        // destructor finishes it; no terminal writer runs in this process.
        let registered = unsafe {
            register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor())
        };
        // A deferred attachment (a failed `_mi_thread_init`) still runs the
        // thread; its allocations retry the attachment, as in C.
        if !registered
            || !matches!(attach_current_thread(),
                ThreadAttachResult::Attached | ThreadAttachResult::AlreadyAttached | ThreadAttachResult::Deferred)
        {
            // SAFETY: an unattached worker cannot allocate; stop here.
            unsafe { abort() }
        }
        THREAD_ATTACHED
    };
    // SAFETY: the key exists; the marker is not a pointer.
    unsafe { pthread_setspecific(key, marker as *const c_void) };
}

// ---------------------------------------------------------------------------
// C runtime inputs and errno
// ---------------------------------------------------------------------------

struct MuslRuntime;

// SAFETY: every method is the named musl C function or the weak C++ symbol.
unsafe impl SourceCRuntime for MuslRuntime {
    unsafe fn getenv(&self, name: *const c_char) -> *const c_char {
        // SAFETY: forwarded NUL-terminated name.
        unsafe { getenv(name) }
    }

    unsafe fn realpath(&self, name: *const c_char, resolved: *mut c_char) -> *mut c_char {
        // SAFETY: forwarded buffer contract.
        unsafe { realpath(name, resolved) }
    }

    fn path_max(&self) -> c_long {
        // SAFETY: a constant NUL-terminated path.
        unsafe { pathconf(c"/".as_ptr(), PC_PATH_MAX) }
    }

    fn new_handler(&self) -> Option<unsafe extern "C" fn()> {
        // SAFETY: the weak symbol is null or `std::get_new_handler`.
        unsafe { _ZSt15get_new_handlerv }.and_then(|get| unsafe { get() })
    }

    fn abort(&self) -> ! {
        // SAFETY: musl `abort` never returns.
        unsafe { abort() }
    }
}

#[inline]
fn apply_errno(effect: SourceErrno) {
    if effect != SourceErrno::Unchanged {
        // SAFETY: musl's thread-local errno.
        unsafe {
            let errno = __errno_location();
            *errno = effect.apply(*errno);
        }
    }
}

#[inline]
fn finish<T>(result: Sourced<T>) -> T {
    apply_errno(result.errno);
    result.value
}

#[inline]
fn pointer(block: Block) -> *mut c_void {
    block.map_or(null_mut(), |block| block.as_ptr().cast())
}

#[inline]
fn allocation(result: Sourced<Block>) -> *mut c_void {
    pointer(finish(result))
}

#[inline]
fn freed(outcome: FreeOutcome) {
    if outcome == FreeOutcome::Retained {
        // SAFETY: a legal free the runtime could not complete is terminal;
        // there is no C backend to recover it.
        unsafe { abort() }
    }
    // A debug padding report rejects the caller's invalid free and leaves
    // that block owned, exactly as pinned `mi_free` returns after its callback.
}

#[inline]
unsafe fn write_size(out: *mut usize, value: Option<usize>) {
    if let (false, Some(value)) = (out.is_null(), value) {
        // SAFETY: the caller supplied a writable size output.
        unsafe { out.write(value) };
    }
}

// ---------------------------------------------------------------------------
// Allocation (alloc.c)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn mi_malloc(size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::malloc(size))
}

#[no_mangle]
pub extern "C" fn mi_zalloc(size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::zalloc(size))
}

#[no_mangle]
pub extern "C" fn mi_malloc_small(size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::malloc_small(size))
}

#[no_mangle]
pub extern "C" fn mi_zalloc_small(size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::zalloc_small(size))
}

#[no_mangle]
pub extern "C" fn mi_calloc(count: usize, size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::calloc(count, size))
}

#[no_mangle]
pub extern "C" fn mi_mallocn(count: usize, size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::mallocn(count, size))
}

unsafe fn with_block_size(result: Sourced<(Block, Option<usize>)>, block_size: *mut usize) -> *mut c_void {
    let (block, size) = finish(result);
    // SAFETY: forwarded writable output.
    unsafe { write_size(block_size, size) };
    pointer(block)
}

#[no_mangle]
pub unsafe extern "C" fn mi_umalloc(size: usize, block_size: *mut usize) -> *mut c_void {
    bind_thread();
    // SAFETY: forwarded output.
    unsafe { with_block_size(api::umalloc(size), block_size) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_umalloc_small(size: usize, block_size: *mut usize) -> *mut c_void {
    bind_thread();
    // SAFETY: forwarded output.
    unsafe { with_block_size(api::umalloc_small(size), block_size) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_uzalloc_small(size: usize, block_size: *mut usize) -> *mut c_void {
    bind_thread();
    // SAFETY: forwarded output.
    unsafe { with_block_size(api::uzalloc_small(size), block_size) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_ucalloc(count: usize, size: usize, block_size: *mut usize) -> *mut c_void {
    bind_thread();
    // SAFETY: forwarded output.
    unsafe { with_block_size(api::ucalloc(count, size), block_size) }
}

#[no_mangle]
pub extern "C" fn mi_new(size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::new(&MuslRuntime, size))
}

#[no_mangle]
pub extern "C" fn mi_new_nothrow(size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::new_nothrow(&MuslRuntime, size))
}

#[no_mangle]
pub extern "C" fn mi_new_n(count: usize, size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::new_n(&MuslRuntime, count, size))
}

// ---------------------------------------------------------------------------
// Free and usable size (free.c, page-queue.c, heap.c, init.c)
// ---------------------------------------------------------------------------

/// Registers pointer-only work without creating the worker's default Theap.
#[inline]
fn register_thread_for_pointer_access() {
    if PROCESS.load(Ordering::Acquire) == PROCESS_READY {
        let key = THREAD_KEY.load(Ordering::Acquire) as PthreadKey;
        // SAFETY: the process's Release publication follows key creation.
        if unsafe { pthread_getspecific(key) }.is_null() {
            // Pinned pointer lookup and free use page metadata without
            // `_mi_thread_init`. Register only the runtime admission descriptor
            // so a later free can take the metadata-Theap stats path.
            let initial = unsafe {
                pthread_equal(pthread_self(), INITIAL_THREAD.load(Ordering::Acquire) as Pthread)
            } != 0;
            if initial {
                bind_thread_cold(key);
            } else {
                let registered = unsafe {
                    register_current_native_allocator_worker_descriptor(
                        current_native_allocator_thread_descriptor(),
                    )
                };
                if !registered || unsafe { pthread_setspecific(key, THREAD_FREE_ONLY as *const c_void) } != 0 {
                    unsafe { abort() }
                }
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mi_free(block: *mut c_void) {
    if block.is_null() {
        return;
    }
    register_thread_for_pointer_access();
    // SAFETY: the C caller passes null or a live allocation it gives up.
    freed(finish(unsafe { api::free_sourced(block.cast()) }));
}

#[no_mangle]
pub unsafe extern "C" fn mi_free_small(block: *mut c_void) {
    if !block.is_null() { register_thread_for_pointer_access(); }
    // SAFETY: forwarded small allocation free contract.
    freed(finish(unsafe { api::free_small_sourced(block.cast()) }));
}

#[no_mangle]
pub unsafe extern "C" fn mi_free_size(block: *mut c_void, _size: usize) {
    // SAFETY: forwarded free contract; release ignores the size hint.
    unsafe { mi_free(block) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_free_aligned(block: *mut c_void, _alignment: usize) {
    // SAFETY: forwarded free contract; release ignores the alignment hint.
    unsafe { mi_free(block) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_free_size_aligned(block: *mut c_void, _size: usize, _alignment: usize) {
    // SAFETY: forwarded free contract; release ignores both hints.
    unsafe { mi_free(block) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_ufree(block: *mut c_void, block_size: *mut usize) {
    if !block.is_null() {
        register_thread_for_pointer_access();
    }
    // SAFETY: forwarded free contract.
    let (outcome, size) = finish(unsafe { api::ufree_sourced(block.cast()) });
    freed(outcome);
    // SAFETY: forwarded output.
    unsafe { write_size(block_size, Some(size)) };
}

#[no_mangle]
pub unsafe extern "C" fn mi_cfree(block: *mut c_void) -> bool {
    if !block.is_null() {
        register_thread_for_pointer_access();
    }
    // SAFETY: `mi_cfree` accepts any pointer the process owns.
    let (outcome, owned) = unsafe { api::cfree(block.cast()) };
    freed(outcome);
    owned
}

#[no_mangle]
pub unsafe extern "C" fn mi_usable_size(block: *const c_void) -> usize {
    if !block.is_null() {
        register_thread_for_pointer_access();
    }
    // SAFETY: the C caller passes null or a live allocation.
    finish(unsafe { api::usable_size_sourced(block.cast()) })
}

#[no_mangle]
pub extern "C" fn mi_good_size(size: usize) -> usize {
    bind_thread();
    api::good_size(size)
}

#[no_mangle]
pub extern "C" fn mi_malloc_good_size(size: usize) -> usize {
    bind_thread();
    api::malloc_good_size(size)
}

#[no_mangle]
pub unsafe extern "C" fn mi_check_owned(pointer: *const c_void) -> bool {
    bind_thread();
    // SAFETY: `mi_check_owned` accepts any pointer the process owns.
    unsafe { api::check_owned(pointer.cast()) }
}

#[no_mangle]
pub extern "C" fn mi_is_redirected() -> bool {
    api::is_redirected()
}

#[no_mangle]
pub extern "C" fn mi_collect(force: bool) {
    bind_thread();
    api::collect(force);
}

// ---------------------------------------------------------------------------
// Reallocation (alloc.c, alloc-posix.c)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn mi_expand(block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C caller passes null or a live allocation.
    pointer(unsafe { api::expand(block.cast(), new_size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi__expand(block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C caller passes null or a live allocation.
    allocation(unsafe { api::expand_errno(block.cast(), new_size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_realloc(block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::realloc(block.cast(), new_size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_reallocn(block: *mut c_void, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::reallocn(block.cast(), count, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_reallocf(block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract; `block` is consumed on every path.
    let (result, outcome) = finish(unsafe { api::reallocf(block.cast(), new_size) });
    freed(outcome);
    pointer(result)
}

#[no_mangle]
pub unsafe extern "C" fn mi_rezalloc(block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::rezalloc(block.cast(), new_size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_recalloc(block: *mut c_void, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::recalloc(block.cast(), count, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_urealloc(
    block: *mut c_void,
    new_size: usize,
    block_size_pre: *mut usize,
    block_size_post: *mut usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    let (result, pre, post) = finish(unsafe { api::urealloc(block.cast(), new_size) });
    // SAFETY: forwarded outputs.
    unsafe {
        write_size(block_size_pre, pre);
        write_size(block_size_post, post);
    }
    pointer(result)
}

#[no_mangle]
pub unsafe extern "C" fn mi_reallocarray(block: *mut c_void, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::reallocarray(block.cast(), count, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_reallocarr(pointer_to_block: *mut c_void, count: usize, size: usize) -> c_int {
    bind_thread();
    let slot = pointer_to_block.cast::<*mut u8>();
    // SAFETY: a non-null `ptrp` names the caller's live-or-null pointer.
    let current = (!slot.is_null()).then(|| unsafe { slot.read() });
    // SAFETY: the C realloc contract for `*ptrp`.
    let (code, store, outcome) = finish(unsafe { api::reallocarr(current, count, size) });
    freed(outcome);
    if let ReallocarrStore::Store(value) = store {
        // SAFETY: `store` is produced only for a non-null `ptrp`.
        unsafe { slot.write(value) };
    }
    code
}

#[no_mangle]
pub unsafe extern "C" fn mi_new_realloc(block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::new_realloc(&MuslRuntime, block.cast(), new_size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_new_reallocn(block: *mut c_void, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::new_reallocn(&MuslRuntime, block.cast(), count, size) })
}

// ---------------------------------------------------------------------------
// Aligned allocation (alloc-aligned.c, alloc-posix.c)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn mi_malloc_aligned(size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    allocation(api::malloc_aligned(size, alignment))
}

#[no_mangle]
pub extern "C" fn mi_malloc_aligned_at(size: usize, alignment: usize, offset: usize) -> *mut c_void {
    bind_thread();
    allocation(api::malloc_aligned_at(size, alignment, offset))
}

#[no_mangle]
pub extern "C" fn mi_zalloc_aligned(size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    allocation(api::zalloc_aligned(size, alignment))
}

#[no_mangle]
pub extern "C" fn mi_zalloc_aligned_at(size: usize, alignment: usize, offset: usize) -> *mut c_void {
    bind_thread();
    allocation(api::zalloc_aligned_at(size, alignment, offset))
}

#[no_mangle]
pub extern "C" fn mi_calloc_aligned(count: usize, size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    allocation(api::calloc_aligned(count, size, alignment))
}

#[no_mangle]
pub extern "C" fn mi_calloc_aligned_at(count: usize, size: usize, alignment: usize, offset: usize) -> *mut c_void {
    bind_thread();
    allocation(api::calloc_aligned_at(count, size, alignment, offset))
}

#[no_mangle]
pub unsafe extern "C" fn mi_umalloc_aligned(size: usize, alignment: usize, block_size: *mut usize) -> *mut c_void {
    bind_thread();
    // SAFETY: forwarded output.
    unsafe { with_block_size(api::umalloc_aligned(size, alignment), block_size) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_uzalloc_aligned(size: usize, alignment: usize, block_size: *mut usize) -> *mut c_void {
    bind_thread();
    // SAFETY: forwarded output.
    unsafe { with_block_size(api::uzalloc_aligned(size, alignment), block_size) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_realloc_aligned(block: *mut c_void, new_size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::realloc_aligned(block.cast(), new_size, alignment) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_realloc_aligned_at(
    block: *mut c_void,
    new_size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::realloc_aligned_at(block.cast(), new_size, alignment, offset) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_rezalloc_aligned(block: *mut c_void, new_size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::rezalloc_aligned(block.cast(), new_size, alignment) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_rezalloc_aligned_at(
    block: *mut c_void,
    new_size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::rezalloc_aligned_at(block.cast(), new_size, alignment, offset) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_recalloc_aligned(
    block: *mut c_void,
    count: usize,
    size: usize,
    alignment: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::recalloc_aligned(block.cast(), count, size, alignment) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_recalloc_aligned_at(
    block: *mut c_void,
    count: usize,
    size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: the C realloc contract.
    allocation(unsafe { api::recalloc_aligned_at(block.cast(), count, size, alignment, offset) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_aligned_recalloc(
    block: *mut c_void,
    count: usize,
    size: usize,
    alignment: usize,
) -> *mut c_void {
    // SAFETY: forwarded realloc contract.
    unsafe { mi_recalloc_aligned(block, count, size, alignment) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_aligned_offset_recalloc(
    block: *mut c_void,
    count: usize,
    size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    // SAFETY: forwarded realloc contract.
    unsafe { mi_recalloc_aligned_at(block, count, size, alignment, offset) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_posix_memalign(out: *mut *mut c_void, alignment: usize, size: usize) -> c_int {
    bind_thread();
    let (code, store) = finish(api::posix_memalign(out.is_null(), alignment, size));
    if let Some(block) = store {
        // SAFETY: `store` is produced only for a non-null output.
        unsafe { out.write(pointer(block)) };
    }
    code
}

#[no_mangle]
pub extern "C" fn mi_memalign(alignment: usize, size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::memalign(alignment, size))
}

#[no_mangle]
pub extern "C" fn mi_valloc(size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::valloc(size))
}

#[no_mangle]
pub extern "C" fn mi_pvalloc(size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::pvalloc(size))
}

#[no_mangle]
pub extern "C" fn mi_aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    bind_thread();
    allocation(api::aligned_alloc(alignment, size))
}

#[no_mangle]
pub extern "C" fn mi_new_aligned(size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    allocation(api::new_aligned(&MuslRuntime, size, alignment))
}

#[no_mangle]
pub extern "C" fn mi_new_aligned_nothrow(size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    allocation(api::new_aligned_nothrow(&MuslRuntime, size, alignment))
}

// ---------------------------------------------------------------------------
// Conveniences (alloc.c, alloc-posix.c)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn mi_strdup(text: *const c_char) -> *mut c_char {
    bind_thread();
    // SAFETY: the C caller passes null or a NUL-terminated string.
    allocation(unsafe { api::strdup(text) }).cast()
}

#[no_mangle]
pub unsafe extern "C" fn mi_strndup(text: *const c_char, max: usize) -> *mut c_char {
    bind_thread();
    // SAFETY: the C strndup contract.
    allocation(unsafe { api::strndup(text, max) }).cast()
}

#[no_mangle]
pub unsafe extern "C" fn mi_mbsdup(text: *const u8) -> *mut u8 {
    bind_thread();
    // SAFETY: the C caller passes null or a NUL-terminated string.
    allocation(unsafe { api::mbsdup(text) }).cast()
}

#[no_mangle]
pub unsafe extern "C" fn mi_wcsdup(text: *const WideChar) -> *mut WideChar {
    bind_thread();
    // SAFETY: the C caller passes null or a NUL-terminated wide string.
    allocation(unsafe { api::wcsdup(text) }).cast()
}

#[no_mangle]
pub unsafe extern "C" fn mi_realpath(name: *const c_char, resolved: *mut c_char) -> *mut c_char {
    bind_thread();
    // SAFETY: the C realpath contract.
    finish(unsafe { api::realpath(&MuslRuntime, name, resolved) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_dupenv_s(buf: *mut *mut c_char, size: *mut usize, name: *const c_char) -> c_int {
    bind_thread();
    // SAFETY: the C caller passes null or a NUL-terminated name.
    let (code, value, length) = finish(unsafe { api::dupenv_s(&MuslRuntime, buf.is_null(), size.is_null(), name) });
    // SAFETY: outputs are written only when non-null.
    unsafe {
        write_size(size, length);
        if let Some(value) = value {
            buf.write(pointer(value).cast());
        }
    }
    code
}

#[no_mangle]
pub unsafe extern "C" fn mi_wdupenv_s(buf: *mut *mut WideChar, size: *mut usize, name: *const WideChar) -> c_int {
    let (code, value, length) = api::wdupenv_s(buf.is_null(), size.is_null(), name.is_null());
    // SAFETY: outputs are written only when non-null.
    unsafe {
        write_size(size, length);
        if let Some(value) = value {
            buf.write(pointer(value).cast());
        }
    }
    code
}

// ---------------------------------------------------------------------------
// Options, callbacks, and statistics.
//
// Each entry is the same-named `crabc_mimalloc::source_options_api`
// function. Keep the C ABI projections together as the source interface grows.
// ---------------------------------------------------------------------------

use crabc_mimalloc::__crabc_runtime::source_options_api as options;

/// `mi_option_t` is a C enum, passed as `int`.
type OptionValue = c_int;
type OutputFunction = options::OutputFunction;
type ErrorFunction = options::ErrorFunction;
type DeferredFreeFunction = options::DeferredFreeFunction;

#[no_mangle]
pub extern "C" fn mi_version() -> c_int {
    options::version()
}

#[no_mangle]
pub extern "C" fn mi_option_get(option: OptionValue) -> c_long {
    options::option_get(option)
}

#[no_mangle]
pub extern "C" fn mi_option_get_clamp(option: OptionValue, min: c_long, max: c_long) -> c_long {
    options::option_get_clamp(option, min, max)
}

#[no_mangle]
pub extern "C" fn mi_option_get_size(option: OptionValue) -> usize {
    options::option_get_size(option)
}

#[no_mangle]
pub extern "C" fn mi_option_is_enabled(option: OptionValue) -> bool {
    options::option_is_enabled(option)
}

#[no_mangle]
pub extern "C" fn mi_option_set(option: OptionValue, value: c_long) {
    options::option_set(option, value)
}

#[no_mangle]
pub extern "C" fn mi_option_set_default(option: OptionValue, value: c_long) {
    options::option_set_default(option, value)
}

#[no_mangle]
pub extern "C" fn mi_option_set_enabled(option: OptionValue, enable: bool) {
    options::option_set_enabled(option, enable)
}

#[no_mangle]
pub extern "C" fn mi_option_set_enabled_default(option: OptionValue, enable: bool) {
    options::option_set_enabled_default(option, enable)
}

#[no_mangle]
pub extern "C" fn mi_option_enable(option: OptionValue) {
    options::option_set_enabled(option, true)
}

#[no_mangle]
pub extern "C" fn mi_option_disable(option: OptionValue) {
    options::option_set_enabled(option, false)
}

#[no_mangle]
pub unsafe extern "C" fn mi_options_print_out(output: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: the C caller's output callback contract.
    unsafe { options::options_print_out(output, argument) }
}

#[no_mangle]
pub extern "C" fn mi_options_print() {
    // SAFETY: the default route has no caller callback.
    unsafe { options::options_print_out(None, null_mut()) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_register_output(output: Option<OutputFunction>, argument: *mut c_void) {
    // SAFETY: the C caller's `mi_register_output` contract.
    unsafe { options::register_output(output, argument) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_register_error(handler: Option<ErrorFunction>, argument: *mut c_void) {
    // SAFETY: the C caller's `mi_register_error` contract.
    unsafe { options::register_error(handler, argument) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_register_deferred_free(callback: Option<DeferredFreeFunction>, argument: *mut c_void) {
    // SAFETY: the C caller's `mi_register_deferred_free` contract.
    unsafe { options::register_deferred_free(callback, argument) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_stats_get(stats: *mut c_void) -> bool {
    // Pinned `mi_stats_get` does not initialize the calling thread. crabc
    // libc registers every pthread's allocator descriptor before user code
    // without attaching it; do only that, as the runtime's operation
    // admission requires.
    // SAFETY: this musl thread's allocator TLS stays mapped for its life;
    // registration is idempotent.
    let _ = unsafe { register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor()) };
    // SAFETY: the C caller passes null or a `mi_stats_t`.
    unsafe { options::stats_get(stats) }
}

#[no_mangle]
/// # Safety
/// `id` is null, the main id, or a live child retained during this call.
/// `stats` is null or an aligned, exclusively readable and writable complete
/// `mi_stats_t`; the caller retains its existing Theaps and owning Heaps.
pub unsafe extern "C" fn mi_subproc_stats_get(id: *mut c_void, stats: *mut c_void) -> bool {
    register_thread_for_statistics();
    // SAFETY: the C caller retains the selected id and complete source image.
    unsafe { options::subproc_stats_get(id, stats) }
}

#[no_mangle]
/// # Safety
/// `id` is null, the main id, or a live child retained during this call.
/// `stats` is null or an aligned, exclusively readable and writable complete
/// `mi_stats_t`.
pub unsafe extern "C" fn mi_subproc_stats_get_exclusive(id: *mut c_void, stats: *mut c_void) -> bool {
    register_thread_for_statistics();
    // SAFETY: the C caller retains the selected id and complete source image.
    unsafe { options::subproc_stats_get_exclusive(id, stats) }
}

#[no_mangle]
/// # Safety
/// Retain a non-null child `id` and the calling thread's roots during the
/// snapshot. `buffer` is null or exclusively writable for `size` bytes.
/// Release an allocator-owned result with `mi_free`.
pub unsafe extern "C" fn mi_subproc_stats_get_json(id: *mut c_void, size: usize, buffer: *mut c_char) -> *mut c_char {
    register_thread_for_statistics();
    // SAFETY: the C caller's selected-id and writable-buffer contracts.
    unsafe { options::subproc_stats_json(id, size, buffer) }
}

#[no_mangle]
/// # Safety
/// `id` is null, the main id, or a child retained through every callback.
/// A selected `out` is callable with each message and `argument`; it may
/// allocate but must not destroy the selected subprocess during rendering.
pub unsafe extern "C" fn mi_subproc_stats_print_out(id: *mut c_void, out: Option<OutputFunction>, argument: *mut c_void) {
    register_thread_for_statistics();
    let out = source_output(out.map_or(core::ptr::null(), |out| out as *const c_void));
    // SAFETY: the C caller retains the selected id across valid callbacks.
    unsafe { options::subproc_stats_print_out(id, out, argument) };
}

#[no_mangle]
/// # Safety
/// `heap` is null or a live Heap. Retain it and the calling thread's selected
/// Theap and owning Heap through this call. `stats` is null or an aligned,
/// exclusively readable and writable complete `mi_stats_t`.
pub unsafe extern "C" fn mi_heap_stats_get(heap: HeapPointer, stats: *mut c_void) -> bool {
    register_thread_for_statistics();
    // SAFETY: the C caller retains the source Heap and complete source image.
    unsafe { heaps::heap_stats_get(heap, stats) }
}

#[no_mangle]
/// # Safety
/// `heap` is null or a live Heap retained with the caller's roots during
/// the snapshot. `buffer` is null or exclusively writable for `size` bytes.
/// Release an allocator-owned result with `mi_free`.
pub unsafe extern "C" fn mi_heap_stats_get_json(heap: HeapPointer, size: usize, buffer: *mut c_char) -> *mut c_char {
    register_thread_for_statistics();
    // SAFETY: the C caller retains the source Heap and writable buffer.
    unsafe { heaps::heap_stats_json(heap, size, buffer) }
}

#[no_mangle]
/// # Safety
/// Retain the selected Heap and the caller's roots during the snapshot.
/// A selected `out` and `argument` remain valid for each synchronous message;
/// callbacks may allocate but must not destroy the selected Heap.
pub unsafe extern "C" fn mi_heap_stats_print_out(heap: HeapPointer, out: Option<OutputFunction>, argument: *mut c_void) {
    register_thread_for_statistics();
    let out = source_output(out.map_or(core::ptr::null(), |out| out as *const c_void));
    // SAFETY: the C caller's Heap-lifetime and synchronous callback contracts.
    unsafe { heaps::heap_stats_print_out(heap, out, argument) };
}

#[no_mangle]
/// # Safety
/// `heap` is null or a live Heap retained with its subprocess through this
/// merge. Exclude concurrent merges and destruction of that Heap.
pub unsafe extern "C" fn mi_heap_stats_merge_to_subproc(heap: HeapPointer) {
    register_thread_for_statistics();
    // SAFETY: the C caller retains this Heap and owning subprocess.
    unsafe { heaps::heap_stats_merge_to_subproc(heap) };
}

/// Pinned `_mi_fputs` sends a null `out`, or one equal to `stdout` or
/// `stderr` (`src/options.c:466-478`), to the process default route.
fn source_output(out: *const c_void) -> Option<OutputFunction> {
    // SAFETY: plain reads of musl's permanent stream words.
    let (standard_output, standard_error) = unsafe {
        (core::ptr::read(core::ptr::addr_of!(stdout)), core::ptr::read(core::ptr::addr_of!(stderr)))
    };
    if out.is_null() || out == standard_output.cast_const() || out == standard_error.cast_const() {
        return None;
    }
    // SAFETY: the C caller passes an `mi_output_fun`.
    Some(unsafe { core::mem::transmute::<*const c_void, OutputFunction>(out) })
}

/// Registers the calling thread's allocator descriptor before a statistics
/// entry, which, as in the source, does not initialize the thread.
fn register_thread_for_statistics() {
    // SAFETY: this musl thread's allocator TLS stays mapped for its life;
    // registration is idempotent.
    let _ = unsafe { register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor()) };
}

#[no_mangle]
pub unsafe extern "C" fn mi_stats_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    register_thread_for_statistics();
    let out = source_output(out.map_or(core::ptr::null(), |out| out as *const c_void));
    // SAFETY: the C caller's `mi_output_fun` contract.
    unsafe { options::stats_print_out(out, argument) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_stats_print(out: *mut c_void) {
    register_thread_for_statistics();
    // SAFETY: as `mi_stats_print_out` with a null argument.
    unsafe { options::stats_print_out(source_output(out), core::ptr::null_mut()) }
}

/// # Safety
/// The selected subprocess stays live through every output callback. The
/// callback may allocate, but must not change that subprocess's Heap list
/// or destroy it while the source visitation lock is held.
#[no_mangle]
pub unsafe extern "C" fn mi_subproc_heap_stats_print_out(
    id: *mut c_void, out: Option<OutputFunction>, argument: *mut c_void,
) {
    register_thread_for_statistics();
    let out = source_output(out.map_or(core::ptr::null(), |out| out as *const c_void));
    // SAFETY: the C caller retains the selected subprocess and supplies the
    // synchronous output callback under the source Heap-list restrictions.
    unsafe { options::subproc_heap_stats_print_out(id, out, argument) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_thread_stats_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    register_thread_for_statistics();
    let out = source_output(out.map_or(core::ptr::null(), |out| out as *const c_void));
    // SAFETY: the C caller's `mi_output_fun` contract.
    unsafe { options::thread_stats_print_out(out, argument) }
}

#[no_mangle]
pub extern "C" fn mi_stats_reset() {
    register_thread_for_statistics();
    options::stats_reset();
}

#[no_mangle]
pub extern "C" fn mi_stats_get_bin_size(bin: usize) -> usize {
    options::stats_get_bin_size(bin)
}

#[no_mangle]
pub unsafe extern "C" fn mi_stats_get_json(size: usize, buffer: *mut c_char) -> *mut c_char {
    register_thread_for_statistics();
    // SAFETY: the C caller's buffer contract.
    unsafe { options::stats_json(core::ptr::null(), size, buffer) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_stats_as_json(stats: *const c_void, size: usize, buffer: *mut c_char) -> *mut c_char {
    register_thread_for_statistics();
    if stats.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the C caller's image and buffer contracts.
    unsafe { options::stats_json(stats, size, buffer) }
}

#[no_mangle]
pub unsafe extern "C" fn mi_process_info(
    elapsed: *mut usize, user: *mut usize, system: *mut usize, current_rss: *mut usize,
    peak_rss: *mut usize, current_commit: *mut usize, peak_commit: *mut usize, page_faults: *mut usize,
) {
    let info = options::process_info();
    for (pointer, value) in [
        (elapsed, info.elapsed_milliseconds), (user, info.user_milliseconds),
        (system, info.system_milliseconds), (current_rss, info.current_rss), (peak_rss, info.peak_rss),
        (current_commit, info.current_commit), (peak_commit, info.peak_commit),
        (page_faults, info.page_faults),
    ] {
        if !pointer.is_null() {
            // SAFETY: each non-null pointer is a writable `size_t`.
            unsafe { pointer.write(value) };
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mi_process_info_print_out(out: Option<OutputFunction>, argument: *mut c_void) {
    let out = source_output(out.map_or(core::ptr::null(), |out| out as *const c_void));
    // SAFETY: the C caller's `mi_output_fun` contract.
    unsafe { options::process_info_print_out(out, argument) }
}

#[no_mangle]
pub extern "C" fn mi_process_info_print() {
    // SAFETY: the default route.
    unsafe { options::process_info_print_out(None, core::ptr::null_mut()) }
}

// ---------------------------------------------------------------------------
// First-class Heaps and OS reservation.
//
// Each entry is the same-named `crabc_mimalloc::source_heap_api` function;
// keep these C ABI projections together as the source interface grows.
// ---------------------------------------------------------------------------

use crabc_mimalloc::__crabc_runtime::source_heap_api as heaps;

#[no_mangle]
/// # Safety
/// Arena backing and page geometry remain live and quiescent during this
/// diagnostic traversal; callbacks retain its traversed arena backing.
pub unsafe extern "C" fn mi_debug_show_arenas() {
    // SAFETY: forwarded diagnostic traversal and output callback contract.
    unsafe { heaps::debug_show_arenas() }
}

#[no_mangle]
/// # Safety
/// As `mi_debug_show_arenas`.
pub unsafe extern "C" fn mi_arenas_print() {
    // SAFETY: forwarded diagnostic traversal and output callback contract.
    unsafe { heaps::arenas_print() }
}

/// `mi_heap_t*`, opaque to C.
type HeapPointer = *mut c_void;
/// `mi_theap_t*`, opaque to C.
type TheapPointer = *mut c_void;

#[no_mangle]
/// # Safety
/// A non-null Heap remains live. No affinity setter, allocation read or Heap
/// destruction overlaps this call.
pub unsafe extern "C" fn mi_heap_set_numa_affinity(heap: HeapPointer, numa_node: c_int) {
    bind_thread();
    // SAFETY: forwarded source Heap lifetime and synchronization obligations.
    unsafe { heaps::heap_set_numa_affinity(heap, numa_node) }
}

#[no_mangle]
pub extern "C" fn mi_heap_new() -> HeapPointer {
    bind_thread();
    heaps::heap_new()
}

#[no_mangle]
/// # Safety
/// A non-null arena ID names a live parent arena returned by this process.
/// Its backing outlives the Heap and all of its Theaps and pages.
pub unsafe extern "C" fn mi_heap_new_in_arena(arena_id: *mut c_void) -> HeapPointer {
    bind_thread();
    // SAFETY: the C caller retains the arena backing and the returned Heap.
    unsafe { heaps::heap_new_in_arena(arena_id) }
}

#[no_mangle]
pub extern "C" fn mi_heap_main() -> HeapPointer {
    bind_thread();
    heaps::heap_main()
}

#[no_mangle]
/// # Safety
/// `heap` is a live Heap of this thread's subprocess and remains live until
/// the returned Theap is no longer used. The calling thread is attached.
pub unsafe extern "C" fn mi_heap_theap(heap: HeapPointer) -> TheapPointer {
    bind_thread();
    // SAFETY: the C caller retains its Heap and this thread's attachment.
    unsafe { heaps::heap_theap(heap) }
}

#[no_mangle]
pub extern "C" fn mi_theap_get_default() -> TheapPointer {
    bind_thread();
    heaps::theap_get_default()
}

#[no_mangle]
/// # Safety
/// A non-null `theap` is a live, initialized Theap of the calling thread's
/// TLD and Heap. It remains live until the prior default is restored.
pub unsafe extern "C" fn mi_theap_set_default(theap: TheapPointer) -> TheapPointer {
    bind_thread();
    // SAFETY: the caller retains the candidate and its thread association.
    unsafe { heaps::theap_set_default(theap) }
}

#[no_mangle]
/// # Safety
/// `theap` is a live Theap of the calling thread and remains linked to its
/// Heap and TLD throughout the allocation.
pub unsafe extern "C" fn mi_theap_malloc(theap: TheapPointer, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the caller retains this thread's selected Theap.
    allocation(unsafe { heaps::theap_malloc(theap, size, false) })
}

#[no_mangle]
/// # Safety
/// `theap` satisfies [`mi_theap_malloc`]'s lifetime and thread obligations.
pub unsafe extern "C" fn mi_theap_zalloc(theap: TheapPointer, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the caller retains this thread's selected Theap.
    allocation(unsafe { heaps::theap_malloc(theap, size, true) })
}

#[no_mangle]
/// # Safety
/// `theap` remains linked to the calling thread's live TLD and Heap for
/// the complete allocation.
pub unsafe extern "C" fn mi_theap_calloc(theap: TheapPointer, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the caller retains the exact current-thread Theap.
    allocation(unsafe { api::theap_calloc(theap, count, size) })
}

#[no_mangle]
/// # Safety
/// `theap` remains linked to the calling thread's live TLD and Heap, and
/// `size` does not exceed the pinned header's small-size maximum.
pub unsafe extern "C" fn mi_theap_malloc_small(theap: TheapPointer, size: usize) -> *mut c_void {
    // SAFETY: forwarded current-thread Theap and small-size obligations.
    unsafe { mi_theap_malloc(theap, size) }
}

#[no_mangle]
/// # Safety
/// `theap` remains linked to the calling thread's live TLD and Heap, and
/// `size` does not exceed the pinned header's small-size maximum.
pub unsafe extern "C" fn mi_theap_zalloc_small(theap: TheapPointer, size: usize) -> *mut c_void {
    // SAFETY: forwarded current-thread Theap and small-size obligations.
    unsafe { mi_theap_zalloc(theap, size) }
}

#[no_mangle]
/// # Safety
/// `theap` remains linked to the calling thread's live TLD and Heap for
/// the complete allocation.
pub unsafe extern "C" fn mi_theap_malloc_aligned(theap: TheapPointer, size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the caller retains the exact current-thread Theap.
    allocation(unsafe { api::theap_malloc_aligned_at(theap, size, alignment, 0, false) })
}

#[no_mangle]
/// # Safety
/// `theap` remains linked to the calling thread's live TLD and Heap for
/// the complete allocation.
pub unsafe extern "C" fn mi_theap_zalloc_aligned(theap: TheapPointer, size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the caller retains the exact current-thread Theap.
    allocation(unsafe { api::theap_malloc_aligned_at(theap, size, alignment, 0, true) })
}

#[no_mangle]
/// # Safety
/// `theap` belongs to the calling thread's live TLD and Heap, retained for
/// the call. `block` is null or an exact live allocation exclusively held
/// during reallocation; success consumes it and failure preserves it.
pub unsafe extern "C" fn mi_theap_realloc(theap: TheapPointer, block: *mut c_void, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the caller supplies the exact live client and Theap.
    allocation(unsafe { api::theap_realloc(theap, block.cast(), size, false) })
}

#[no_mangle]
/// # Safety
/// `theap` belongs to the calling thread's live TLD and Heap, retained for
/// the call. `block` is null or an exact live allocation exclusively held
/// during reallocation; success consumes it and failure preserves it.
pub unsafe extern "C" fn mi_theap_rezalloc(theap: TheapPointer, block: *mut c_void, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the caller supplies the exact live client and Theap.
    allocation(unsafe { api::theap_realloc(theap, block.cast(), size, true) })
}

#[no_mangle]
/// # Safety
/// A non-null `theap` is retained and address-stable. If initialized, it
/// belongs to the calling thread's live TLD and Heap, and no other operation
/// mutates its queues or destroys its Heap during collection.
pub unsafe extern "C" fn mi_theap_collect(theap: TheapPointer, force: bool) {
    // SAFETY: the caller retains the supplied current-thread Theap image.
    unsafe { api::theap_collect(theap, force) };
}

#[no_mangle]
/// # Safety
/// `theap` is a retained initialized image and `stats` is null or an aligned
/// writable source statistics image, excluded from other accesses for the call.
pub unsafe extern "C" fn mi_theap_stats_get(theap: TheapPointer, stats: *mut c_void) -> bool {
    register_thread_for_statistics();
    // SAFETY: the caller retains both source images for the copy.
    unsafe { api::theap_stats_get(theap, stats.cast()) }
}

#[no_mangle]
/// # Safety
/// The retained Theap, Heap, page queues, mappings, block areas and free lists
/// remain quiescent for the traversal. The callback may inspect offered
/// images only during each call and does not mutate or free a visited page.
pub unsafe extern "C" fn mi_theap_visit_blocks(
    theap: *const c_void,
    visit_blocks: bool,
    visitor: Option<heaps::HeapBlockVisitor>,
    argument: *mut c_void,
) -> bool {
    bind_thread();
    // SAFETY: forwarded complete quiescent traversal and callback lifetime.
    unsafe { api::theap_visit_blocks(theap, visit_blocks, visitor, argument) }
}

#[no_mangle]
/// The selected release build has no guarded allocation state.
pub extern "C" fn mi_theap_guarded_set_sample_rate(_theap: TheapPointer, _rate: usize, _seed: usize) {}

#[no_mangle]
/// The selected release build has no guarded allocation state.
pub extern "C" fn mi_theap_guarded_set_size_bound(_theap: TheapPointer, _minimum: usize, _maximum: usize) {}

#[no_mangle]
/// # Safety
/// `pointer` is null, lies in a live allocation held through this call, or
/// lies in caller-owned memory this allocator never mapped. No thread may
/// move its page to another Heap or unregister its arena slice concurrently.
pub unsafe extern "C" fn mi_heap_of(pointer: *const c_void) -> HeapPointer {
    bind_thread();
    // SAFETY: the C caller keeps the queried page stable for this lookup.
    unsafe { heaps::heap_of(pointer.cast()) }
}

#[no_mangle]
/// # Safety
/// The pointer and its arena slice must satisfy [`mi_heap_of`]'s obligations.
pub unsafe extern "C" fn mi_any_heap_contains(pointer: *const c_void) -> bool {
    bind_thread();
    // SAFETY: the C caller keeps the queried arena slice stable.
    unsafe { heaps::any_heap_contains(pointer.cast()) }
}

#[no_mangle]
/// # Safety
/// `pointer` is null, inside a live allocation retained through this call,
/// or in caller-owned memory this allocator never mapped. No thread may
/// register or unregister its containing PageMap slice during the lookup.
pub unsafe extern "C" fn mi_is_in_heap_region(pointer: *const c_void) -> bool {
    bind_thread();
    // SAFETY: the C caller excludes mutation of this PageMap slice.
    unsafe { heaps::is_in_heap_region(pointer.cast()) }
}

#[no_mangle]
/// # Safety
/// The pointer and its arena slice must satisfy [`mi_heap_of`]'s obligations;
/// `heap` must be null or a live Heap held through this call.
pub unsafe extern "C" fn mi_heap_contains(heap: HeapPointer, pointer: *const c_void) -> bool {
    bind_thread();
    // SAFETY: the C caller holds a live Heap and a stable queried page.
    unsafe { heaps::heap_contains(heap, pointer.cast()) }
}

#[no_mangle]
/// # Safety
/// `pointer` is null, inside a live allocation retained through this call,
/// or in caller-owned memory this allocator never mapped. Its registered
/// page and queue fields must remain stable without concurrent allocation,
/// free, collection, or Heap movement. `heap` is null or a live Heap held
/// through the call.
pub unsafe extern "C" fn mi_unsafe_heap_page_is_under_utilized(
    heap: HeapPointer,
    pointer: *mut c_void,
    percentage: usize,
) -> bool {
    bind_thread();
    // SAFETY: the C caller keeps both the PageMap slice and ordinary page
    // fields stable while the source predicate reads them.
    unsafe { heaps::heap_page_is_under_utilized(heap, pointer.cast(), percentage) }
}

#[no_mangle]
/// # Safety
/// `heap` is null or live throughout the call. Its pages, arena bitmaps,
/// block areas, and free-list state remain stable: no concurrent owner or
/// producer may move, free, mutate, or publish a remote free to them.
/// `visitor` and `argument` remain callable through the final callback. The
/// visitor may inspect an offered area or block only during that callback.
pub unsafe extern "C" fn mi_heap_visit_blocks(
    heap: HeapPointer,
    visit_blocks: bool,
    visitor: Option<heaps::HeapBlockVisitor>,
    argument: *mut c_void,
) -> bool {
    bind_thread();
    // SAFETY: the C caller holds the selected Heap and its pages quiescent
    // and retains the callback and argument for every invocation.
    unsafe { heaps::heap_visit_blocks(heap, visit_blocks, visitor, argument) }
}

#[no_mangle]
/// # Safety
/// `heap` is null or live throughout the call. Its abandoned pages, arena
/// bitmaps, block areas, and free lists remain stable with no concurrent
/// owner or producer mutating them. `visitor` and `argument` remain callable
/// through the final callback, and offered area or block pointers are used
/// only during that callback.
pub unsafe extern "C" fn mi_heap_visit_abandoned_blocks(
    heap: HeapPointer,
    visit_blocks: bool,
    visitor: Option<heaps::HeapBlockVisitor>,
    argument: *mut c_void,
) -> bool {
    bind_thread();
    // SAFETY: the caller retains the selected Heap, abandoned pages, and
    // callback for the source-ordered quiescent traversal.
    unsafe { heaps::heap_visit_abandoned_blocks(heap, visit_blocks, visitor, argument) }
}

#[inline]
fn heap_released(released: bool) {
    if !released {
        // SAFETY: a legal Heap release the runtime could not complete is
        // terminal, as a retained free is.
        unsafe { abort() }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_delete(heap: HeapPointer) {
    bind_thread();
    // SAFETY: the C caller's `mi_heap_delete` contract.
    heap_released(unsafe { heaps::heap_release(heap, false) });
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_destroy(heap: HeapPointer) {
    bind_thread();
    // SAFETY: the C caller's `mi_heap_destroy` contract.
    heap_released(unsafe { heaps::heap_release(heap, true) });
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_malloc(heap: HeapPointer, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C caller passes a live Heap.
    allocation(unsafe { heaps::heap_malloc(heap, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_zalloc(heap: HeapPointer, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_zalloc(heap, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_malloc_small(heap: HeapPointer, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above; the caller keeps `size <= MI_SMALL_SIZE_MAX`.
    allocation(unsafe { heaps::heap_malloc(heap, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_zalloc_small(heap: HeapPointer, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_zalloc(heap, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_calloc(heap: HeapPointer, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_calloc(heap, count, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_mallocn(heap: HeapPointer, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_mallocn(heap, count, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_malloc_aligned(heap: HeapPointer, size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_malloc_aligned_at(heap, size, alignment, 0, false) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_malloc_aligned_at(
    heap: HeapPointer,
    size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_malloc_aligned_at(heap, size, alignment, offset, false) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_zalloc_aligned(heap: HeapPointer, size: usize, alignment: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_malloc_aligned_at(heap, size, alignment, 0, true) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_zalloc_aligned_at(
    heap: HeapPointer,
    size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_malloc_aligned_at(heap, size, alignment, offset, true) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_calloc_aligned(
    heap: HeapPointer,
    count: usize,
    size: usize,
    alignment: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_calloc_aligned_at(heap, count, size, alignment, 0) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_calloc_aligned_at(
    heap: HeapPointer,
    count: usize,
    size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_calloc_aligned_at(heap, count, size, alignment, offset) })
}

#[no_mangle]
pub extern "C" fn mi_reserve_os_memory(size: usize, commit: bool, allow_large: bool) -> c_int {
    bind_thread();
    finish(heaps::reserve_os_memory(size, commit, allow_large))
}

#[no_mangle]
pub unsafe extern "C" fn mi_reserve_os_memory_ex(
    size: usize,
    commit: bool,
    allow_large: bool,
    exclusive: bool,
    arena_id: *mut *mut c_void,
) -> c_int {
    bind_thread();
    // SAFETY: the C caller passes null or a writable `mi_arena_id_t*`.
    finish(unsafe { heaps::reserve_os_memory_ex(size, commit, allow_large, exclusive, arena_id) })
}

#[no_mangle]
/// # Safety
/// `arena_id` is null or writable; a returned arena ID remains owned by its
/// subprocess through every use of the reserved huge backing.
pub unsafe extern "C" fn mi_reserve_huge_os_pages_at_ex(
    pages: usize,
    numa_node: c_int,
    timeout_milliseconds: usize,
    exclusive: bool,
    arena_id: *mut *mut c_void,
) -> c_int {
    bind_thread();
    // SAFETY: the C caller supplies null or a writable arena-ID output.
    finish(unsafe { heaps::reserve_huge_os_pages_at_ex(
        pages, numa_node, timeout_milliseconds, exclusive, arena_id,
    ) })
}

#[no_mangle]
/// # Safety
/// `size` is null or writable; a non-null arena ID names a live parent
/// arena of this process for the duration of the query.
pub unsafe extern "C" fn mi_arena_area(arena_id: *mut c_void, size: *mut usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C caller supplies a live arena ID and writable output.
    unsafe { heaps::arena_area(arena_id, size) }
}

#[no_mangle]
pub extern "C" fn mi_arena_min_size() -> usize {
    heaps::arena_min_size()
}

#[no_mangle]
pub extern "C" fn mi_arena_min_alignment() -> usize {
    heaps::arena_min_alignment()
}

#[no_mangle]
pub extern "C" fn mi_arena_max_object_size() -> usize {
    heaps::arena_max_object_size()
}

#[no_mangle]
/// # Safety
/// A non-null arena ID names a live parent arena whose backing remains live
/// throughout the query.
pub unsafe extern "C" fn mi_arena_contains(arena_id: *mut c_void, pointer: *const c_void) -> bool {
    bind_thread();
    // SAFETY: the C caller supplies a live arena ID for this query.
    unsafe { heaps::arena_contains(arena_id, pointer) }
}

#[no_mangle]
/// # Safety
/// The external mapped range and its true commitment and zero state are
/// retained by the caller for every arena owner; `arena_id` is null or writable.
pub unsafe extern "C" fn mi_manage_os_memory_ex(
    start: *mut c_void,
    size: usize,
    is_committed: bool,
    is_pinned: bool,
    is_zero: bool,
    numa_node: c_int,
    exclusive: bool,
    arena_id: *mut *mut c_void,
) -> bool {
    bind_thread();
    // SAFETY: the C caller retains the external region and writable output.
    unsafe { heaps::manage_os_memory_ex(
        start, size, is_committed, is_pinned, is_zero, numa_node, exclusive, arena_id,
    ) }
}

#[no_mangle]
/// # Safety
/// The caller retains the mapped range, callback code, and callback argument
/// through every arena, Heap, Theap, page, and callback use. A true callback
/// commit makes its entire span accessible; callback state synchronizes
/// concurrent or reentrant calls. `arena_id` is null or writable.
pub unsafe extern "C" fn mi_manage_memory(
    start: *mut c_void,
    size: usize,
    is_committed: bool,
    is_pinned: bool,
    is_zero: bool,
    numa_node: c_int,
    exclusive: bool,
    callback: Option<heaps::ManagedCommitFunction>,
    user_argument: *mut c_void,
    arena_id: *mut *mut c_void,
) -> bool {
    bind_thread();
    // SAFETY: the public caller retains the external mapping and callback
    // capability for the same complete arena lifetime.
    unsafe { heaps::manage_memory(start, size, is_committed, is_pinned,
        is_zero, numa_node, exclusive, callback, user_argument, arena_id) }
}

#[no_mangle]
/// # Safety
/// The caller retains the external mapped range through all arena, Heap,
/// Theap and page uses; commitment and zero flags describe its initial state.
pub unsafe extern "C" fn mi_manage_os_memory(
    start: *mut c_void,
    size: usize,
    is_committed: bool,
    is_pinned: bool,
    is_zero: bool,
    numa_node: c_int,
) -> bool {
    bind_thread();
    // SAFETY: the C caller retains the range; source selects a nonexclusive
    // arena and no arena-ID output through this public form.
    unsafe { heaps::manage_os_memory(start, size, is_committed, is_pinned, is_zero, numa_node) }
}

// ---------------------------------------------------------------------------
// Heap reallocation, strings, `new`, and collection.
// ---------------------------------------------------------------------------

type HeapChar = c_char;

#[inline]
fn reallocation(result: Sourced<(Block, FreeOutcome)>) -> *mut c_void {
    let (block, outcome) = finish(result);
    freed(outcome);
    pointer(block)
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_realloc(heap: HeapPointer, block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C caller's `mi_heap_realloc` contract.
    reallocation(unsafe { heaps::heap_realloc(heap, block.cast(), new_size, false) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_reallocn(heap: HeapPointer, block: *mut c_void, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_reallocn(heap, block.cast(), count, size, false) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_reallocf(heap: HeapPointer, block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_reallocf(heap, block.cast(), new_size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_rezalloc(heap: HeapPointer, block: *mut c_void, new_size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_realloc(heap, block.cast(), new_size, true) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_recalloc(heap: HeapPointer, block: *mut c_void, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_reallocn(heap, block.cast(), count, size, true) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_realloc_aligned(
    heap: HeapPointer,
    block: *mut c_void,
    new_size: usize,
    alignment: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_realloc_aligned(heap, block.cast(), new_size, alignment, None, false) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_realloc_aligned_at(
    heap: HeapPointer,
    block: *mut c_void,
    new_size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_realloc_aligned(heap, block.cast(), new_size, alignment, Some(offset), false) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_rezalloc_aligned(
    heap: HeapPointer,
    block: *mut c_void,
    new_size: usize,
    alignment: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_realloc_aligned(heap, block.cast(), new_size, alignment, None, true) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_rezalloc_aligned_at(
    heap: HeapPointer,
    block: *mut c_void,
    new_size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_realloc_aligned(heap, block.cast(), new_size, alignment, Some(offset), true) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_recalloc_aligned(
    heap: HeapPointer,
    block: *mut c_void,
    count: usize,
    size: usize,
    alignment: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_recalloc_aligned(heap, block.cast(), count, size, alignment, None) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_recalloc_aligned_at(
    heap: HeapPointer,
    block: *mut c_void,
    count: usize,
    size: usize,
    alignment: usize,
    offset: usize,
) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    reallocation(unsafe { heaps::heap_recalloc_aligned(heap, block.cast(), count, size, alignment, Some(offset)) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_strdup(heap: HeapPointer, text: *const HeapChar) -> *mut HeapChar {
    bind_thread();
    // SAFETY: the C caller passes null or a NUL-terminated string.
    allocation(unsafe { heaps::heap_strdup(heap, text) }).cast()
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_strndup(heap: HeapPointer, text: *const HeapChar, max: usize) -> *mut HeapChar {
    bind_thread();
    // SAFETY: as above, bounded by `max`.
    allocation(unsafe { heaps::heap_strndup(heap, text, max) }).cast()
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_realpath(heap: HeapPointer, name: *const HeapChar, resolved: *mut HeapChar) -> *mut HeapChar {
    bind_thread();
    // SAFETY: the C caller's `mi_heap_realpath` contract.
    finish(unsafe { heaps::heap_realpath(&MuslRuntime, heap, name, resolved) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_alloc_new(heap: HeapPointer, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: the C caller passes a live Heap.
    allocation(unsafe { heaps::heap_alloc_new(&MuslRuntime, heap, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_alloc_new_n(heap: HeapPointer, count: usize, size: usize) -> *mut c_void {
    bind_thread();
    // SAFETY: as above.
    allocation(unsafe { heaps::heap_alloc_new_n(&MuslRuntime, heap, count, size) })
}

#[no_mangle]
pub unsafe extern "C" fn mi_heap_collect(heap: HeapPointer, force: bool) {
    bind_thread();
    // SAFETY: the C caller passes a live Heap.
    unsafe { heaps::heap_collect(heap, force) }
}

// ---------------------------------------------------------------------------
// Subprocesses.
// ---------------------------------------------------------------------------

/// `mi_subproc_id_t`: a struct holding one pointer, passed by value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SubprocId {
    id: *mut c_void,
}

#[no_mangle]
pub extern "C" fn mi_subproc_main() -> SubprocId {
    bind_thread();
    SubprocId { id: heaps::subproc_main() }
}

#[no_mangle]
pub extern "C" fn mi_subproc_current() -> SubprocId {
    bind_thread();
    SubprocId { id: heaps::subproc_current() }
}

#[no_mangle]
pub extern "C" fn mi_subproc_new() -> SubprocId {
    bind_thread();
    SubprocId { id: heaps::subproc_new() }
}

#[no_mangle]
pub unsafe extern "C" fn mi_subproc_destroy(subproc: SubprocId) {
    bind_thread();
    // SAFETY: the C caller passes a live id; a child that threads still
    // belong to is left alive rather than destroyed under them.
    let _ = unsafe { heaps::subproc_destroy(subproc.id) };
}

/// Pinned `mi_subproc_add_current_thread`, for a thread that has made no
/// allocation: the thread registers with the runtime without attaching to
/// the process main subprocess, and on admission its key marks it attached
/// so the key destructor finishes it in the child.
#[no_mangle]
pub unsafe extern "C" fn mi_subproc_add_current_thread(subproc: SubprocId) {
    if PROCESS.load(Ordering::Acquire) != PROCESS_READY {
        return;
    }
    let key = THREAD_KEY.load(Ordering::Acquire) as PthreadKey;
    // SAFETY: the key exists once the process is ready.
    let bound = !unsafe { pthread_getspecific(key) }.is_null();
    if !bound {
        // SAFETY: this musl thread's allocator TLS stays mapped until its key
        // destructor finishes it.
        let _ = unsafe {
            register_current_native_allocator_worker_descriptor(current_native_allocator_thread_descriptor())
        };
    }
    // SAFETY: the C caller's contract: a live id, on a thread that has not
    // allocated yet.
    let added = unsafe { heaps::subproc_add_current_thread(subproc.id) };
    if !bound && added == heaps::SubprocAddCurrentThread::Added {
        // SAFETY: the key exists; the marker is not a pointer.
        unsafe { pthread_setspecific(key, THREAD_ATTACHED as *const c_void) };
    }
}

#[no_mangle]
pub unsafe extern "C" fn mi_subproc_visit_heaps(
    subproc: SubprocId,
    visitor: Option<heaps::HeapVisitor>,
    argument: *mut c_void,
) -> bool {
    bind_thread();
    let Some(visitor) = visitor else { return false };
    // SAFETY: the C caller's visitor contract.
    unsafe { heaps::subproc_visit_heaps(subproc.id, visitor, argument) }
}
