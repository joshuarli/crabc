//! Evidence-only unprefixed `mi_*` C ABI over the native crabc-mimalloc
//! runtime.
//!
//! This static library lets an unmodified C program written against the
//! pinned mimalloc v3.5.0 `mimalloc.h` run on the Rust port inside a musl
//! process: the allocator M4 differential links its shared C driver once
//! against the pinned C sources and once against this library, and the
//! upstream `test/test-api.c` links against it. It is not a production
//! allocator: it neither interposes `malloc` nor enters crabc libc, and the
//! C backend remains selected everywhere else.
//!
//! The exported functions are exactly the M4 external functions of
//! `compat/allocator/m4-gate-x86_64-v3.5.0.json`, each a thin projection of
//! the same-named `crabc_mimalloc::source_api` entry, which applies the
//! returned errno effect to musl's `errno`.
//!
//! Process and thread binding follow the selected Linux primitives of pinned
//! `src/prim/unix/prim.c` and `src/init.c`: a load-time constructor publishes
//! the host's startup facts and starts the process (`mi_process_load`), and a
//! thread's first entry registers and attaches it and associates a
//! `pthread_key_t` whose destructor finishes it
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
    NativeProcessStartupFacts, RuntimeStderrOutput, ThreadAttachResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, initialize_process,
    prepare_native_later_thread_arena, publish_native_process_startup_facts,
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

// Values stored under the thread key: the initial thread is process-owned
// and never finished by the key; an attached worker is.
const THREAD_INITIAL: usize = 1;
const THREAD_ATTACHED: usize = 2;

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

/// Pinned `mi_process_load`: publish the host facts, start the process, and
/// prepare the arena later threads share, as crabc libc's selected startup
/// does. Runs once, from the initial thread, before `main`.
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
            publish_native_process_startup_facts(facts) && initialize_process() && prepare_native_later_thread_arena()
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

/// `mi_pthread_done`: finish an attached worker after its user destructors.
unsafe extern "C" fn thread_done(value: *mut c_void) {
    if value as usize == THREAD_ATTACHED {
        let _ = finish_current_thread_native_after_user_destructors();
    }
}

/// Binds the calling thread before its first native operation.
#[inline]
fn bind_thread() {
    let key = THREAD_KEY.load(Ordering::Acquire) as PthreadKey;
    // SAFETY: the key exists once the process is ready.
    if PROCESS.load(Ordering::Acquire) != PROCESS_READY || !unsafe { pthread_getspecific(key) }.is_null() {
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
        if !registered || attach_current_thread() != ThreadAttachResult::Attached {
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

#[no_mangle]
pub unsafe extern "C" fn mi_free(block: *mut c_void) {
    bind_thread();
    // SAFETY: the C caller passes null or a live allocation it gives up.
    freed(unsafe { api::free(block.cast()) });
}

#[no_mangle]
pub unsafe extern "C" fn mi_free_small(block: *mut c_void) {
    // SAFETY: forwarded free contract.
    unsafe { mi_free(block) }
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
    bind_thread();
    // SAFETY: forwarded free contract.
    let (outcome, size) = unsafe { api::ufree(block.cast()) };
    freed(outcome);
    // SAFETY: forwarded output.
    unsafe { write_size(block_size, Some(size)) };
}

#[no_mangle]
pub unsafe extern "C" fn mi_cfree(block: *mut c_void) -> bool {
    bind_thread();
    // SAFETY: `mi_cfree` accepts any pointer the process owns.
    let (outcome, owned) = unsafe { api::cfree(block.cast()) };
    freed(outcome);
    owned
}

#[no_mangle]
pub unsafe extern "C" fn mi_usable_size(block: *const c_void) -> usize {
    bind_thread();
    // SAFETY: the C caller passes null or a live allocation.
    unsafe { api::usable_size(block.cast()) }
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
