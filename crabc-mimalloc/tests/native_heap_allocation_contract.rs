#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicUsize, Ordering};
use crabc_mimalloc::source_api::{self as api, Block, SourceCRuntime, Sourced};
use crabc_mimalloc::source_heap_api as heaps;

unsafe extern "C" {
    fn getenv(name: *const c_char) -> *mut c_char;
    fn realpath(name: *const c_char, resolved: *mut c_char) -> *mut c_char;
    fn pathconf(path: *const c_char, name: c_int) -> c_long;
}

// Pinned public mi_option_t value for arena_reserve.
const ARENA_RESERVE: i32 = 23;
const PATH_MAX_PARAMETER: c_int = 4;
// Debug pointer validation accepts word-aligned clients. Use a nonzero
// word-sized offset so usable-size, reallocation, and free follow that
// source precondition while release still exercises byte-granular offsets.
const ALIGNED_OFFSET: usize = if cfg!(feature = "mi-debug-1") { 8 } else { 7 };

static NEW_CALLS: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" fn new_handler() { NEW_CALLS.fetch_add(1, Ordering::Relaxed); }
struct Runtime;
// SAFETY: musl owns the process-lifetime C environment and path operations.
// The new handler only increments a counter and never enters the allocator.
unsafe impl SourceCRuntime for Runtime {
    unsafe fn getenv(&self, name: *const c_char) -> *const c_char {
        unsafe { getenv(name) }
    }
    unsafe fn realpath(&self, name: *const c_char, resolved: *mut c_char) -> *mut c_char {
        unsafe { realpath(name, resolved) }
    }
    fn path_max(&self) -> c_long { unsafe { pathconf(c"/".as_ptr(), PATH_MAX_PARAMETER) } }
    fn new_handler(&self) -> Option<unsafe extern "C" fn()> { Some(new_handler) }
    fn abort(&self) -> ! { std::process::abort() }
}

#[derive(Clone, Copy)]
enum Replacement {
    Plain, Counted, Zeroed, CountedZeroed,
    Aligned, AlignedAt, AlignedZeroed, AlignedAtZeroed,
    AlignedCountedZeroed, AlignedAtCountedZeroed,
}

impl Replacement {
    fn zeroed(self) -> bool {
        matches!(self, Self::Zeroed | Self::CountedZeroed | Self::AlignedZeroed
            | Self::AlignedAtZeroed | Self::AlignedCountedZeroed | Self::AlignedAtCountedZeroed)
    }
    fn counted(self) -> bool {
        matches!(self, Self::Counted | Self::CountedZeroed
            | Self::AlignedCountedZeroed | Self::AlignedAtCountedZeroed)
    }
    fn aligned(self) -> bool {
        !matches!(self, Self::Plain | Self::Counted | Self::Zeroed | Self::CountedZeroed)
    }
    fn offset(self) -> Option<usize> {
        matches!(self, Self::AlignedAt | Self::AlignedAtZeroed | Self::AlignedAtCountedZeroed)
            .then_some(ALIGNED_OFFSET)
    }
}

fn block(result: Sourced<Block>) -> NonNull<u8> {
    assert_eq!(result.errno.apply(37), 37);
    result.value.expect("a valid Heap request allocates")
}

unsafe fn contents(pointer: NonNull<u8>, size: usize, byte: u8) {
    for index in 0..size {
        assert_eq!(unsafe { pointer.as_ptr().add(index).read() }, byte, "byte {index}");
    }
}

unsafe fn free(pointer: NonNull<u8>) {
    assert_eq!(unsafe { api::free(pointer.as_ptr()) }, api::FreeOutcome::Freed);
}

#[test]
fn heap_requests_preserve_content_failure_and_legal_release_lifetimes() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    // OS-backed pages exercise source commitment and released-Heap ownership.
    // Select that public VM policy before any application Heap allocation.
    crabc_mimalloc::source_options_api::option_set(
        ARENA_RESERVE, 0,
    );
    let growth_heap = heaps::heap_new();
    assert!(!growth_heap.is_null());
    // Keep same-bin clients live until allocation must extend or add a page.
    for index in 0..28 {
        let allocation = unsafe { heaps::heap_malloc(growth_heap, 8192) };
        assert!(allocation.value.is_some(), "ordinary OS Heap page growth fails at {index}");
    }
    assert!(unsafe { heaps::heap_release(growth_heap, true) });
    let heap = heaps::heap_new();
    assert!(!heap.is_null());
    let runtime = Runtime;
    let count_overflow_errno = if cfg!(feature = "mi-debug-1") { 12 } else { 0 };
    let mut live = Vec::new();

    // All blocks stay live together, so zeroing must not overwrite a neighbor.
    // The small exported entries use the same Heap allocation kernel.
    unsafe {
        for zero in [false, true] {
            let ordinary = block(if zero { heaps::heap_zalloc(heap, 73) } else { heaps::heap_malloc(heap, 73) });
            if zero { contents(ordinary, 73, 0); }
            ordinary.as_ptr().write_bytes(0xa5, 73);
            live.push((ordinary, 73));
            let counted = block(if zero { heaps::heap_calloc(heap, 1, 73) } else { heaps::heap_mallocn(heap, 1, 73) });
            if zero { contents(counted, 73, 0); }
            counted.as_ptr().write_bytes(0xa5, 73);
            live.push((counted, 73));
            for offset in [0, ALIGNED_OFFSET] {
                let aligned = block(heaps::heap_malloc_aligned_at(heap, 73, 128, offset, zero));
                assert_eq!((aligned.as_ptr().addr() + offset) % 128, 0);
                if zero { contents(aligned, 73, 0); }
                aligned.as_ptr().write_bytes(0xa5, 73);
                live.push((aligned, 73));
                let calloc = block(heaps::heap_calloc_aligned_at(heap, 1, 73, 128, offset));
                contents(calloc, 73, 0);
                calloc.as_ptr().write_bytes(0xa5, 73);
                live.push((calloc, 73));
            }
        }
        for (result, errno) in [(heaps::heap_malloc(heap, usize::MAX), 12),
            (heaps::heap_zalloc(heap, usize::MAX), 12),
            (heaps::heap_calloc(heap, usize::MAX, 2), count_overflow_errno),
            (heaps::heap_mallocn(heap, usize::MAX, 2), count_overflow_errno),
            (heaps::heap_calloc_aligned_at(heap, usize::MAX, 2, 128, ALIGNED_OFFSET), count_overflow_errno)] {
            assert!(result.value.is_none());
            assert_eq!(result.errno.apply(0), errno);
            assert_eq!(result.errno.apply(37), 37);
        }
        for zero in [false, true] {
            for offset in [0, ALIGNED_OFFSET] {
                let invalid = heaps::heap_malloc_aligned_at(heap, 73, 24, offset, zero);
                assert!(invalid.value.is_none());
                assert_eq!(invalid.errno.apply(0), 22);
                assert_eq!(invalid.errno.apply(37), 37);
            }
        }
        for (pointer, size) in &live {
            assert_eq!(heaps::heap_of(pointer.as_ptr()), heap);
            contents(*pointer, *size, 0xa5);
        }

        // A failed replacement preserves the exact live pointer and payload.
        // Growth then verifies both the preserved prefix and the zero tail.
        for entry in [Replacement::Plain, Replacement::Counted, Replacement::Zeroed,
            Replacement::CountedZeroed, Replacement::Aligned, Replacement::AlignedAt,
            Replacement::AlignedZeroed, Replacement::AlignedAtZeroed,
            Replacement::AlignedCountedZeroed, Replacement::AlignedAtCountedZeroed] {
            let original = block(heaps::heap_zalloc(heap, 73));
            original.as_ptr().write_bytes(0x6b, 73);
            let zero = entry.zeroed();
            let replace = |pointer, size| match entry {
                Replacement::Plain | Replacement::Zeroed => heaps::heap_realloc(heap, pointer, size, zero),
                Replacement::Counted | Replacement::CountedZeroed => heaps::heap_reallocn(heap, pointer, 1, size, zero),
                Replacement::AlignedCountedZeroed | Replacement::AlignedAtCountedZeroed =>
                    heaps::heap_recalloc_aligned(heap, pointer, 1, size, 128, entry.offset()),
                _ => heaps::heap_realloc_aligned(heap, pointer, size, 128, entry.offset(), zero),
            };
            let failed = replace(original.as_ptr(), usize::MAX);
            assert!(failed.value.0.is_none());
            assert_ne!(failed.errno.apply(0), 0);
            contents(original, 73, 0x6b);
            if entry.counted() {
                let overflow = if !entry.aligned() {
                    heaps::heap_reallocn(heap, original.as_ptr(), usize::MAX, 2, zero)
                } else {
                    heaps::heap_recalloc_aligned(heap, original.as_ptr(), usize::MAX, 2, 128,
                        entry.offset())
                };
                assert!(overflow.value.0.is_none());
                assert_eq!(overflow.errno.apply(37), 37);
                assert_eq!(overflow.errno.apply(0), count_overflow_errno);
                contents(original, 73, 0x6b);
            }
            if entry.aligned() {
                let invalid = heaps::heap_realloc_aligned(heap, original.as_ptr(), 4096, 24,
                    entry.offset(), zero);
                assert!(invalid.value.0.is_none());
                assert_eq!(invalid.errno.apply(0), 22);
                contents(original, 73, 0x6b);
            }
            let grown = replace(original.as_ptr(), 4096).value.0.expect("growth succeeds");
            contents(grown, 73, 0x6b);
            if zero { contents(NonNull::new_unchecked(grown.as_ptr().add(73)), 4096 - 73, 0); }
            if entry.aligned() { assert_eq!((grown.as_ptr().addr() + entry.offset().unwrap_or(0)) % 128, 0); }
            assert_eq!(heaps::heap_of(grown.as_ptr()), heap);
            grown.as_ptr().write_bytes(0xa5, 4096);
            live.push((grown, 4096));
        }
        let consumed = block(heaps::heap_malloc(heap, 73));
        let failed = heaps::heap_reallocf(heap, consumed.as_ptr(), usize::MAX);
        assert!(failed.value.0.is_none());
        assert_eq!(failed.value.1, api::FreeOutcome::Freed);

        let text = c"heap-content";
        let duplicate = block(heaps::heap_strdup(heap, text.as_ptr()));
        assert_eq!(core::slice::from_raw_parts(duplicate.as_ptr(), 13), text.to_bytes_with_nul());
        duplicate.as_ptr().write_bytes(0xa5, 13);
        live.push((duplicate, 13));
        let limited = block(heaps::heap_strndup(heap, text.as_ptr(), 4));
        assert_eq!(core::slice::from_raw_parts(limited.as_ptr(), 5), b"heap\0");
        limited.as_ptr().write_bytes(0xa5, 5);
        live.push((limited, 5));
        assert!(heaps::heap_strdup(heap, core::ptr::null()).value.is_none());
        assert!(heaps::heap_strndup(heap, core::ptr::null(), 4).value.is_none());
        let path = heaps::heap_realpath(&runtime, heap, c"/".as_ptr(), null_mut()).value;
        assert!(!path.is_null());
        assert_eq!(core::ffi::CStr::from_ptr(path), c"/");
        path.cast::<u8>().write_bytes(0xa5, 2);
        live.push((NonNull::new_unchecked(path.cast()), 2));
        assert!(heaps::heap_realpath(&runtime, heap, c"/crabc-heap-contract-absent/path".as_ptr(), null_mut()).value.is_null());
        for result in [heaps::heap_alloc_new(&runtime, heap, 73), heaps::heap_alloc_new_n(&runtime, heap, 1, 73)] {
            let pointer = block(result);
            pointer.as_ptr().write_bytes(0xa5, 73);
            live.push((pointer, 73));
        }
        assert!(heaps::heap_alloc_new(&runtime, heap, usize::MAX).value.is_none());
        assert!(heaps::heap_alloc_new_n(&runtime, heap, usize::MAX, 2).value.is_none());
        assert_eq!(NEW_CALLS.load(Ordering::Relaxed), 2);

        let reallocf_source = block(heaps::heap_malloc(heap, 73));
        reallocf_source.as_ptr().write_bytes(0xa5, 73);
        let reallocf_result = heaps::heap_reallocf(heap, reallocf_source.as_ptr(), 4096).value.0.unwrap();
        contents(reallocf_result, 73, 0xa5);
        reallocf_result.as_ptr().write_bytes(0xa5, 4096);
        live.push((reallocf_result, 4096));

        refusal_preserves_live_clients(heap, &runtime);

        // Delete preserves application blocks. Their former Heap handle is
        // not passed to any operation after release; a live destination Heap
        // accepts each replacement and owns the copied content.
        assert!(heaps::heap_release(heap, false));
        let destination = heaps::heap_new();
        assert!(!destination.is_null());
        for (index, (pointer, size)) in live.into_iter().enumerate() {
            contents(pointer, size, 0xa5);
            assert!(!heaps::heap_theap(destination).is_null(), "destination remains live at output {index}");
            let usable = api::usable_size_sourced(pointer.as_ptr());
            assert_eq!(usable.errno.apply(37), 37);
            let observed = usable.value;
            assert!(observed >= size, "released live output {index} remains usable");
            let owner = heaps::heap_of(pointer.as_ptr());
            let replacement = heaps::heap_realloc(destination, pointer.as_ptr(), 8192, false);
            let moved = replacement.value.0.unwrap_or_else(|| panic!(
                "live output {index}: usable={observed}, heap={owner:p}, errno={}",
                replacement.errno.apply(0),
            ));
            contents(moved, size, 0xa5);
            assert_eq!(heaps::heap_of(moved.as_ptr()), destination);
            // Keep every moved output live until the destination is destroyed.
        }
        let terminal = block(heaps::heap_zalloc(destination, 4096));
        contents(terminal, 4096, 0);
        assert!(heaps::heap_release(destination, true));
        // Destroy consumes every remaining block; none is read or freed.
        let after = block(heaps::heap_malloc(heaps::heap_main(), 73));
        after.as_ptr().write_bytes(0x37, 73);
        contents(after, 73, 0x37);
        free(after);
    }
}

// The caller owns this live Heap and every input; no concurrent operation
// observes the temporary VM policy or accesses the tested clients.
unsafe fn refusal_preserves_live_clients(heap: *mut c_void, runtime: &Runtime) {
    use crabc_mimalloc::source_options_api as options;
    const DISALLOW_OS_ALLOC: i32 = 17;
    const DISALLOW_ARENA_ALLOC: i32 = 26;
    let empty = heaps::heap_new();
    assert!(!empty.is_null());
    assert!(!unsafe { heaps::heap_theap(empty) }.is_null());
    let sentinel = block(unsafe { heaps::heap_malloc(heap, 73) });
    unsafe { sentinel.as_ptr().write_bytes(0xa5, 73) };
    let mut originals = Vec::new();
    for _ in 0..11 {
        let original = block(unsafe { heaps::heap_malloc(heap, 73) });
        unsafe { original.as_ptr().write_bytes(0x6b, 73) };
        originals.push(original);
    }
    // Create every input before refusing new pages. The untouched Heap has
    // no application pages, so a valid small request must use the VM policy.
    let previous_os = options::option_get(DISALLOW_OS_ALLOC);
    let previous_arena = options::option_get(DISALLOW_ARENA_ALLOC);
    options::option_set(DISALLOW_OS_ALLOC, 1);
    options::option_set(DISALLOW_ARENA_ALLOC, 1);
    unsafe {
        for (name, request) in [
            ("malloc", heaps::heap_malloc(empty, 73)),
            ("zalloc", heaps::heap_zalloc(empty, 73)),
            ("calloc", heaps::heap_calloc(empty, 1, 73)),
            ("mallocn", heaps::heap_mallocn(empty, 1, 73)),
            ("malloc_aligned", heaps::heap_malloc_aligned_at(empty, 73, 128, 0, false)),
            ("malloc_aligned_at", heaps::heap_malloc_aligned_at(empty, 73, 128, ALIGNED_OFFSET, false)),
            ("zalloc_aligned", heaps::heap_malloc_aligned_at(empty, 73, 128, 0, true)),
            ("zalloc_aligned_at", heaps::heap_malloc_aligned_at(empty, 73, 128, ALIGNED_OFFSET, true)),
            ("calloc_aligned", heaps::heap_calloc_aligned_at(empty, 1, 73, 128, 0)),
            ("calloc_aligned_at", heaps::heap_calloc_aligned_at(empty, 1, 73, 128, ALIGNED_OFFSET)),
            ("strdup", heaps::heap_strdup(empty, c"heap-content".as_ptr())),
            ("strndup", heaps::heap_strndup(empty, c"heap-content".as_ptr(), 4)),
        ] {
            assert!(request.value.is_none(), "{name} refuses a fresh page");
            assert_eq!(request.errno.apply(0), 12, "{name}");
            assert_eq!(request.errno.apply(37), 37, "{name} preserves prior errno");
            contents(sentinel, 73, 0xa5);
            assert_eq!(heaps::heap_of(sentinel.as_ptr()), heap);
        }
        let path = heaps::heap_realpath(runtime, empty, c"/".as_ptr(), null_mut());
        assert!(path.value.is_null());
        assert_eq!(path.errno.apply(0), 12);
        let calls_before = NEW_CALLS.load(Ordering::Relaxed);
        for request in [heaps::heap_alloc_new(runtime, empty, 73),
                        heaps::heap_alloc_new_n(runtime, empty, 1, 73)] {
            assert!(request.value.is_none());
            assert_eq!(request.errno.apply(0), 12);
            assert_eq!(request.errno.apply(37), 37);
        }
        assert_eq!(NEW_CALLS.load(Ordering::Relaxed) - calls_before, 8);
        for (index, entry) in [Replacement::Plain, Replacement::Counted, Replacement::Zeroed,
            Replacement::CountedZeroed, Replacement::Aligned, Replacement::AlignedAt,
            Replacement::AlignedZeroed, Replacement::AlignedAtZeroed,
            Replacement::AlignedCountedZeroed, Replacement::AlignedAtCountedZeroed].into_iter().enumerate() {
            let original = originals[index];
            let size = 16 * 1024 * 1024;
            let zero = entry.zeroed();
            let request = match entry {
                Replacement::Plain | Replacement::Zeroed => heaps::heap_realloc(empty, original.as_ptr(), size, zero),
                Replacement::Counted | Replacement::CountedZeroed => heaps::heap_reallocn(empty, original.as_ptr(), 1, size, zero),
                Replacement::AlignedCountedZeroed | Replacement::AlignedAtCountedZeroed =>
                    heaps::heap_recalloc_aligned(empty, original.as_ptr(), 1, size, 128, entry.offset()),
                _ => heaps::heap_realloc_aligned(empty, original.as_ptr(), size, 128, entry.offset(), zero),
            };
            assert!(request.value.0.is_none(), "replacement {index} refuses growth");
            assert_eq!(request.errno.apply(0), 12);
            assert_eq!(request.errno.apply(37), 37);
            contents(original, 73, 0x6b);
            assert_eq!(heaps::heap_of(original.as_ptr()), heap);
            free(original);
        }
        let consumed = heaps::heap_reallocf(empty, originals[10].as_ptr(), 16 * 1024 * 1024);
        assert!(consumed.value.0.is_none());
        assert_eq!(consumed.value.1, api::FreeOutcome::Freed);
        assert_eq!(consumed.errno.apply(0), 12);
        contents(sentinel, 73, 0xa5);
        assert_eq!(heaps::heap_of(sentinel.as_ptr()), heap);
        free(sentinel);
    }
    options::option_set(DISALLOW_OS_ALLOC, previous_os);
    options::option_set(DISALLOW_ARENA_ALLOC, previous_arena);
    assert!(unsafe { heaps::heap_release(empty, true) });
}
