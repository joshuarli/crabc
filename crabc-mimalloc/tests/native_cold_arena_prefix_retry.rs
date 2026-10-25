#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{c_int, c_void};
use crabc_mimalloc::{source_api, source_heap_api};

unsafe extern "C" {
    fn mmap(address: *mut c_void, size: usize, protection: c_int, flags: c_int, fd: c_int, offset: isize) -> *mut c_void;
    fn mprotect(address: *mut c_void, size: usize, protection: c_int) -> c_int;
}

struct Capture {
    base: usize,
    arena_size: usize,
    armed: bool,
    metadata_calls: usize,
    metadata_bytes: usize,
    prefix_calls: usize,
    prefix_bytes: usize,
    refused_prefix: usize,
    refused_bytes: usize,
    same_prefix: bool,
}

unsafe extern "C" fn commit_memory(commit: bool, start: *mut u8, size: usize, zero: *mut bool, argument: *mut c_void) -> bool {
    let capture = unsafe { &mut *argument.cast::<Capture>() };
    assert!(commit);
    assert!(start.addr() >= capture.base && size <= capture.arena_size
        && start.addr() - capture.base <= capture.arena_size - size);
    if capture.armed && zero.is_null() {
        capture.metadata_calls += 1;
        capture.metadata_bytes = size;
    }
    if capture.armed && !zero.is_null() {
        capture.prefix_calls += 1;
        capture.prefix_bytes = size;
        if capture.prefix_calls == 1 {
            capture.refused_prefix = start.addr();
            capture.refused_bytes = size;
            return false;
        }
        capture.same_prefix = start.addr() == capture.refused_prefix;
    }
    assert_eq!(unsafe { mprotect(start.cast(), size, 3) }, 0);
    if !zero.is_null() { unsafe { zero.write(true) }; }
    true
}

#[test]
fn cold_arena_prefix_refusal_retries_in_arena() {
    assert!(native_runtime_test_support::initialize(4096));
    let arena_size = source_heap_api::arena_min_size();
    let alignment = source_heap_api::arena_min_alignment();
    let mapping = unsafe { mmap(core::ptr::null_mut(), arena_size + alignment, 0, 0x22, -1, 0) };
    assert_ne!(mapping.addr(), usize::MAX);
    let base = (mapping.addr() + alignment - 1) & !(alignment - 1);
    let capture = Box::leak(Box::new(Capture { base, arena_size, armed: false, metadata_calls: 0,
        metadata_bytes: 0, prefix_calls: 0, prefix_bytes: 0, refused_prefix: 0, refused_bytes: 0, same_prefix: false }));
    let argument = core::ptr::from_mut(capture).cast();
    let mut arena = core::ptr::null_mut();
    assert!(unsafe { source_heap_api::manage_memory(base as *mut c_void, arena_size,
        false, false, true, -1, false, Some(commit_memory), argument, &mut arena) });
    capture.armed = true;
    let block = source_api::malloc(100000).value.expect("source allocation retries the refused prefix");
    capture.armed = false;
    unsafe { block.as_ptr().write_bytes(0x5a, 100000) };
    let bytes = unsafe { core::slice::from_raw_parts(block.as_ptr(), 100000) }.iter().all(|byte| *byte == 0x5a);
    let owned = unsafe { source_api::check_owned(block.as_ptr()) && source_heap_api::heap_contains(source_heap_api::heap_main(), block.as_ptr()) };
    println!("CRABC_COLD_ARENA_PREFIX_RETRY_BEGIN");
    println!("metadata.calls={}\nmetadata.bytes={}\nprefix.calls={}\nprefix.bytes={}",
        capture.metadata_calls, capture.metadata_bytes, capture.prefix_calls, capture.prefix_bytes);
    println!("prefix.refused_bytes={}", capture.refused_bytes);
    println!("prefix.same={}\nclient.in_arena={}\nclient.owned={}\nclient.bytes={}",
        usize::from(capture.same_prefix), usize::from(block.as_ptr().addr() >= base && block.as_ptr().addr() < base + arena_size),
        usize::from(owned), usize::from(bytes));
    println!("CRABC_COLD_ARENA_PREFIX_RETRY_END");
    unsafe { source_api::free(block.as_ptr()); }
}
