#![cfg(all(target_arch = "x86_64", feature = "test-adapter"))]

use core::ffi::{c_char, c_void};
use core::ptr::NonNull;
use std::ffi::CStr;
use crabc_mimalloc::TestAllocatorContext;
#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;
use crabc_mimalloc::__crabc_runtime::{source_api, source_heap_api, source_options_api};

#[derive(Default)]
struct Capture {
    bytes: Vec<u8>, fragments: Vec<usize>,
    context: Option<NonNull<TestAllocatorContext>>, reentered: bool,
}
unsafe extern "C" fn capture(message: *const c_char, argument: *mut c_void) {
    // SAFETY: registration retains this exact capture and C fragment through
    // serialized delivery; no context reference is retained by the callback.
    let capture = unsafe { &mut *argument.cast::<Capture>() };
    let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
    capture.bytes.extend_from_slice(bytes);
    capture.fragments.push(bytes.len());
    if let Some(context) = capture.context.filter(|_| !capture.reentered) {
        capture.reentered = true;
        // SAFETY: the renderer retains pointee owners, never a context borrow.
        // This callback alone owns allocation transitions on the creating thread.
        let block = unsafe { (*context.as_ptr()).alloc(33) }.unwrap();
        unsafe { (*context.as_ptr()).free(block) }.unwrap();
    }
}

#[test]
fn private_arena_diagnostics_select_independent_contexts() {
    let mut first = TestAllocatorContext::new().unwrap();
    let mut second = TestAllocatorContext::new().unwrap();
    let first_pointer = NonNull::from(&mut first);
    let second_pointer = NonNull::from(&mut second);
    let a = first.alloc(33).unwrap();
    let b = second.alloc(33).unwrap();
    let c = second.alloc(6000).unwrap();
    let mut first_output = Capture::default();
    let mut second_output = Capture::default();
    assert!(native_runtime_test_support::initialize(4096));
    assert!(crabc_mimalloc::__crabc_runtime::prepare_native_initial_thread_owner());
    let mut global_arena = core::ptr::null_mut();
    assert_eq!(unsafe { source_heap_api::reserve_os_memory_ex(
        source_heap_api::arena_min_size(), true, false, false, &mut global_arena) }.value, 0);
    assert!(!global_arena.is_null());
    let global_block = source_api::malloc(33).value.unwrap();
    let mut global_output = Capture::default();
    unsafe { source_options_api::register_output(Some(capture), (&mut global_output as *mut Capture).cast()); }
    global_output.bytes.clear();
    global_output.fragments.clear();
    // SAFETY: both contexts/captures stay live on their creating thread and
    // every registration/traversal is serialized before explicit teardown.
    unsafe {
        assert!(TestAllocatorContext::register_arena_output(first_pointer, Some(capture), (&mut first_output as *mut Capture).cast()));
        assert!(TestAllocatorContext::register_arena_output(second_pointer, Some(capture), (&mut second_output as *mut Capture).cast()));
        first_output.bytes.clear(); first_output.fragments.clear();
        second_output.bytes.clear(); second_output.fragments.clear();
        first_output.context = Some(first_pointer);
        second_output.context = Some(second_pointer);
        assert!(TestAllocatorContext::debug_show_arenas(first_pointer));
        assert!(TestAllocatorContext::debug_show_arenas(second_pointer));
    }
    let first_text = std::str::from_utf8(&first_output.bytes).unwrap();
    let second_text = std::str::from_utf8(&second_output.bytes).unwrap();
    assert!(first_text.ends_with("total pages in arenas: 1\n"), "selected private context must emit its own registered page: {first_text:?}");
    assert!(second_text.ends_with("total pages in arenas: 2\n"));
    assert!(first_text.contains("subproc: 0, numa: -1\n"));
    assert!(second_text.contains("subproc: 0, numa: -1\n"));
    assert!(!first_output.fragments.is_empty());
    assert!(first_output.reentered && second_output.reentered);
    assert!(global_output.bytes.is_empty(), "private callbacks must not reach the native global sink");
    assert_eq!(first.outstanding_allocations(), 1);
    assert_eq!(second.outstanding_allocations(), 2);
    let first_header = first_text.lines().next().unwrap().to_owned();
    let second_header = second_text.lines().next().unwrap().to_owned();
    assert_ne!(first_header, second_header);
    let first_bytes = first_output.bytes.clone();
    let second_bytes = second_output.bytes.clone();
    unsafe { source_heap_api::debug_show_arenas(); }
    let global_text = std::str::from_utf8(&global_output.bytes).unwrap();
    let global_header = global_text.lines().next().unwrap();
    let global_address = global_header.split(" at 0x").nth(1).unwrap().split(':').next().unwrap();
    assert_eq!(usize::from_str_radix(global_address, 16).unwrap(), global_arena as usize);
    assert!(!global_text.contains(&first_header) && !global_text.contains(&second_header));
    assert_eq!(first_output.bytes, first_bytes);
    assert_eq!(second_output.bytes, second_bytes);
    let raw_first = first_pointer.as_ptr() as usize;
    std::thread::spawn(move || {
        let pointer = NonNull::new(raw_first as *mut TestAllocatorContext).unwrap();
        // SAFETY: the creating thread waits and retains the context; thread
        // admission must reject before mutable owner/lifecycle projection.
        assert!(!unsafe { TestAllocatorContext::debug_show_arenas(pointer) });
        assert!(!unsafe { TestAllocatorContext::register_arena_output(pointer, None, core::ptr::null_mut()) });
    }).join().unwrap();
    assert_eq!(first_output.bytes, first_bytes);
    first_output.bytes.clear();
    assert!(unsafe { TestAllocatorContext::debug_show_arenas(first_pointer) });
    assert_eq!(first_output.bytes, first_bytes, "rejected foreign registration must retain the original callback pair");
    unsafe {
        let _ = source_api::free(global_block.as_ptr());
        source_options_api::register_output(None, core::ptr::null_mut());
    }
    unsafe { first.free(a).unwrap(); second.free(b).unwrap(); second.free(c).unwrap(); }
    first.shutdown().unwrap(); second.shutdown().unwrap();
    assert!(!unsafe { TestAllocatorContext::debug_show_arenas(first_pointer) });
    assert!(!unsafe { TestAllocatorContext::register_arena_output(first_pointer, None, core::ptr::null_mut()) });
    assert_eq!(first_output.bytes, first_bytes);
}
