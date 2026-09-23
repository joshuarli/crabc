#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, native_allocate_aligned, native_free,
    native_reallocate, native_reallocate_aligned, native_reallocate_zeroed,
    native_reallocate_aligned_zeroed, native_usable_size,
};

fn allocated(result: NativePageAllocationResult) -> core::ptr::NonNull<u8> {
    match result {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => panic!("native aligned allocation failed"),
    }
}

#[test]
fn native_aligned_reallocate_reuses_replaces_and_preserves_on_oom() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("native Linux exposes AT_PAGESZ");
    assert!(native_runtime_test_support::initialize(page_size));

    let null_zero = allocated(unsafe { native_reallocate_aligned(None, 0, 8) });
    assert_eq!(unsafe { null_zero.as_ptr().read() }, 0);
    assert_eq!(unsafe { native_free(null_zero) }, NativePageFreeResult::Freed);

    let alignment = 128;
    let original = allocated(native_allocate_aligned(33, alignment, false));
    let usable = unsafe { native_usable_size(original) }.expect("live aligned client");
    assert!(usable >= 33);
    assert_eq!(original.as_ptr().addr() & (alignment - 1), 0);
    unsafe { core::ptr::write_bytes(original.as_ptr(), 0x79, usable) };

    let half = usable - usable / 2;
    let reused = allocated(unsafe { native_reallocate_aligned(Some(original), half, alignment) });
    assert_eq!(reused, original, "pinned aligned realloc reuses at ceil-half");

    assert!(matches!(
        unsafe { native_reallocate_aligned(Some(reused), usize::MAX, alignment) },
        NativePageAllocationResult::AllocationFailed,
    ), "invalid-size failure leaves the old aligned client live");
    assert_eq!(unsafe { native_usable_size(reused) }, Some(usable));
    assert_eq!(unsafe { reused.as_ptr().read() }, 0x79);

    let replacement_size = half - 1;
    let replacement = allocated(unsafe {
        native_reallocate_aligned(Some(reused), replacement_size, alignment)
    });
    assert_ne!(replacement, reused, "below ceil-half requires replacement");
    assert_eq!(replacement.as_ptr().addr() & (alignment - 1), 0);
    for index in 0..replacement_size {
        assert_eq!(unsafe { replacement.as_ptr().add(index).read() }, 0x79);
    }
    assert_eq!(unsafe { native_free(replacement) }, NativePageFreeResult::Freed);

    let ordinary = allocated(native_allocate_aligned(49, 16, false));
    let ordinary_zero = allocated(unsafe { native_reallocate(Some(ordinary), 0) });
    assert_ne!(ordinary_zero, ordinary);
    assert_eq!(unsafe { ordinary_zero.as_ptr().read() }, 0);
    assert_eq!(unsafe { native_free(ordinary_zero) }, NativePageFreeResult::Freed);

    let zeroed = allocated(native_allocate_aligned(33, 16, false));
    let old_usable = unsafe { native_usable_size(zeroed) }.unwrap();
    unsafe { core::ptr::write_bytes(zeroed.as_ptr(), 0x5a, old_usable) };
    assert!(matches!(
        unsafe { native_reallocate_zeroed(Some(zeroed), usize::MAX) },
        NativePageAllocationResult::AllocationFailed,
    ));
    assert_eq!(unsafe { zeroed.as_ptr().read() }, 0x5a);
    let grown = allocated(unsafe { native_reallocate_zeroed(Some(zeroed), old_usable + 17) });
    let grown_usable = unsafe { native_usable_size(grown) }.unwrap();
    for index in 0..old_usable {
        assert_eq!(unsafe { grown.as_ptr().add(index).read() }, 0x5a);
    }
    for index in old_usable..grown_usable {
        assert_eq!(unsafe { grown.as_ptr().add(index).read() }, 0);
    }
    let zero_size = allocated(unsafe { native_reallocate_zeroed(Some(grown), 0) });
    let zero_size_usable = unsafe { native_usable_size(zero_size) }.unwrap();
    for index in 0..zero_size_usable {
        assert_eq!(unsafe { zero_size.as_ptr().add(index).read() }, 0);
    }
    assert_eq!(unsafe { native_free(zero_size) }, NativePageFreeResult::Freed);

    let aligned_zeroed = allocated(native_allocate_aligned(33, alignment, false));
    let aligned_old_usable = unsafe { native_usable_size(aligned_zeroed) }.unwrap();
    unsafe { core::ptr::write_bytes(aligned_zeroed.as_ptr(), 0x6b, aligned_old_usable) };
    let aligned_grown = allocated(unsafe {
        native_reallocate_aligned_zeroed(Some(aligned_zeroed), aligned_old_usable + 17, alignment)
    });
    let aligned_new_usable = unsafe { native_usable_size(aligned_grown) }.unwrap();
    assert_eq!(aligned_grown.as_ptr().addr() & (alignment - 1), 0);
    for index in 0..aligned_old_usable {
        assert_eq!(unsafe { aligned_grown.as_ptr().add(index).read() }, 0x6b);
    }
    for index in aligned_old_usable..aligned_new_usable {
        assert_eq!(unsafe { aligned_grown.as_ptr().add(index).read() }, 0);
    }
    assert_eq!(unsafe { native_free(aligned_grown) }, NativePageFreeResult::Freed);
    println!("aligned_realloc:null_zero=1,reuse=1,oom_preserved=1,replaced=1,aligned=1,copy=1");
    println!("zeroed_realloc:ordinary_oom=1,ordinary_copy=1,ordinary_tail=1,ordinary_zero=1,aligned_copy=1,aligned_tail=1");
}
