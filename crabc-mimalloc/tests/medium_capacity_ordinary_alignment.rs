#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate, native_free,
    native_usable_size, prepare_native_later_thread_arena,
};

const SAMPLES: usize = 16;
const CASES: [(usize, usize); 10] = [
    (1, 8), (8, 8), (9, 16), (15, 16), (16, 16), (17, 32),
    (24, 32), (32, 32), (10248, 12288), (65536, 65536),
];

fn page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes its page size")
}

fn observe_ordinary_alignment(owner: &str) {
    for (request, expected_usable) in CASES {
        let mut blocks = Vec::with_capacity(SAMPLES);
        let mut aligned16 = 0;
        for _ in 0..SAMPLES {
            let block = match native_allocate(request, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!("the ordinary source allocates the requested block"),
            };
            aligned16 += usize::from(block.as_ptr().addr() & 15 == 0);
            // SAFETY: this exact client remains live until the local frees below.
            let usable = unsafe { native_usable_size(block) }
                .expect("the ordinary client's usable extent is available");
            assert_eq!(usable, expected_usable);
            blocks.push(block);
        }
        std::println!(
            "trace.ordinary owner={owner} request={request} aligned16={aligned16} usable={expected_usable}"
        );
        if request >= 9 {
            assert_eq!(aligned16, SAMPLES, "ordinary blocks with a 16-byte size class meet max_align_t");
        }
        for block in blocks {
            // SAFETY: each block is this owner's exact live ordinary client.
            assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
        }
    }
}

#[test]
fn ordinary_native_medium_size_keeps_source_capacity_and_c_alignment() {
    assert!(native_runtime_test_support::initialize(page_size()));
    observe_ordinary_alignment("initial");
    assert!(prepare_native_later_thread_arena());
    let worker = std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        observe_ordinary_alignment("worker");
        finish_current_thread_native_after_user_destructors()
    });
    assert_eq!(worker.join().expect("the worker finishes"), ThreadFinishResult::Finished);
}
