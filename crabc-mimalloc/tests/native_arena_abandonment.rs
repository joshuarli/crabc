// Rust half of the pinned arena-abandonment differential in
// `compat/allocator/m2_arena_abandonment_x86_64.{c,py}`. A freeing worker
// keeps one live block in the medium bin and runs an owner worker to its exit;
// every free goes through `native_free`, and each observation prints the same
// fields as the C oracle: the arena page and abandoned-bitmap records of the
// owner's page and the free, committed and purge slice counts of its span.
#![cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ptr::NonNull;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeRuntimeArenaSpanTestAudit,
    ThreadAttachResult, ThreadFinishResult, finish_current_thread_native_after_user_destructors,
    native_allocate_aligned, native_block_size, native_free,
    native_runtime_arena_span_state_test_audit, native_runtime_current_local_page_same_test_audit,
    native_runtime_current_local_page_test_audit, native_runtime_live_client_arena_span_test_audit,
    native_runtime_live_client_memory_kind_test_audit, native_runtime_live_client_page_test_audit,
    native_runtime_main_heap_os_abandoned_empty_test_audit, prepare_native_later_thread_arena,
};

const REQUEST: usize = 10_248;
const BLOCKS: usize = 42;
const OS_REQUEST: usize = 7;
const OS_ALIGNMENT: usize = 32 * 1024 * 1024;
const ARENA_MEMORY_KIND: u8 = 6;
const NO_PAGE_ENGINE: i32 = -3;
const NOT_CURRENT_OWNER: i32 = -6;

fn allocate_aligned(request: usize, alignment: usize) -> NonNull<u8> {
    match native_allocate_aligned(request, alignment, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the attached worker allocates a {request}-byte client"),
    }
}

fn allocate() -> NonNull<u8> {
    allocate_aligned(REQUEST, 16)
}

fn free(block: NonNull<u8>) {
    // SAFETY: every caller passes one exact live client exactly once.
    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
}

fn emit(name: &str, field: &str, value: usize) {
    println!("m2.arena_abandon.{name}.{field}={value}");
}

fn emit_span(name: &str, span: NativeRuntimeArenaSpanTestAudit) {
    // SAFETY: the owner has finished and the freeing worker is the only
    // allocator client; its last free has returned before this observation.
    let state = unsafe { native_runtime_arena_span_state_test_audit(span) }
        .expect("the published arena span remains auditable");
    emit(name, "page", state.page_record_set);
    emit(name, "abandoned", state.abandoned_record_set);
    emit(name, "free", state.free_slices);
    emit(name, "committed", state.committed_slices);
    emit(name, "purge", state.purge_slices);
}

fn emit_reclaimed(name: &str, live: NonNull<u8>) {
    // SAFETY: `live` is still allocated and only this thread touches its page.
    let reclaimed = match unsafe { native_runtime_current_local_page_test_audit(live) } {
        Ok(_) => 1,
        Err(NO_PAGE_ENGINE | NOT_CURRENT_OWNER) => 0,
        Err(error) => panic!("{name}: the page audit failed with {error}"),
    };
    emit(name, "reclaimed", reclaimed);
}

fn emit_live(name: &str, span: NativeRuntimeArenaSpanTestAudit, live: NonNull<u8>) {
    emit_span(name, span);
    emit_reclaimed(name, live);
}

fn os_abandoned_listed() -> usize {
    let empty = native_runtime_main_heap_os_abandoned_empty_test_audit()
        .expect("the active process main Heap is auditable");
    usize::from(!empty)
}

fn on_worker<R: Send + 'static>(work: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let result = work();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        result
    })
    .join()
    .expect("the worker completes")
}

struct Owned {
    blocks: Vec<usize>,
    reserved: usize,
    block_size: usize,
}

fn run_owner(count: usize) -> (Vec<NonNull<u8>>, usize, usize) {
    let Owned { blocks, reserved, block_size } = on_worker(move || {
        let mut blocks: Vec<NonNull<u8>> = (1..count).map(|_| allocate()).collect();
        for block in &blocks[1..] {
            // SAFETY: both clients are live and owned by this thread.
            assert_eq!(unsafe { native_runtime_current_local_page_same_test_audit(blocks[0], *block) }, Ok(true));
        }
        // SAFETY: the first client is live and its page is still owned here;
        // the final allocation may make the page full and abandon it.
        let page = unsafe { native_runtime_current_local_page_test_audit(blocks[0]) }
            .expect("the owner holds its medium page");
        blocks.push(allocate());
        // SAFETY: this owner is the only allocator client; both clients are live.
        let same = unsafe { (native_runtime_live_client_page_test_audit(blocks[0]),
            native_runtime_live_client_page_test_audit(blocks[count - 1])) };
        assert_eq!(same.0.expect("a live page").page_address(), same.1.expect("a live page").page_address());
        // SAFETY: the first client is live.
        let block_size = unsafe { native_block_size(blocks[0]) }.expect("a live client has a block size");
        Owned { blocks: blocks.iter().map(|block| block.as_ptr() as usize).collect(), reserved: page.reserved, block_size }
    });
    let blocks = blocks.into_iter().map(|address| NonNull::new(address as *mut u8).expect("a client")).collect();
    (blocks, reserved, block_size)
}

fn span_of(block: NonNull<u8>) -> NativeRuntimeArenaSpanTestAudit {
    // SAFETY: the owner has finished and this worker performs no concurrent
    // allocator operation while it copies the live client's arena span.
    unsafe { native_runtime_live_client_arena_span_test_audit(block) }
        .expect("the abandoned medium client names an arena span")
}

fn freer() {
    let own = allocate();

    let (mapped, reserved, block_size) = run_owner(2);
    let span = span_of(mapped[0]);
    emit("mapped", "reserved", reserved);
    emit("mapped", "block_size", block_size);
    emit("mapped", "slices", span.slice_count());
    emit_live("mapped.exit", span, mapped[0]);
    free(mapped[1]);
    emit_live("mapped.first", span, mapped[0]);
    free(mapped[0]);
    emit_span("mapped.last", span);

    let (full, reserved, _) = run_owner(BLOCKS);
    assert_eq!(reserved, BLOCKS);
    let span = span_of(full[0]);
    emit_live("full.exit", span, full[0]);
    for step in 1..=7 {
        free(full[BLOCKS - step]);
        emit_live(&format!("full.free{step}"), span, full[0]);
    }
    for index in (1..BLOCKS - 7).rev() {
        free(full[index]);
    }
    emit_live("full.penultimate", span, full[0]);
    free(full[0]);
    emit_span("full.last", span);

    let os = on_worker(|| allocate_aligned(OS_REQUEST, OS_ALIGNMENT).as_ptr() as usize);
    let os = NonNull::new(os as *mut u8).expect("an OS singleton client");
    // SAFETY: the owner has finished and the client is live and quiescent.
    let os_kind = unsafe { native_runtime_live_client_memory_kind_test_audit(os) }
        .expect("the live OS singleton has a memory kind");
    emit("os", "arena", usize::from(os_kind == ARENA_MEMORY_KIND));
    emit("os.exit", "listed", os_abandoned_listed());
    emit_reclaimed("os.exit", os);
    free(os);
    emit("os.last", "listed", os_abandoned_listed());

    free(own);
}

#[test]
fn arena_abandonment_transitions_match_the_pinned_source() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ");
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    on_worker(freer);
}
