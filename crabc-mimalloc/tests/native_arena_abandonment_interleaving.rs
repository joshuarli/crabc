// Rust half of the pinned arena-abandonment interleaving differential in
// `compat/allocator/m2_arena_abandonment_interleaving_x86_64.{c,py}`. Each
// scenario pauses one thread at a source memory access by revoking that
// access to one OS page; the SIGSEGV handler waits until the main thread has
// let another thread act and restored the page, and the access retries. The
// owner exit, foreign frees and arena reader all take the ordinary
// persistent-owner and pointer-first PageMap paths, and each observation
// prints the same fields as the C oracle.
#![cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{c_int, c_void};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeRuntimeAbandonmentWordsTestAudit,
    NativeRuntimeArenaSpanTestAudit, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    native_runtime_abandonment_words_test_audit, native_runtime_arena_span_state_test_audit,
    native_runtime_current_local_page_test_audit, native_runtime_live_client_arena_span_test_audit,
    native_runtime_live_client_page_test_audit, native_runtime_main_heap_abandoned_count_test_audit,
    native_runtime_unabandon_busy_wait_test_audit, prepare_native_later_thread_arena, source_options_api,
};

const REQUEST: usize = 10_248;
const WAIT: Duration = Duration::from_secs(30);
const ROLE_OWNER: usize = 1;
const ROLE_FREER: usize = 2;
const ROLE_READER: usize = 3;
const MAX_PAUSES: usize = 2;
const SIGSEGV: c_int = 11;
const SA_SIGINFO: c_int = 4;
const PROT_READ: u32 = 1;
const PROT_READ_WRITE: u32 = 3;
const SIGINFO_ADDRESS_OFFSET: usize = 16;
const PAGE_RECLAIM_ON_FREE: c_int = 35;

#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: c_int,
    restorer: usize,
}

unsafe extern "C" {
    fn sigaction(signal: c_int, action: *const SigAction, previous: *mut SigAction) -> c_int;
    fn __errno_location() -> *mut c_int;
}

struct Pause {
    role: AtomicUsize,
    address: AtomicUsize,
    released: AtomicBool,
}

static OS_PAGE: AtomicUsize = AtomicUsize::new(0);
static ROLE_TIDS: [AtomicI32; 4] = [const { AtomicI32::new(0) }; 4];
static ARMED: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static PAUSES: [Pause; MAX_PAUSES] = [const {
    Pause { role: AtomicUsize::new(0), address: AtomicUsize::new(0), released: AtomicBool::new(false) }
}; MAX_PAUSES];
static PAUSE_COUNT: AtomicUsize = AtomicUsize::new(0);
static mut PREVIOUS: SigAction = SigAction { handler: 0, mask: [0; 16], flags: 0, restorer: 0 };

fn current_role() -> usize {
    let tid = crabc_core::thread::gettid();
    (ROLE_OWNER..=ROLE_READER).find(|&role| ROLE_TIDS[role].load(Ordering::Acquire) == tid).unwrap_or(0)
}

extern "C" fn on_fault(_signal: c_int, info: *mut c_void, _context: *mut c_void) {
    // SAFETY: musl returns the faulting thread's live errno slot.
    let errno = unsafe { __errno_location() };
    // SAFETY: that slot stays valid for the whole handler.
    let saved_errno = unsafe { errno.read() };
    let field = info.cast::<u8>().wrapping_add(SIGINFO_ADDRESS_OFFSET).cast::<usize>();
    // SAFETY: the kernel passes a valid `siginfo_t` for an SA_SIGINFO
    // SIGSEGV; `si_addr` follows its three leading ints and padding.
    let address = unsafe { field.read() };
    pause_at(address);
    // SAFETY: as above; the handler restores the interrupted code's errno.
    unsafe { errno.write(saved_errno) };
}

fn pause_at(address: usize) {
    let base = address & !(OS_PAGE.load(Ordering::Relaxed) - 1);
    let role = current_role();
    let armed = ARMED.iter().any(|page| page.load(Ordering::Acquire) == base);
    let index = if role != 0 && armed { PAUSE_COUNT.fetch_add(1, Ordering::AcqRel) } else { MAX_PAUSES };
    if index >= MAX_PAUSES {
        // SAFETY: restores the action this test replaced; the faulting access
        // then retries under it.
        unsafe { sigaction(SIGSEGV, &raw const PREVIOUS, core::ptr::null_mut()) };
        return;
    }
    PAUSES[index].address.store(address, Ordering::Relaxed);
    PAUSES[index].role.store(role, Ordering::Release);
    while !PAUSES[index].released.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
}

fn install_fault_handler() {
    let action = SigAction { handler: on_fault as *const () as usize, mask: [0; 16], flags: SA_SIGINFO, restorer: 0 };
    // SAFETY: `on_fault` has the SA_SIGINFO handler ABI, touches only atomics
    // and the saved action, and stays installed for the test process.
    assert_eq!(unsafe { sigaction(SIGSEGV, &action, &raw mut PREVIOUS) }, 0);
}

fn register_role(role: usize) {
    ROLE_TIDS[role].store(crabc_core::thread::gettid(), Ordering::Release);
}

fn reset_pauses() {
    for pause in &PAUSES {
        pause.role.store(0, Ordering::Relaxed);
        pause.address.store(0, Ordering::Relaxed);
        pause.released.store(false, Ordering::Relaxed);
    }
    PAUSE_COUNT.store(0, Ordering::Release);
}

fn await_pause(index: usize, role: usize) -> usize {
    let deadline = Instant::now() + WAIT;
    while PAUSES[index].role.load(Ordering::Acquire) == 0 {
        assert!(Instant::now() < deadline, "pause {index} is reached");
        std::thread::yield_now();
    }
    assert_eq!(PAUSES[index].role.load(Ordering::Acquire), role, "pause {index} names its source role");
    PAUSES[index].address.load(Ordering::Relaxed)
}

fn release_pause(index: usize) {
    PAUSES[index].released.store(true, Ordering::Release);
}

fn page_of(address: usize) -> usize {
    address & !(OS_PAGE.load(Ordering::Relaxed) - 1)
}

fn protect(address: usize, protection: u32) {
    // SAFETY: the page is a mapped, committed allocator metadata page. Only
    // the paused source access and this test's own observations touch it
    // while access is revoked, and every scenario restores read-write access.
    unsafe { crabc_core::mm::mprotect_raw(page_of(address) as *mut u8, OS_PAGE.load(Ordering::Relaxed), protection) }
        .expect("the allocator metadata page changes protection");
}

fn restrict_page(slot: usize, address: usize, protection: u32) {
    ARMED[slot].store(page_of(address), Ordering::Release);
    protect(address, protection);
}

fn restore_page(slot: usize, address: usize) {
    protect(address, PROT_READ_WRITE);
    ARMED[slot].store(0, Ordering::Release);
}

fn allocate(request: usize) -> NonNull<u8> {
    match native_allocate_aligned(request, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the attached worker allocates a {request}-byte client"),
    }
}

fn free(block: NonNull<u8>) {
    // SAFETY: every caller passes one exact live client exactly once.
    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
}

fn emit(name: &str, field: &str, value: i64) {
    println!("m2.arena_interleave.{name}.{field}={value}");
}

fn emit_span(name: &str, span: NativeRuntimeArenaSpanTestAudit) {
    // SAFETY: every participating thread is paused, joined or idle, and no
    // page that could share this span is being claimed or released.
    let state = unsafe { native_runtime_arena_span_state_test_audit(span) }
        .expect("the published arena span remains auditable");
    emit(name, "page", state.page_record_set as i64);
    emit(name, "abandoned", state.abandoned_record_set as i64);
    emit(name, "free", state.free_slices as i64);
    emit(name, "committed", state.committed_slices as i64);
    emit(name, "purge", state.purge_slices as i64);
}

fn abandoned_record_set(span: NativeRuntimeArenaSpanTestAudit) -> i64 {
    // SAFETY: the participating threads are paused at protected accesses;
    // the arena bitmaps this copy reads are readable.
    let state = unsafe { native_runtime_arena_span_state_test_audit(span) }
        .expect("the published arena span remains auditable");
    state.abandoned_record_set as i64
}

fn emit_layout(name: &str, words: NativeRuntimeAbandonmentWordsTestAudit) {
    let word = page_of(words.abandoned_word);
    emit(name, "distinct_pages", i64::from(word != page_of(words.thread_free)
        && word != page_of(words.abandoned_bitmap_slot) && word != page_of(words.arena)));
}

fn attach() {
    assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
}

fn finish() {
    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
}

enum Job {
    Free(usize),
    Owns(usize),
}

struct Freer {
    jobs: Sender<Option<Job>>,
    done: Receiver<i64>,
    thread: std::thread::JoinHandle<()>,
}

impl Freer {
    fn start() -> Self {
        let (jobs, job_receiver) = channel::<Option<Job>>();
        let (done_sender, done) = channel();
        let thread = std::thread::spawn(move || {
            register_role(ROLE_FREER);
            attach();
            let own = allocate(REQUEST);
            done_sender.send(0).expect("the main thread awaits the freer");
            while let Some(job) = job_receiver.recv().expect("the main thread posts jobs") {
                let result = match job {
                    Job::Free(address) => {
                        free(NonNull::new(address as *mut u8).expect("a client"));
                        0
                    }
                    Job::Owns(address) => {
                        let block = NonNull::new(address as *mut u8).expect("a client");
                        // SAFETY: the client is live and this thread is its
                        // only allocator participant.
                        i64::from(unsafe { native_runtime_current_local_page_test_audit(block) }.is_ok())
                    }
                };
                done_sender.send(result).expect("the main thread awaits the job");
            }
            free(own);
            finish();
        });
        done.recv_timeout(WAIT).expect("the freer starts");
        Self { jobs, done, thread }
    }

    fn post(&self, block: NonNull<u8>) {
        self.jobs.send(Some(Job::Free(block.as_ptr() as usize))).expect("the freer accepts a job");
    }

    fn owns(&self, block: NonNull<u8>) -> i64 {
        self.jobs.send(Some(Job::Owns(block.as_ptr() as usize))).expect("the freer accepts a job");
        self.done.recv_timeout(WAIT).expect("the ownership check returns")
    }

    fn await_free(&self) {
        self.done.recv_timeout(WAIT).expect("the posted free returns");
    }

    fn stop(self) {
        self.jobs.send(None).expect("the freer accepts its stop");
        self.thread.join().expect("the freer completes");
    }
}

struct Owner {
    blocks: Vec<NonNull<u8>>,
    exit: Sender<()>,
    exited: Receiver<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Owner {
    fn start(count: usize) -> Self {
        let (blocks_sender, blocks) = channel::<Vec<usize>>();
        let (exit, exit_receiver) = channel();
        let (exited_sender, exited) = channel();
        let thread = std::thread::spawn(move || {
            register_role(ROLE_OWNER);
            attach();
            let blocks: Vec<NonNull<u8>> = (0..count).map(|_| allocate(REQUEST)).collect();
            for block in &blocks[1..] {
                // SAFETY: both clients are live and this owner is quiescent.
                let same = unsafe { (native_runtime_live_client_page_test_audit(blocks[0]),
                    native_runtime_live_client_page_test_audit(*block)) };
                assert_eq!(same.0.expect("a live page").page_address(), same.1.expect("a live page").page_address());
            }
            blocks_sender.send(blocks.iter().map(|block| block.as_ptr() as usize).collect())
                .expect("the main thread awaits the owner's clients");
            exit_receiver.recv().expect("the main thread posts the exit");
            finish();
            exited_sender.send(()).expect("the main thread awaits the exit");
        });
        let blocks = blocks.recv_timeout(WAIT).expect("the owner allocates")
            .into_iter().map(|address| NonNull::new(address as *mut u8).expect("a client")).collect();
        Self { blocks, exit, exited, thread }
    }

    fn post_exit(&self) {
        self.exit.send(()).expect("the owner accepts its exit");
    }

    fn finish(self) {
        self.exited.recv_timeout(WAIT).expect("the owner exits");
        self.thread.join().expect("the owner completes");
        ROLE_TIDS[ROLE_OWNER].store(0, Ordering::Release);
    }
}

fn audits(block: NonNull<u8>) -> (NativeRuntimeArenaSpanTestAudit, NativeRuntimeAbandonmentWordsTestAudit) {
    // SAFETY: the client is live, its owner is waiting and no other thread
    // is entering the allocator.
    unsafe {
        (native_runtime_live_client_arena_span_test_audit(block).expect("a medium client names an arena span"),
         native_runtime_abandonment_words_test_audit(block).expect("a medium client names its words"))
    }
}

fn unown_first(freer: &Freer) {
    let owner = Owner::start(1);
    let (span, words) = audits(owner.blocks[0]);
    emit_layout("first", words);
    reset_pauses();
    restrict_page(0, words.abandoned_word, PROT_READ);
    owner.post_exit();
    emit("first", "exit_pause_word", i64::from(await_pause(0, ROLE_OWNER) == words.abandoned_word));
    freer.post(owner.blocks[0]);
    freer.await_free();
    emit("first", "freer_returned", 1);
    restore_page(0, words.abandoned_word);
    release_pause(0);
    owner.finish();
    emit("first", "pauses", PAUSE_COUNT.load(Ordering::Acquire) as i64);
    emit_span("first.exit", span);
}

fn unown_cas(freer: &Freer, name: &str, count: usize) {
    let owner = Owner::start(count);
    let (span, words) = audits(owner.blocks[0]);
    emit_layout(name, words);
    reset_pauses();
    restrict_page(0, words.abandoned_word, PROT_READ);
    owner.post_exit();
    emit(name, "exit_pause_word", i64::from(await_pause(0, ROLE_OWNER) == words.abandoned_word));
    restrict_page(1, words.thread_free, PROT_READ);
    restore_page(0, words.abandoned_word);
    release_pause(0);
    emit(name, "unown_pause_head", i64::from(await_pause(1, ROLE_OWNER) == words.thread_free));
    emit(name, "mapped_before_free", abandoned_record_set(span));
    restore_page(1, words.thread_free);
    freer.post(owner.blocks[count - 1]);
    freer.await_free();
    emit(name, "freer_returned", 1);
    release_pause(1);
    let first = owner.blocks[0];
    owner.finish();
    emit(name, "pauses", PAUSE_COUNT.load(Ordering::Acquire) as i64);
    emit_span(&format!("{name}.exit"), span);
    if count > 1 {
        freer.post(first);
        freer.await_free();
        emit_span(&format!("{name}.last"), span);
    }
}

fn busy_waits() -> i64 {
    native_runtime_unabandon_busy_wait_test_audit().expect("the active subprocess statistics are auditable")
}

fn unabandon_wait(freer: &Freer, name: &str, count: usize) {
    let owner = Owner::start(count);
    let blocks = owner.blocks.clone();
    let (span, words) = audits(blocks[0]);
    owner.post_exit();
    owner.finish();
    emit_layout(name, words);
    emit_span(&format!("{name}.abandoned"), span);

    let (ready_sender, ready) = channel();
    let (go, go_receiver) = channel::<()>();
    let reader = std::thread::spawn(move || {
        register_role(ROLE_READER);
        attach();
        let warm = allocate(16);
        ready_sender.send(0).expect("the main thread awaits the reader");
        go_receiver.recv().expect("the main thread starts the search");
        let block = allocate(REQUEST);
        // SAFETY: the reader's own client is live and only it touches the page.
        let owned = unsafe { native_runtime_current_local_page_test_audit(block) }.is_ok();
        ready_sender.send(i64::from(owned)).expect("the main thread awaits the allocation");
        go_receiver.recv().expect("the main thread ends the reader");
        free(block);
        free(warm);
        finish();
    });
    ready.recv_timeout(WAIT).expect("the reader starts");
    let waits_before = busy_waits();
    reset_pauses();
    restrict_page(0, words.abandoned_word, PROT_READ);
    freer.post(blocks[count - 1]);
    emit(name, "freer_pause_word", i64::from(await_pause(0, ROLE_FREER) == words.abandoned_word));
    // SAFETY: the freer holds the page's owner bit and is paused before it
    // can release the page, so its initialized head word stays mapped.
    let head = unsafe { (*(words.thread_free as *const AtomicUsize)).load(Ordering::Relaxed) };
    emit(name, "freer_owns", i64::from(head & 1 == 1));
    restrict_page(1, words.thread_free, PROT_READ);
    restore_page(0, words.abandoned_word);
    go.send(()).expect("the reader accepts the search");
    emit(name, "reader_pause_head", i64::from(await_pause(1, ROLE_READER) == words.thread_free));
    emit(name, "reader_cleared", 1 - abandoned_record_set(span));
    release_pause(0);
    let deadline = Instant::now() + WAIT;
    while busy_waits() == waits_before && Instant::now() < deadline {
        std::thread::yield_now();
    }
    emit(name, "freer_waiting", busy_waits() - waits_before);
    restore_page(1, words.thread_free);
    release_pause(1);
    freer.await_free();
    let owned = ready.recv_timeout(WAIT).expect("the reader allocates");
    emit(name, "busy_waits", busy_waits() - waits_before);
    emit(name, "reader_owns", owned);
    emit(name, "pauses", PAUSE_COUNT.load(Ordering::Acquire) as i64);
    emit(&format!("{name}.freed"), "abandoned_count", native_runtime_main_heap_abandoned_count_test_audit()
        .expect("the main Heap is auditable") as i64);
    if count > 1 {
        emit(name, "freer_reclaimed", freer.owns(blocks[0]));
        emit_span(&format!("{name}.reclaimed"), span);
    }
    go.send(()).expect("the reader accepts its end");
    reader.join().expect("the reader completes");
    if count > 1 {
        freer.post(blocks[0]);
        freer.await_free();
    } else {
        emit_span(&format!("{name}.last"), span);
    }
}

#[test]
fn abandonment_interleavings_match_the_pinned_source() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ");
    OS_PAGE.store(page_size, Ordering::Relaxed);
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    install_fault_handler();
    let freer = Freer::start();
    unown_first(&freer);
    unown_cas(&freer, "cas", 1);
    unown_cas(&freer, "cas_live", 2);
    unabandon_wait(&freer, "wait", 1);
    source_options_api::option_set(PAGE_RECLAIM_ON_FREE, 1);
    unabandon_wait(&freer, "reclaim", 2);
    source_options_api::option_set(PAGE_RECLAIM_ON_FREE, 0);
    freer.stop();
}
