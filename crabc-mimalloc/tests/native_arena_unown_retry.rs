// Rust half of the pinned arena unown-retry differential in
// `compat/allocator/m2_arena_unown_retry_aarch64.{c,py}`. A forked tracer
// arms one AArch64 hardware store watchpoint on the owner thread's page
// `xthread_free` word, so the owner stops before its release CAS while a
// foreign thread frees blocks onto the owned list; the tracer then disarms
// and detaches and the CAS retries. Owner exit, the generic allocation path
// and the foreign frees take the ordinary persistent-owner and pointer-first
// PageMap paths, and each observation prints the same fields as the C oracle.
#![cfg(all(target_arch = "aarch64", feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::{c_int, c_long, c_void};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeRuntimeArenaSpanTestAudit,
    ThreadAttachResult, ThreadFinishResult, finish_current_thread_native_after_user_destructors,
    native_allocate, native_allocate_aligned, native_free, native_runtime_arena_span_state_test_audit,
    native_runtime_current_local_page_test_audit, native_runtime_live_client_arena_span_test_audit,
    native_runtime_live_client_memory_kind_test_audit, native_runtime_live_client_thread_free_test_audit,
    native_runtime_main_heap_os_abandoned_empty_test_audit, prepare_native_later_thread_arena,
    source_options_api,
};

const MEDIUM: usize = 10_248;
const MEDIUM_BLOCKS: usize = 42;
const SMALL: usize = 8192;
const OS_REQUEST: usize = 7;
const OS_ALIGNMENT: usize = 32 * 1024 * 1024;
const ARENA_MEMORY_KIND: u8 = 6;
const DISALLOW_ARENA_ALLOC: c_int = 26;
const WAIT: Duration = Duration::from_secs(30);

const PTRACE_CONT: c_int = 7;
const PTRACE_DETACH: c_int = 17;
const PTRACE_GETSIGINFO: c_int = 0x4202;
const PTRACE_SETREGSET: c_int = 0x4205;
const PTRACE_SEIZE: c_int = 0x4206;
const PTRACE_INTERRUPT: c_int = 0x4207;
const NT_ARM_HW_WATCH: usize = 0x403;
const WAIT_ALL: c_int = 0x4000_0000;
const SIGTRAP: c_int = 5;
const SIGKILL: c_int = 9;
const TRAP_HWBKPT: c_int = 4;
const PR_SET_PDEATHSIG: c_int = 1;
const PR_SET_PTRACER: c_int = 0x5961_6d61;
const EINVAL: c_int = 22;
const SIGINFO_CODE_OFFSET: usize = 8;
const SIGINFO_ADDRESS_OFFSET: usize = 16;
const PROT_READ_WRITE: u32 = 3;
const MAP_SHARED_ANONYMOUS: u32 = 0x01 | 0x20;
// DBGWCR: enable, EL0 only, store accesses, all eight bytes of an aligned
// doubleword (Arm ARM D13.3.13).
const WATCH_STORE_DOUBLEWORD: u32 = 1 | (2 << 1) | (2 << 3) | (0xff << 5);

const TRACE_ARM: u32 = 1;
const TRACE_RELEASE: u32 = 2;
const TRACE_QUIT: u32 = 3;

unsafe extern "C" {
    fn fork() -> c_int;
    fn ptrace(request: c_int, ...) -> c_long;
    fn prctl(option: c_int, ...) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn sched_yield() -> c_int;
    fn _exit(status: c_int) -> !;
    fn __errno_location() -> *mut c_int;
}

#[repr(C)]
struct WatchRegister {
    address: u64,
    control: u32,
    pad: u32,
}

#[repr(C)]
struct WatchState {
    dbg_info: u32,
    pad: u32,
    registers: [WatchRegister; 1],
}

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    length: usize,
}

#[repr(C)]
struct Tracer {
    request: AtomicU32,
    done: AtomicU32,
    command: AtomicU32,
    tid: AtomicI32,
    address: AtomicUsize,
    hits: AtomicU32,
    hit_address: AtomicUsize,
    hit_code: AtomicI32,
    failure: AtomicU32,
}

fn stopped(status: c_int) -> bool {
    status & 0xff == 0x7f
}

// The tracer child runs after `fork` in a multithreaded process, so it calls
// only async-signal-safe functions and never allocates, panics or unwinds.
fn tracer_fail(tracer: &Tracer, line: u32) -> ! {
    let _ = tracer.failure.compare_exchange(0, line, Ordering::AcqRel, Ordering::Acquire);
    // SAFETY: terminates the forked tracer without running parent-owned
    // destructors.
    unsafe { _exit(1) }
}

fn set_watch(tid: c_int, address: usize, control: u32) -> bool {
    let mut state = WatchState {
        dbg_info: 0,
        pad: 0,
        registers: [WatchRegister { address: address as u64, control, pad: 0 }],
    };
    let mut vector = IoVec { base: (&raw mut state).cast(), length: size_of::<WatchState>() };
    // SAFETY: `tid` is this tracer's ptrace-stopped tracee and both buffers
    // are live, initialized `user_hwdebug_state` and iovec images.
    unsafe { ptrace(PTRACE_SETREGSET, tid, NT_ARM_HW_WATCH, &raw mut vector) == 0 }
}

fn tracer_arm(tracer: &Tracer, tid: c_int, address: usize) {
    // SAFETY: plain ptrace requests on the parent's thread; the child holds
    // no Rust state across them.
    if unsafe { ptrace(PTRACE_SEIZE, tid, 0usize, 0usize) } != 0
        || unsafe { ptrace(PTRACE_INTERRUPT, tid, 0usize, 0usize) } != 0
    {
        tracer_fail(tracer, line!());
    }
    let mut status = 0;
    // SAFETY: waits for this tracer's own tracee.
    if unsafe { waitpid(tid, &raw mut status, WAIT_ALL) } != tid || !stopped(status) {
        tracer_fail(tracer, line!());
    }
    let pending = if status >> 16 == 0 { (status >> 8) & 0xff } else { 0 };
    if !set_watch(tid, address, WATCH_STORE_DOUBLEWORD)
        // SAFETY: resumes the stopped tracee with its pending signal.
        || unsafe { ptrace(PTRACE_CONT, tid, 0usize, pending as usize) } != 0
    {
        tracer_fail(tracer, line!());
    }
}

fn tracer_await_trap(tracer: &Tracer, tid: c_int) {
    loop {
        let mut status = 0;
        // SAFETY: waits for this tracer's own tracee.
        if unsafe { waitpid(tid, &raw mut status, WAIT_ALL) } != tid || !stopped(status) {
            tracer_fail(tracer, line!());
        }
        let mut signal = (status >> 8) & 0xff;
        if status >> 16 != 0 {
            signal = 0;
        } else if signal == SIGTRAP {
            let mut info = [0u8; 128];
            // SAFETY: the stopped tracee's siginfo fits the 128-byte buffer.
            if unsafe { ptrace(PTRACE_GETSIGINFO, tid, 0usize, info.as_mut_ptr()) } != 0 {
                tracer_fail(tracer, line!());
            }
            let code = c_int::from_ne_bytes(info[SIGINFO_CODE_OFFSET..SIGINFO_CODE_OFFSET + 4]
                .try_into().unwrap_or([0; 4]));
            if code == TRAP_HWBKPT {
                let address = usize::from_ne_bytes(info[SIGINFO_ADDRESS_OFFSET..SIGINFO_ADDRESS_OFFSET + 8]
                    .try_into().unwrap_or([0; 8]));
                tracer.hit_address.store(address, Ordering::Release);
                tracer.hit_code.store(code, Ordering::Release);
                tracer.hits.fetch_add(1, Ordering::AcqRel);
                return;
            }
        }
        // SAFETY: resumes the stopped tracee, delivering any foreign signal.
        if unsafe { ptrace(PTRACE_CONT, tid, 0usize, signal as usize) } != 0 {
            tracer_fail(tracer, line!());
        }
    }
}

fn tracer_release(tracer: &Tracer, tid: c_int) {
    // SAFETY: detaches the watchpoint-stopped tracee without a signal.
    if !set_watch(tid, 0, 0) || unsafe { ptrace(PTRACE_DETACH, tid, 0usize, 0usize) } != 0 {
        tracer_fail(tracer, line!());
    }
}

fn tracer_main(tracer: &Tracer) -> ! {
    // SAFETY: asks the kernel to kill this child if the test process dies.
    if unsafe { prctl(PR_SET_PDEATHSIG, SIGKILL as usize, 0usize, 0usize, 0usize) } != 0 {
        tracer_fail(tracer, line!());
    }
    let mut seen = 0;
    loop {
        while tracer.request.load(Ordering::Acquire) == seen {
            // SAFETY: async-signal-safe scheduler yield.
            unsafe { sched_yield() };
        }
        seen = tracer.request.load(Ordering::Acquire);
        let tid = tracer.tid.load(Ordering::Acquire);
        match tracer.command.load(Ordering::Acquire) {
            // SAFETY: ends the forked tracer without parent-owned destructors.
            TRACE_QUIT => unsafe { _exit(0) },
            TRACE_ARM => {
                tracer_arm(tracer, tid, tracer.address.load(Ordering::Acquire));
                tracer.done.store(seen, Ordering::Release);
                tracer_await_trap(tracer, tid);
            }
            TRACE_RELEASE => {
                tracer_release(tracer, tid);
                tracer.done.store(seen, Ordering::Release);
            }
            _ => tracer_fail(tracer, line!()),
        }
    }
}

struct TracerProcess {
    shared: &'static Tracer,
    pid: c_int,
    requests: u32,
}

impl TracerProcess {
    fn start() -> Self {
        // SAFETY: a fresh shared anonymous mapping; zero bytes are a valid
        // `Tracer` and both processes access it only through its atomics.
        let mapping = unsafe {
            crabc_core::mm::mmap_raw(core::ptr::null_mut(), size_of::<Tracer>(), PROT_READ_WRITE,
                MAP_SHARED_ANONYMOUS, -1, 0)
        }.expect("the tracer state maps shared");
        // SAFETY: the mapping is page-aligned, zeroed and never unmapped.
        let shared = unsafe { &*mapping.cast::<Tracer>() };
        // SAFETY: the child continues only in `tracer_main`.
        let pid = unsafe { fork() };
        assert!(pid >= 0, "the tracer forks");
        if pid == 0 {
            tracer_main(shared);
        }
        // Yama restricts PTRACE_SEIZE of a parent's thread; without Yama
        // the request is EINVAL.
        // SAFETY: names the forked child as this process's permitted tracer.
        let named = unsafe { prctl(PR_SET_PTRACER, pid as usize, 0usize, 0usize, 0usize) } == 0
            // SAFETY: musl returns the calling thread's live errno slot.
            || unsafe { *__errno_location() } == EINVAL;
        assert!(named, "the tracer is a permitted ptracer");
        Self { shared, pid, requests: 0 }
    }

    fn post(&mut self, command: u32) {
        self.shared.command.store(command, Ordering::Release);
        self.requests += 1;
        self.shared.request.store(self.requests, Ordering::Release);
    }

    fn command(&mut self, command: u32) {
        self.post(command);
        let deadline = Instant::now() + WAIT;
        while self.shared.done.load(Ordering::Acquire) != self.requests {
            assert_eq!(self.shared.failure.load(Ordering::Acquire), 0, "the tracer failed");
            assert!(Instant::now() < deadline, "the tracer completes its command");
            std::thread::yield_now();
        }
    }

    fn arm(&mut self, tid: i32, address: usize) {
        self.shared.hits.store(0, Ordering::Release);
        self.shared.hit_address.store(0, Ordering::Release);
        self.shared.hit_code.store(0, Ordering::Release);
        self.shared.tid.store(tid, Ordering::Release);
        self.shared.address.store(address, Ordering::Release);
        self.command(TRACE_ARM);
    }

    fn await_hit(&self) -> usize {
        let deadline = Instant::now() + WAIT;
        while self.shared.hits.load(Ordering::Acquire) == 0 {
            assert_eq!(self.shared.failure.load(Ordering::Acquire), 0, "the tracer failed");
            assert!(Instant::now() < deadline, "the owner reaches its release CAS");
            std::thread::yield_now();
        }
        self.shared.hit_address.load(Ordering::Acquire)
    }

    fn stop(mut self) {
        self.post(TRACE_QUIT);
        let mut status = 0;
        // SAFETY: reaps this process's own forked tracer.
        assert_eq!(unsafe { waitpid(self.pid, &raw mut status, 0) }, self.pid);
        assert_eq!(status, 0, "the tracer exits cleanly");
        assert_eq!(self.shared.failure.load(Ordering::Acquire), 0, "the tracer failed");
    }
}

fn allocate(request: usize, alignment: usize) -> NonNull<u8> {
    let result = if alignment == 0 {
        native_allocate(request, false)
    } else {
        native_allocate_aligned(request, alignment, false)
    };
    match result {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the attached worker allocates a {request}-byte client"),
    }
}

fn free(block: NonNull<u8>) {
    // SAFETY: every caller passes one exact live client exactly once.
    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
}

fn attach() {
    assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
}

fn finish() {
    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
}

fn emit(name: &str, field: &str, value: i64) {
    println!("m2.arena_unown_retry.{name}.{field}={value}");
}

fn emit_at(name: &str, stage: &str, field: &str, value: i64) {
    println!("m2.arena_unown_retry.{name}.{stage}.{field}={value}");
}

fn emit_span(name: &str, stage: &str, span: NativeRuntimeArenaSpanTestAudit) {
    // SAFETY: the owner is stopped, waiting or joined and the freer is idle,
    // so no page that could share this span is being claimed or released.
    let state = unsafe { native_runtime_arena_span_state_test_audit(span) }
        .expect("the published arena span remains auditable");
    emit_at(name, stage, "page", state.page_record_set as i64);
    emit_at(name, stage, "abandoned", state.abandoned_record_set as i64);
    emit_at(name, stage, "free", state.free_slices as i64);
    emit_at(name, stage, "committed", state.committed_slices as i64);
    emit_at(name, stage, "purge", state.purge_slices as i64);
}

fn os_listed() -> i64 {
    let empty = native_runtime_main_heap_os_abandoned_empty_test_audit()
        .expect("the active process main Heap is auditable");
    i64::from(!empty)
}

fn emit_head(name: &str, stage: &str, head: usize) {
    // SAFETY: a live client keeps its page metadata mapped, and the source
    // head is an atomic word that every thread accesses atomically.
    let word = unsafe { (*(head as *const AtomicUsize)).load(Ordering::Relaxed) };
    emit_at(name, stage, "owned", (word & 1) as i64);
    emit_at(name, stage, "pending", i64::from(word & !1 != 0));
}

fn thread_free(block: NonNull<u8>) -> usize {
    // SAFETY: the client is live and its owner is quiescent.
    unsafe { native_runtime_live_client_thread_free_test_audit(block) }.expect("a live client names its page head")
}

struct Freer {
    jobs: Sender<Option<usize>>,
    done: Receiver<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Freer {
    fn start() -> Self {
        let (jobs, job_receiver) = channel::<Option<usize>>();
        let (done_sender, done) = channel();
        let thread = std::thread::spawn(move || {
            attach();
            let own = allocate(MEDIUM, 0);
            done_sender.send(()).expect("the main thread awaits the freer");
            while let Some(address) = job_receiver.recv().expect("the main thread posts jobs") {
                free(NonNull::new(address as *mut u8).expect("a client"));
                done_sender.send(()).expect("the main thread awaits the job");
            }
            free(own);
            finish();
        });
        done.recv_timeout(WAIT).expect("the freer starts");
        Self { jobs, done, thread }
    }

    fn free(&self, block: NonNull<u8>) {
        self.jobs.send(Some(block.as_ptr() as usize)).expect("the freer accepts a job");
        self.done.recv_timeout(WAIT).expect("the foreign free returns");
    }

    fn stop(self) {
        self.jobs.send(None).expect("the freer accepts its stop");
        self.thread.join().expect("the freer completes");
    }
}

#[derive(Clone, Copy)]
struct OwnerPlan {
    size: usize,
    alignment: usize,
    count: Option<usize>,
    allocate_last_on_step: bool,
}

struct Owner {
    tid: i32,
    blocks: Vec<NonNull<u8>>,
    steps: Sender<()>,
    reports: Receiver<Vec<usize>>,
    thread: std::thread::JoinHandle<()>,
}

impl Owner {
    fn start(plan: OwnerPlan) -> Self {
        let (steps, step_receiver) = channel();
        let (report_sender, reports) = channel::<Vec<usize>>();
        let thread = std::thread::spawn(move || {
            attach();
            let first = allocate(plan.size, plan.alignment);
            let count = plan.count.unwrap_or_else(|| {
                // SAFETY: the client is live and owned by this thread.
                usize::from(unsafe { native_runtime_current_local_page_test_audit(first) }
                    .expect("the owner holds its page").reserved)
            });
            let head = thread_free(first);
            let allocate_same = || {
                let block = allocate(plan.size, plan.alignment);
                assert_eq!(thread_free(block), head, "every client shares the owner's page");
                block
            };
            let first_step = if plan.allocate_last_on_step { count - 1 } else { count };
            let mut blocks = vec![first];
            blocks.extend((1..first_step).map(|_| allocate_same()));
            let mut report = vec![crabc_core::thread::gettid() as usize];
            report.extend(blocks.iter().map(|block| block.as_ptr() as usize));
            report_sender.send(report).expect("the main thread awaits the owner's clients");
            step_receiver.recv().expect("the main thread posts the first step");
            if plan.allocate_last_on_step {
                let last = allocate_same();
                report_sender.send(vec![last.as_ptr() as usize]).expect("the main thread awaits the last client");
                step_receiver.recv().expect("the main thread posts the exit");
            }
            finish();
            report_sender.send(Vec::new()).expect("the main thread awaits the exit");
        });
        let report = reports.recv_timeout(WAIT).expect("the owner allocates");
        let tid = report[0] as i32;
        let blocks = report[1..].iter().map(|&address| NonNull::new(address as *mut u8).expect("a client")).collect();
        Self { tid, blocks, steps, reports, thread }
    }

    fn step(&self) {
        self.steps.send(()).expect("the owner accepts its step");
    }

    fn await_last(&mut self) {
        let last = self.reports.recv_timeout(WAIT).expect("the owner allocates its last client");
        self.blocks.push(NonNull::new(last[0] as *mut u8).expect("a client"));
    }

    fn finish(self) {
        let exit = self.reports.recv_timeout(WAIT).expect("the owner exits");
        assert!(exit.is_empty());
        self.thread.join().expect("the owner completes");
    }
}

fn pause_at_release(tracer: &mut TracerProcess, name: &str, owner: &Owner, count: usize) -> usize {
    // SAFETY: the client is live and its owner is waiting.
    let kind = unsafe { native_runtime_live_client_memory_kind_test_audit(owner.blocks[0]) }
        .expect("a live client has a memory kind");
    let head = thread_free(owner.blocks[0]);
    emit(name, "arena", i64::from(kind == ARENA_MEMORY_KIND));
    emit(name, "blocks", count as i64);
    tracer.arm(owner.tid, head);
    owner.step();
    emit(name, "pause_head", i64::from(tracer.await_hit() == head));
    emit(name, "pause_trap", i64::from(tracer.shared.hit_code.load(Ordering::Acquire) == TRAP_HWBKPT));
    emit_head(name, "pause", head);
    head
}

fn release_owner(tracer: &mut TracerProcess, name: &str, head: usize) {
    emit_head(name, "pushed", head);
    tracer.command(TRACE_RELEASE);
    emit(name, "hits", i64::from(tracer.shared.hits.load(Ordering::Acquire)));
}

fn span_of(block: NonNull<u8>) -> NativeRuntimeArenaSpanTestAudit {
    // SAFETY: the client is live and its owner is waiting.
    unsafe { native_runtime_live_client_arena_span_test_audit(block) }.expect("an arena client names its span")
}

fn full_all_free(tracer: &mut TracerProcess, freer: &Freer) {
    let owner = Owner::start(OwnerPlan { size: SMALL, alignment: 0, count: None, allocate_last_on_step: false });
    let blocks = owner.blocks.clone();
    let span = span_of(blocks[0]);
    let head = pause_at_release(tracer, "full", &owner, blocks.len());
    emit_span("full", "pause", span);
    for &block in &blocks {
        freer.free(block);
    }
    release_owner(tracer, "full", head);
    owner.finish();
    emit_span("full", "exit", span);
}

fn full_live(tracer: &mut TracerProcess, freer: &Freer) {
    let mut owner = Owner::start(OwnerPlan {
        size: MEDIUM, alignment: 0, count: Some(MEDIUM_BLOCKS), allocate_last_on_step: true,
    });
    let span = span_of(owner.blocks[0]);
    let head = pause_at_release(tracer, "full_live", &owner, MEDIUM_BLOCKS);
    emit_span("full_live", "pause", span);
    freer.free(owner.blocks[0]);
    release_owner(tracer, "full_live", head);
    owner.await_last();
    emit_span("full_live", "exit", span);
    emit_head("full_live", "exit", head);
    owner.step();
    let blocks = owner.blocks.clone();
    owner.finish();
    for &block in &blocks[1..] {
        freer.free(block);
    }
    emit_span("full_live", "last", span);
}

fn os_scenario(tracer: &mut TracerProcess, freer: &Freer, name: &str, plan: OwnerPlan, frees: usize) {
    let owner = Owner::start(plan);
    let blocks = owner.blocks.clone();
    let count = blocks.len();
    let head = pause_at_release(tracer, name, &owner, count);
    emit_at(name, "pause", "listed", os_listed());
    for &block in blocks.iter().rev().take(frees) {
        freer.free(block);
    }
    release_owner(tracer, name, head);
    owner.finish();
    emit_at(name, "exit", "listed", os_listed());
    if frees < count {
        emit_head(name, "exit", head);
        for &block in blocks.iter().rev().skip(frees) {
            freer.free(block);
        }
        emit_at(name, "last", "listed", os_listed());
    }
}

#[test]
fn unown_retry_after_a_remote_free_matches_the_pinned_source() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ");
    assert!(native_runtime_test_support::initialize(page_size));
    assert!(prepare_native_later_thread_arena());
    let mut tracer = TracerProcess::start();
    let freer = Freer::start();
    full_all_free(&mut tracer, &freer);
    full_live(&mut tracer, &freer);
    os_scenario(&mut tracer, &freer, "os_singleton",
        OwnerPlan { size: OS_REQUEST, alignment: OS_ALIGNMENT, count: Some(1), allocate_last_on_step: false }, 1);
    source_options_api::option_set(DISALLOW_ARENA_ALLOC, 1);
    os_scenario(&mut tracer, &freer, "os",
        OwnerPlan { size: MEDIUM, alignment: 0, count: Some(1), allocate_last_on_step: false }, 1);
    os_scenario(&mut tracer, &freer, "os_live",
        OwnerPlan { size: MEDIUM, alignment: 0, count: Some(2), allocate_last_on_step: false }, 1);
    source_options_api::option_set(DISALLOW_ARENA_ALLOC, 0);
    freer.stop();
    tracer.stop();
}
