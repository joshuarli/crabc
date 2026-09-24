// SPDX-License-Identifier: MIT
//
// Rust half of the M3 persistent-owner local-path differential
// (`compat/allocator/m3-local-engine-x86_64-v3.5.0.json`, component
// `persistent-owner-local-path`).
//
// One process runs one workload through the production
// `native_allocate_aligned(size, 16)`/`native_free` boundary on one persistent
// owner: the initial thread's promoted static owner, or one attached later
// thread's compiler-TLS owner. After every operation it walks that owner's
// default Theap through the audit-only
// `native_runtime_current_owner_theap_trace_test_audit` and emits the same
// normalized trace as `compat/allocator/m3_local_trace_x86_64.c` in its
// `initial`/`later` modes over the pinned C default Theap
// (`mi_malloc_aligned(size, 16)`/`mi_free`). `compat/allocator/m3_x86_64.py`
// generates the workloads and compares both producers line by line; any
// format change here must be made identically in the C driver and in
// `crabc-mimalloc/src/single_thread/local_trace.rs`.
//
// The workloads never fill a page, so the default abandoning Theap never
// reaches the M5 abandonment transition; every allocation is freed before the
// owner's ordinary source teardown.
#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, NativeTheapTraceBlock,
    NativeTheapTraceDirect, NativeTheapTraceFact, NativeTheapTracePage, ThreadAttachResult,
    ThreadFinishResult, finish_current_thread_native_after_user_destructors,
    native_allocate_aligned, native_free, native_runtime_current_owner_theap_trace_test_audit,
    prepare_native_later_thread_arena,
};

/// `initial` or `later`: selects the traced owner and marks this process as
/// one fresh trace producer.
const OWNER_ENV: &str = "CRABC_M3_OWNER_TRACE_OWNER";
/// Optional workload file (`m3-local-trace 1`, `arena_bytes=0`).
const WORKLOAD_ENV: &str = "CRABC_M3_OWNER_TRACE_WORKLOAD";
/// Path receiving the normalized trace.
const OUTPUT_ENV: &str = "CRABC_M3_OWNER_TRACE_OUTPUT";
const WORKLOAD_MAGIC: &str = "m3-local-trace 1";
const TEST_NAME: &str = "persistent_owner_local_trace";
const ALIGNMENT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Owner {
    Initial,
    Later,
}

impl Owner {
    fn parse(value: &str) -> Self {
        match value {
            "initial" => Self::Initial,
            "later" => Self::Later,
            other => panic!("unknown persistent owner {other:?}"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Later => "later",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Allocate { id: usize, size: usize },
    Free { id: usize },
}

struct Workload {
    ids: usize,
    operations: Vec<Operation>,
}

fn parse_field(token: Option<&str>, prefix: &str, line: usize) -> usize {
    let token = token.unwrap_or_else(|| panic!("workload line {line}: missing {prefix}"));
    let value = token
        .strip_prefix(prefix)
        .unwrap_or_else(|| panic!("workload line {line}: expected {prefix}, got {token}"));
    value.parse().unwrap_or_else(|_| panic!("workload line {line}: invalid {prefix}{value}"))
}

/// Parses the generator's format, rejecting any sequence that would free a
/// dead or never-allocated ID, so a malformed file cannot become undefined
/// allocator input.
fn parse_workload(text: &str) -> Workload {
    let mut lines = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'));
    let (_, magic) = lines.next().expect("workload has a header");
    assert_eq!(magic, WORKLOAD_MAGIC, "unsupported workload format");
    let (header_line, header) = lines.next().expect("workload has a geometry line");
    let mut fields = header.split_ascii_whitespace();
    let arena_bytes = parse_field(fields.next(), "arena_bytes=", header_line);
    let ids = parse_field(fields.next(), "ids=", header_line);
    assert!(fields.next().is_none(), "workload geometry line has extra fields");
    assert_eq!(arena_bytes, 0, "the persistent-owner profile uses the runtime's own arena");

    let mut live = vec![false; ids];
    let mut operations = Vec::new();
    for (line, text) in lines {
        let mut fields = text.split_ascii_whitespace();
        let operation = match fields.next() {
            Some("a") => {
                let id = parse_field(fields.next(), "", line);
                let size = parse_field(fields.next(), "", line);
                assert!(id < ids && !live[id], "workload line {line}: allocation of live id");
                assert!(size > 0, "workload line {line}: zero-size request");
                live[id] = true;
                Operation::Allocate { id, size }
            }
            Some("f") => {
                let id = parse_field(fields.next(), "", line);
                assert!(id < ids && live[id], "workload line {line}: free of dead id");
                live[id] = false;
                Operation::Free { id }
            }
            other => panic!("workload line {line}: unknown operation {other:?}"),
        };
        assert!(fields.next().is_none(), "workload line {line}: extra fields");
        operations.push(operation);
    }
    assert!(live.iter().all(|live| !live), "the workload frees every allocation");
    Workload { ids, operations }
}

/// A small non-filling built-in workload: direct-small, small, medium, and
/// large blocks, local frees and reuse, and retirement of every page.
fn builtin_workload() -> Workload {
    let mut operations = String::new();
    let mut id = 0usize;
    let mut live = Vec::new();
    for size in [8usize, 24, 1000, 1025, 12_000, 100_000, 300_000] {
        for _ in 0..3 {
            writeln!(operations, "a {id} {size}").unwrap();
            live.push(id);
            id += 1;
        }
    }
    for victim in live.iter().step_by(2) {
        writeln!(operations, "f {victim}").unwrap();
    }
    let mut survivors: Vec<usize> = live.iter().copied().skip(1).step_by(2).collect();
    for size in [16usize, 1000, 12_000] {
        writeln!(operations, "a {id} {size}").unwrap();
        survivors.push(id);
        id += 1;
    }
    for victim in survivors.iter().rev() {
        writeln!(operations, "f {victim}").unwrap();
    }
    // Quick reuse of a retired direct-small page.
    for _ in 0..3 {
        writeln!(operations, "a {id} 48").unwrap();
        writeln!(operations, "f {id}").unwrap();
        id += 1;
    }
    parse_workload(&format!("{WORKLOAD_MAGIC}\narena_bytes=0 ids={id}\n{operations}"))
}

struct PageRecord {
    pid: u64,
    start: usize,
    span: usize,
    block_size: usize,
    line: String,
    seen: bool,
}

/// The shared normalization of `m3_local_trace_x86_64.c`'s owner profile.
#[derive(Default)]
struct Tracer {
    arena: Option<usize>,
    records: BTreeMap<usize, PageRecord>,
    next_pid: u64,
    queue_lines: BTreeMap<usize, String>,
    direct: BTreeMap<usize, u64>,
    global: String,
    bootstrapped: bool,
    out: String,
}

fn block_text(block: Option<NativeTheapTraceBlock>) -> String {
    match block {
        None => String::from("-"),
        Some(NativeTheapTraceBlock { index, remainder: 0 }) => format!("{index}"),
        Some(NativeTheapTraceBlock { index, remainder }) => format!("{index}r{remainder}"),
    }
}

impl Tracer {
    fn new() -> Self {
        Self { next_pid: 1, ..Self::default() }
    }

    fn slot(&mut self, arena: usize, slice: usize) -> usize {
        match self.arena {
            None => self.arena = Some(arena),
            Some(first) => assert_eq!(first, arena, "owner pages span two arenas"),
        }
        slice
    }

    fn snapshot(&mut self) {
        let mut facts = Vec::new();
        assert!(
            native_runtime_current_owner_theap_trace_test_audit(&mut |fact| facts.push(fact)),
            "the persistent owner's page engine is active and its Theap walk completes"
        );
        if !self.bootstrapped {
            self.bootstrapped = true;
            for fact in &facts {
                match *fact {
                    NativeTheapTraceFact::Options { page_full_retain, allow_page_abandon, allow_page_reclaim } => {
                        writeln!(
                            self.out,
                            "T retain{page_full_retain} abandon{} reclaim{}",
                            u8::from(allow_page_abandon),
                            u8::from(allow_page_reclaim)
                        )
                        .unwrap();
                    }
                    NativeTheapTraceFact::Queue { bin, block_size, .. } => {
                        writeln!(self.out, "B{bin} {block_size}").unwrap();
                    }
                    _ => {}
                }
            }
        }
        for record in self.records.values_mut() {
            record.seen = false;
        }
        let mut members = String::new();
        for fact in facts {
            match fact {
                NativeTheapTraceFact::Options { .. } => {}
                NativeTheapTraceFact::NonArenaPage { bin } => {
                    panic!("queue {bin} holds a page that is not arena memory")
                }
                NativeTheapTraceFact::Page { bin, page } => {
                    let NativeTheapTracePage {
                        arena,
                        slice,
                        start,
                        block_size,
                        capacity,
                        reserved,
                        used,
                        free,
                        local_free,
                        retire_expire,
                        in_full,
                        free_is_zero,
                    } = page;
                    let slot = self.slot(arena, slice);
                    let line = format!(
                        "q{bin} s{block_size} c{capacity} r{reserved} u{used} f{} l{} x{retire_expire} F{} z{} S{slot}",
                        block_text(free),
                        block_text(local_free),
                        u8::from(in_full),
                        u8::from(free_is_zero),
                    );
                    let span = reserved * block_size;
                    let pid = match self.records.get_mut(&slot) {
                        Some(record) => {
                            assert!(!record.seen, "page P{} occurs in two queues", record.pid);
                            record.seen = true;
                            record.start = start;
                            record.span = span;
                            record.block_size = block_size;
                            if record.line != line {
                                writeln!(self.out, "~P{} {line}", record.pid).unwrap();
                                record.line = line;
                            }
                            record.pid
                        }
                        None => {
                            let pid = self.next_pid;
                            self.next_pid += 1;
                            writeln!(self.out, "+P{pid} {line}").unwrap();
                            self.records.insert(
                                slot,
                                PageRecord { pid, start, span, block_size, line, seen: true },
                            );
                            pid
                        }
                    };
                    write!(members, "{pid},").unwrap();
                }
                NativeTheapTraceFact::Queue { bin, count, .. } => {
                    let queue_line = format!("{members} n{count}");
                    members.clear();
                    if self.queue_lines.get(&bin) != Some(&queue_line) {
                        writeln!(self.out, "Q{bin} {queue_line}").unwrap();
                        self.queue_lines.insert(bin, queue_line);
                    }
                }
                NativeTheapTraceFact::Direct { index, page } => {
                    if index == 0 {
                        self.emit_removed();
                    }
                    let pid = match page {
                        NativeTheapTraceDirect::Empty => 0,
                        NativeTheapTraceDirect::Page { arena, slice } => {
                            let slot = self.slot(arena, slice);
                            self.records.get(&slot).map_or(u64::MAX, |record| record.pid)
                        }
                        NativeTheapTraceDirect::Other => u64::MAX,
                    };
                    if pid != self.direct.get(&index).copied().unwrap_or(0) {
                        match pid {
                            0 => writeln!(self.out, "D{index} -").unwrap(),
                            u64::MAX => writeln!(self.out, "D{index} ?").unwrap(),
                            pid => writeln!(self.out, "D{index} {pid}").unwrap(),
                        }
                        self.direct.insert(index, pid);
                    }
                }
                NativeTheapTraceFact::Counters {
                    page_count,
                    retired_min,
                    retired_max,
                    pages_full_size,
                    generic_count,
                    generic_collect_count,
                    heartbeat,
                } => {
                    let global = format!(
                        "pc{page_count} rmin{retired_min} rmax{retired_max} pfs{pages_full_size} gc{generic_count} gcc{generic_collect_count} hb{heartbeat}"
                    );
                    if global != self.global {
                        writeln!(self.out, "G {global}").unwrap();
                        self.global = global;
                    }
                }
            }
        }
    }

    /// Removed pages in ascending logical-page order.
    fn emit_removed(&mut self) {
        let mut removed: Vec<u64> = Vec::new();
        self.records.retain(|_, record| {
            if record.seen {
                true
            } else {
                removed.push(record.pid);
                false
            }
        });
        removed.sort_unstable();
        for pid in removed {
            writeln!(self.out, "-P{pid}").unwrap();
        }
    }

    /// Names a returned block by its traced page and block index, as the C
    /// driver does through `_mi_ptr_page`.
    fn block_result(&self, block: *mut u8) -> String {
        let address = block.addr();
        for record in self.records.values() {
            if (record.start..record.start + record.span).contains(&address) {
                let offset = address - record.start;
                let index = block_text(Some(NativeTheapTraceBlock {
                    index: offset / record.block_size,
                    remainder: offset % record.block_size,
                }));
                return format!("= P{} i{index}", record.pid);
            }
        }
        String::from("= ?")
    }
}

/// Runs the workload on the calling persistent owner and returns its trace.
fn run_workload(workload: &Workload) -> String {
    let mut tracer = Tracer::new();
    let mut blocks: Vec<Option<core::ptr::NonNull<u8>>> = vec![None; workload.ids];
    for (index, operation) in workload.operations.iter().copied().enumerate() {
        let step = index + 1;
        match operation {
            Operation::Allocate { id, size } => {
                writeln!(tracer.out, "@{step} a{id} {size}").unwrap();
                let block = match native_allocate_aligned(size, ALIGNMENT, false) {
                    NativePageAllocationResult::Allocated(block) => Some(block),
                    NativePageAllocationResult::AllocationFailed => None,
                    NativePageAllocationResult::Unavailable | NativePageAllocationResult::Retained => {
                        panic!("the persistent owner is unavailable for step {step}")
                    }
                };
                blocks[id] = block;
                tracer.snapshot();
                let result = match block {
                    Some(block) => tracer.block_result(block.as_ptr()),
                    None => String::from("= null"),
                };
                writeln!(tracer.out, "{result}").unwrap();
            }
            Operation::Free { id } => {
                assert!(tracer.bootstrapped, "the owner workload frees before its first allocation");
                writeln!(tracer.out, "@{step} f{id}").unwrap();
                if let Some(block) = blocks[id].take() {
                    // SAFETY: each logical ID frees its one live allocation
                    // from this owner exactly once, as `parse_workload`
                    // enforces; no other thread knows the block.
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                }
                tracer.snapshot();
            }
        }
    }
    writeln!(tracer.out, "E").unwrap();
    assert!(blocks.iter().all(Option::is_none), "the workload freed every allocation");
    tracer.out
}

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// Produces one trace in this process for `owner`.
fn produce(owner: Owner, workload: &Workload) -> String {
    assert!(native_runtime_test_support::initialize(current_page_size()));
    match owner {
        Owner::Initial => run_workload(workload),
        Owner::Later => {
            assert!(
                prepare_native_later_thread_arena(),
                "the dormant initial owner admits one later persistent owner"
            );
            let workload = Workload { ids: workload.ids, operations: workload.operations.clone() };
            std::thread::spawn(move || {
                assert_eq!(
                    native_runtime_test_support::attach_current_thread(),
                    ThreadAttachResult::Attached
                );
                let trace = run_workload(&workload);
                assert_eq!(
                    finish_current_thread_native_after_user_destructors(),
                    ThreadFinishResult::Finished,
                    "the all-free later owner reaches its ordinary source teardown"
                );
                trace
            })
            .join()
            .expect("the later persistent owner joins")
        }
    }
}

fn run_child(owner: Owner, output: &PathBuf) -> String {
    let status = std::process::Command::new(
        std::env::current_exe().expect("the focused test executable has a current path"),
    )
    .args(["--exact", TEST_NAME, "--test-threads=1"])
    .env(OWNER_ENV, owner.name())
    .env_remove(WORKLOAD_ENV)
    .env(OUTPUT_ENV, output)
    .status()
    .expect("the trace child starts");
    assert_eq!(status.code(), Some(0), "the {} owner trace child succeeds", owner.name());
    std::fs::read_to_string(output).expect("the child wrote its trace")
}

/// One fresh process per trace. With `CRABC_M3_OWNER_TRACE_OWNER` set, this
/// process is the producer; otherwise it runs the built-in workload on each
/// owner in two fresh child processes and requires identical traces.
#[test]
fn persistent_owner_local_trace() {
    if let Some(owner) = std::env::var_os(OWNER_ENV) {
        let owner = Owner::parse(owner.to_str().expect("the owner name is UTF-8"));
        let workload = match std::env::var_os(WORKLOAD_ENV) {
            Some(path) => parse_workload(&std::fs::read_to_string(path).expect("read trace workload")),
            None => builtin_workload(),
        };
        let trace = produce(owner, &workload);
        assert!(trace.ends_with("E\n"));
        let output = std::env::var_os(OUTPUT_ENV).expect("the producer has an output path");
        std::fs::write(output, trace).expect("write trace output");
        return;
    }
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m3-persistent-owner-local-trace");
    std::fs::create_dir_all(&directory).expect("create the trace directory");
    for owner in [Owner::Initial, Owner::Later] {
        let first = run_child(owner, &directory.join(format!("{}-1.trace", owner.name())));
        let second = run_child(owner, &directory.join(format!("{}-2.trace", owner.name())));
        assert_eq!(first, second, "the {} owner trace is deterministic across fresh processes", owner.name());
        assert!(first.starts_with("@1 a0 8\nT retain"), "the trace bootstraps at the first allocation");
        assert!(first.contains(" x16 "), "freed pages retire through the ordinary local path");
        assert!(!first.contains("= ?"), "every returned block lies in a traced queue page");
    }
}
