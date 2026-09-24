// SPDX-License-Identifier: MIT
//
// Test-only M3 deterministic local-engine trace driver.
//
// Pinned mimalloc v3.5.0 is the oracle: `compat/allocator/m3_local_trace_x86_64.c`
// runs the same workload file against the pinned C default Theap and emits the
// same normalized trace. `compat/allocator/m3_x86_64.py` generates the
// workloads, runs both producers in separate processes, and compares their
// output line by line.
//
// The trace names allocations by workload-assigned logical IDs and pages by
// discovery order, never by address. After each operation it walks every
// Theap queue from `0` through `BIN_FULL` in source order and emits only what
// changed: page geometry and free/local list heads (as block indices), queue
// membership order and source `count`, the direct-page cache, and the Theap
// counters (`page_count`, retired bounds, `pages_full_size`, generic
// administration, heartbeat). Page slots are arena-slice offsets from the
// managed region base, so the two identically sized in-place arenas also
// compare their page placement.
//
// The profile is the source non-abandoning local Theap
// (`mi_option_page_full_retain == -1`) over one pinned, committed, zero
// in-place arena. It exercises only owner-local allocation, free, page queue,
// full-queue, retirement, and reuse transitions. It deliberately excludes
// remote frees, abandonment, reclaim, thread exit, aligned/zeroed/realloc
// operations, explicit collection, and the process runtime owner.

extern crate std;

use core::pin::pin;
use core::ptr::NonNull;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::string::String;
use std::vec::Vec;
use std::vec;

use super::{DeferredFreeAllocationPhase, GenericAllocationCollection, SingleThreadAllocator};
use crate::arena::{ArenaId, ArenaRegistry, ArenaView, manage_external_in_place};
use crate::bootstrap::ExclusiveTheapBootstrap;
use crate::config::{
    ARENA_ALIGNMENT, ARENA_MIN_SIZE, ARENA_SLICE_SHIFT, BIN_COUNT, PAGES_DIRECT,
};
use crate::os::{MemoryConfig, PageSize};
use crate::page_map::PageMap;
use crate::types::page_queue::page_is_in_full;
use crate::types::{EMPTY_PAGE, LiveThreadId, Page};

/// Path of one generated workload file (`m3-local-trace 1` format).
const WORKLOAD_ENV: &str = "CRABC_M3_LOCAL_TRACE_WORKLOAD";
/// Path receiving the normalized trace. Without it the trace is only checked
/// for determinism and internal consistency.
const OUTPUT_ENV: &str = "CRABC_M3_LOCAL_TRACE_OUTPUT";
const WORKLOAD_MAGIC: &str = "m3-local-trace 1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Allocate { id: usize, size: usize },
    Free { id: usize },
}

#[derive(Debug)]
struct Workload {
    arena_bytes: usize,
    ids: usize,
    operations: Vec<Operation>,
}

fn parse_field(token: Option<&str>, prefix: &str, line: usize) -> usize {
    let token = token.unwrap_or_else(|| panic!("workload line {line}: missing {prefix}"));
    let value = token
        .strip_prefix(prefix)
        .unwrap_or_else(|| panic!("workload line {line}: expected {prefix}, got {token}"));
    value
        .parse()
        .unwrap_or_else(|_| panic!("workload line {line}: invalid {prefix}{value}"))
}

/// Parses the generator's line format. Every ID is allocated before it is
/// freed and freed at most once per allocation; the parser enforces that so a
/// malformed workload cannot become undefined allocator input.
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
    assert!(arena_bytes >= ARENA_MIN_SIZE && arena_bytes % ARENA_MIN_SIZE == 0);

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
    Workload { arena_bytes, ids, operations }
}

/// A small complete built-in workload for standalone and Miri execution. It
/// covers the direct-small cache, one regular-small page moving through
/// `BIN_FULL` and back, a medium page, a singleton, local-free reuse, and
/// retirement of every page it creates.
fn builtin_workload() -> Workload {
    let mut text = String::new();
    writeln!(text, "{WORKLOAD_MAGIC}").unwrap();
    let mut operations = String::new();
    let mut id = 0usize;
    let mut live = Vec::new();
    // Fill one 1-KiB direct-small page past capacity (64 blocks per page).
    for _ in 0..66 {
        writeln!(operations, "a {id} 1024").unwrap();
        live.push(id);
        id += 1;
    }
    // Free two blocks from the first page: it leaves `BIN_FULL` locally.
    for &victim in &live[..2] {
        writeln!(operations, "f {victim}").unwrap();
    }
    live.drain(..2);
    for size in [24usize, 1025, 12_000, 600 * 1024] {
        for _ in 0..3 {
            writeln!(operations, "a {id} {size}").unwrap();
            live.push(id);
            id += 1;
        }
    }
    // Reuse the locally freed blocks, then free everything in reverse order so
    // pages retire through the ordinary local path.
    for _ in 0..2 {
        writeln!(operations, "a {id} 1000").unwrap();
        live.push(id);
        id += 1;
    }
    for victim in live.iter().rev() {
        writeln!(operations, "f {victim}").unwrap();
    }
    writeln!(text, "arena_bytes={} ids={id}", ARENA_MIN_SIZE).unwrap();
    text.push_str(&operations);
    parse_workload(&text)
}

struct PageRecord {
    page: *mut Page,
    pid: u64,
    line: String,
    seen: bool,
}

/// Normalizes one allocator's queue state into the shared line format. The
/// same algorithm is written in C for the pinned oracle; any change here must
/// change `m3_local_trace_x86_64.c` identically.
struct Tracer {
    base: usize,
    slots: usize,
    records: Vec<Option<PageRecord>>,
    next_pid: u64,
    queue_lines: Vec<String>,
    direct: Vec<u64>,
    global: String,
    out: String,
}

fn block_index(page: &Page, block: *mut u8) -> String {
    if block.is_null() {
        return String::from("-");
    }
    // SAFETY: the page is a live queue member of the exclusively borrowed
    // engine; `start` only forms its block-area address.
    let start = unsafe { page.start() } as usize;
    let offset = (block as usize).wrapping_sub(start);
    let size = page.block_size();
    if offset % size == 0 {
        std::format!("{}", offset / size)
    } else {
        std::format!("{}r{}", offset / size, offset % size)
    }
}

impl Tracer {
    fn new(base: usize, arena_bytes: usize) -> Self {
        let slots = arena_bytes >> ARENA_SLICE_SHIFT;
        Self {
            base,
            slots,
            records: (0..slots).map(|_| None).collect(),
            next_pid: 1,
            queue_lines: vec![String::new(); BIN_COUNT],
            direct: vec![0; PAGES_DIRECT],
            global: String::new(),
            out: String::new(),
        }
    }

    /// Names a page by the arena slice holding its first block. Page metadata
    /// itself lives in the arena's aligned metadata array, not at the slice.
    fn slot(&self, page: *mut Page) -> usize {
        // SAFETY: callers pass live queue members or direct-cache entries of
        // the exclusively borrowed engine; `start` only forms an address.
        let address = unsafe { (*page).start() } as usize;
        assert!(address >= self.base, "page {page:p} precedes the traced arena");
        let slot = (address - self.base) >> ARENA_SLICE_SHIFT;
        assert!(slot < self.slots, "page {page:p} lies outside the traced arena");
        slot
    }

    fn pid_of(&self, page: *mut Page) -> Option<u64> {
        match &self.records[self.slot(page)] {
            Some(record) => {
                debug_assert_eq!(record.page, page);
                Some(record.pid)
            }
            None => None,
        }
    }

    fn bootstrap(&mut self, allocator: &SingleThreadAllocator<'_, '_, '_>) {
        let theap = allocator.session.theap();
        writeln!(
            self.out,
            "T retain{} abandon{} reclaim{}",
            theap.page_full_retain(),
            u8::from(theap.allows_page_abandon()),
            u8::from(theap.allows_page_reclaim()),
        )
        .unwrap();
        for bin in 0..BIN_COUNT {
            let queue = theap.queue(bin).unwrap();
            writeln!(self.out, "B{bin} {}", queue.block_size()).unwrap();
        }
        self.snapshot(allocator);
    }

    fn snapshot(&mut self, allocator: &SingleThreadAllocator<'_, '_, '_>) {
        let theap = allocator.session.theap();
        for record in self.records.iter_mut().flatten() {
            record.seen = false;
        }
        for bin in 0..BIN_COUNT {
            let queue = theap.queue(bin).unwrap();
            let mut members = String::new();
            let mut page = queue.first();
            let mut walked = 0usize;
            while !page.is_null() {
                walked += 1;
                assert!(walked <= self.slots, "queue {bin} does not terminate");
                let slot = self.slot(page);
                // SAFETY: queue members are live page metadata owned by this
                // exclusively borrowed single-thread engine.
                let page_ref = unsafe { &*page };
                let line = std::format!(
                    "q{bin} s{} c{} r{} u{} f{} l{} x{} F{} z{} S{slot}",
                    page_ref.block_size(),
                    page_ref.capacity(),
                    page_ref.reserved(),
                    page_ref.used(),
                    block_index(page_ref, page_ref.free_list_head().cast()),
                    block_index(page_ref, page_ref.remote_free_test_local_free().cast()),
                    page_ref.retire_expire(),
                    u8::from(page_is_in_full(page_ref)),
                    u8::from(page_ref.free_is_zero()),
                );
                // A slot identifies exactly one slice-aligned page start, so
                // an occupied slot is always this page's earlier record.
                let pid = match &mut self.records[slot] {
                    Some(record) => {
                        assert!(!record.seen, "page P{} occurs in two queues", record.pid);
                        record.seen = true;
                        if record.line != line {
                            writeln!(self.out, "~P{} {line}", record.pid).unwrap();
                            record.line = line;
                        }
                        record.pid
                    }
                    empty => {
                        let pid = self.next_pid;
                        self.next_pid += 1;
                        writeln!(self.out, "+P{pid} {line}").unwrap();
                        *empty = Some(PageRecord { page, pid, line, seen: true });
                        pid
                    }
                };
                write!(members, "{pid},").unwrap();
                page = page_ref.next();
            }
            let queue_line = std::format!("{members} n{}", queue.count());
            if queue_line != self.queue_lines[bin] {
                writeln!(self.out, "Q{bin} {queue_line}").unwrap();
                self.queue_lines[bin] = queue_line;
            }
        }
        let mut removed = BTreeMap::new();
        for record in &mut self.records {
            if record.as_ref().is_some_and(|record| !record.seen) {
                let record = record.take().unwrap();
                removed.insert(record.pid, ());
            }
        }
        for pid in removed.keys() {
            writeln!(self.out, "-P{pid}").unwrap();
        }
        for index in 0..PAGES_DIRECT {
            let page = theap.direct_page(index).unwrap();
            let pid = if core::ptr::eq(page, EMPTY_PAGE.as_ptr()) {
                0
            } else {
                self.pid_of(page).unwrap_or(u64::MAX)
            };
            if pid != self.direct[index] {
                match pid {
                    0 => writeln!(self.out, "D{index} -").unwrap(),
                    u64::MAX => writeln!(self.out, "D{index} ?").unwrap(),
                    pid => writeln!(self.out, "D{index} {pid}").unwrap(),
                }
                self.direct[index] = pid;
            }
        }
        let (retired_min, retired_max) = theap.retired_bounds();
        let (heartbeat, generic_count, generic_collect_count) =
            theap.test_generic_administration_image();
        let global = std::format!(
            "pc{} rmin{retired_min} rmax{retired_max} pfs{} gc{generic_count} gcc{generic_collect_count} hb{heartbeat}",
            theap.page_count(),
            theap.pages_full_size(),
        );
        if global != self.global {
            writeln!(self.out, "G {global}").unwrap();
            self.global = global;
        }
    }
}

/// Allocates through the engine's phased source path, the same
/// `_mi_malloc_generic` administration and forced-retry sequence that the
/// runtime owners drive. Between phases this stands in for the runtime's
/// phase B: the source `_mi_deferred_free` heartbeat with no registered
/// callback.
fn allocate_phased(
    allocator: &mut SingleThreadAllocator<'_, '_, '_>,
    size: usize,
) -> Option<NonNull<u8>> {
    let mut phase = allocator.begin_deferred_free_allocation(size, false);
    loop {
        match phase {
            DeferredFreeAllocationPhase::Complete(block) => return block,
            DeferredFreeAllocationPhase::Collect { collection, continuation } => {
                let force = matches!(collection, GenericAllocationCollection::Force);
                allocator.session.test_run_empty_deferred_free_phase(force);
                phase = allocator.resume_deferred_free_allocation(collection, continuation);
            }
        }
    }
}

/// Runs one workload through a fresh non-abandoning local engine and returns
/// its normalized trace.
fn run_workload(workload: &Workload) -> String {
    // Declaration order is teardown order in reverse: the engine and PageMap
    // are dismantled before the registry, the backing region is released
    // after them, and this run's own source-main subprocess image outlives
    // all of them. Owning it here, rather than leaking a static test owner,
    // lets Miri prove that the run returns every allocation it made.
    let subprocess = crate::subproc::MainSubprocess::new();
    let layout = Layout::from_size_align(workload.arena_bytes, ARENA_ALIGNMENT).unwrap();
    // SAFETY: the layout is nonzero; the region stays allocated until every
    // page has been force-collected and the registry has been dropped.
    let region = NonNull::new(unsafe { alloc_zeroed(layout) }).expect("trace arena region");
    let registry = ArenaRegistry::new(subprocess.as_ptr());
    // SAFETY: `region` is one live, writable, committed, zero allocation of
    // `arena_bytes` bytes reserved for this registry's whole lifetime.
    let managed = unsafe {
        manage_external_in_place(
            &registry,
            region.as_ptr(),
            workload.arena_bytes,
            PageSize::new(4096).unwrap(),
            true,
            true,
            true,
            -1,
            false,
            None,
        )
    }
    .expect("the trace arena is managed in place");
    assert!(managed.is_complete());
    // SAFETY: the arena was just published by this live registry.
    let arena = unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
    let config = MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1024 * 1024, false, false);
    let mut page_map = PageMap::initialize(config, 0, true).unwrap();
    let mut bootstrap = pin!(ExclusiveTheapBootstrap::new());
    let mut allocator = SingleThreadAllocator::activate_non_abandoning(
        bootstrap.as_mut(),
        LiveThreadId::new(12).unwrap(),
        arena,
        ArenaId::none(),
        &mut page_map,
        0,
    )
    .unwrap();

    let mut tracer = Tracer::new(region.as_ptr() as usize, workload.arena_bytes);
    tracer.bootstrap(&allocator);
    let mut blocks: Vec<Option<NonNull<u8>>> = vec![None; workload.ids];
    for (index, operation) in workload.operations.iter().copied().enumerate() {
        let step = index + 1;
        match operation {
            Operation::Allocate { id, size } => {
                writeln!(tracer.out, "@{step} a{id} {size}").unwrap();
                let block = allocate_phased(&mut allocator, size);
                blocks[id] = block;
                tracer.snapshot(&allocator);
                match block {
                    Some(block) => {
                        // SAFETY: the block was just returned by this engine
                        // and remains live; the lookup reads its PageMap entry.
                        let page = unsafe { allocator.page_for_block(block) };
                        match tracer.pid_of(page) {
                            Some(pid) => {
                                // SAFETY: `page` is a live queue member.
                                let index = block_index(unsafe { &*page }, block.as_ptr());
                                writeln!(tracer.out, "= P{pid} i{index}").unwrap();
                            }
                            None => writeln!(tracer.out, "= ?").unwrap(),
                        }
                    }
                    None => writeln!(tracer.out, "= null").unwrap(),
                }
            }
            Operation::Free { id } => {
                writeln!(tracer.out, "@{step} f{id}").unwrap();
                if let Some(block) = blocks[id].take() {
                    // SAFETY: each logical ID frees its one live allocation
                    // exactly once, as enforced by `parse_workload`.
                    unsafe { allocator.free(block) }.expect("local trace free succeeds");
                }
                tracer.snapshot(&allocator);
            }
        }
    }
    writeln!(tracer.out, "E").unwrap();

    assert!(blocks.iter().all(Option::is_none), "the workload freed every allocation");
    assert!(allocator.collect_retired(true));
    assert_eq!(allocator.session.theap().page_count(), 0);
    drop(allocator);
    // SAFETY: forced retirement removed every PageMap entry and no allocation
    // from this engine remains live.
    unsafe { page_map.destroy() }.unwrap();
    drop(registry);
    // SAFETY: allocated above with exactly `layout`; every user is gone.
    unsafe { dealloc(region.as_ptr(), layout) };
    tracer.out
}

/// Produces the Rust half of the M3 C/Rust local-engine differential.
///
/// Without `CRABC_M3_LOCAL_TRACE_WORKLOAD`, this runs the built-in workload,
/// which keeps the test meaningful in the ordinary unit suite and under Miri.
#[test]
fn emit_m3_local_trace() {
    let workload = match env::var_os(WORKLOAD_ENV) {
        Some(path) => parse_workload(&fs::read_to_string(path).expect("read trace workload")),
        None => builtin_workload(),
    };
    let trace = run_workload(&workload);
    assert!(trace.ends_with("E\n"));
    if let Some(path) = env::var_os(OUTPUT_ENV) {
        let mut file = fs::File::create(path).expect("create trace output");
        file.write_all(trace.as_bytes()).expect("write trace output");
    }
}

/// Two fresh engines over identical arenas produce the identical normalized
/// trace: the trace depends on no address, clock, or entropy value.
#[test]
fn m3_local_trace_is_deterministic_across_fresh_engines() {
    let workload = builtin_workload();
    let first = run_workload(&workload);
    let second = run_workload(&workload);
    assert_eq!(first, second);
    // The built-in workload reaches the full queue, returns from it locally,
    // retires, and allocates a singleton. An exhausted singleton moves to
    // `BIN_FULL` at once (`mi_malloc_generic_fallback`), so it is recognized
    // by its block size rather than by `BIN_HUGE` membership.
    assert!(first.lines().any(|line| line.starts_with("Q74 ") && !line.starts_with("Q74  n0")));
    assert!(first.lines().any(|line| line.contains(" F1 ")));
    assert!(first.lines().any(|line| line.contains(" x16 ")));
    let singleton = first.lines().filter(|line| line.starts_with("+P")).any(|line| {
        line.split_ascii_whitespace()
            .find_map(|field| field.strip_prefix('s'))
            .and_then(|size| size.parse::<usize>().ok())
            .is_some_and(|size| size > crate::config::LARGE_MAX_OBJ_SIZE)
    });
    assert!(singleton, "the built-in workload creates a singleton page");
}
