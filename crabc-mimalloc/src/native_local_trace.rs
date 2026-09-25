// SPDX-License-Identifier: MIT
//! Native-boundary local trace, the Rust half of the differential run by
//! `compat/allocator/native_local_trace_x86_64.py` against
//! `compat/allocator/native_local_trace_x86_64.c`.
//!
//! One fresh process initializes the runtime, then applies the same
//! workload through `native_allocate_aligned(size, 16, zero)`/`native_free`
//! first on the initial persistent owner and then on one attached later
//! owner. After every operation it prints the touched page's normalized
//! state (page by discovery order, blocks by index) and the default Theap's
//! counters, the same line the pinned C driver prints for `mi_malloc_aligned`/`mi_free` on
//! the main thread and one worker. Without the workload/output environment
//! it runs a small built-in workload and only checks internal consistency.

extern crate std;

use core::ffi::c_char;
use core::ptr::NonNull;
use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

use crate::compiler_tls::default_theap;
use crate::config::BIN_COUNT;
use crate::diagnostic_output::RuntimeStderrOutput;
use crate::runtime_lifecycle::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    prepare_native_later_thread_arena, register_current_native_allocator_worker_descriptor,
    test_initialize_process_from_host_environment,
};
use crate::types::{Page, Theap};

const WORKLOAD_ENV: &str = "CRABC_NATIVE_LOCAL_TRACE_WORKLOAD";
const OUTPUT_ENV: &str = "CRABC_NATIVE_LOCAL_TRACE_OUTPUT";
const WORKLOAD_MAGIC: &str = "native-local-trace 1";
/// The C `malloc` alignment the libc native adapter passes.
const ALIGNMENT: usize = 16;

#[derive(Clone, Copy)]
enum Operation {
    Allocate { id: usize, size: usize, zero: bool },
    Free { id: usize },
}

fn parse_workload(text: &str) -> (usize, Vec<Operation>) {
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(WORKLOAD_MAGIC), "workload magic");
    let mut ids = 0;
    let mut operations = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        let number = |index: usize| -> usize { fields[index].parse().expect("workload integer") };
        match fields.first().copied() {
            Some("a") => {
                let id = number(1);
                ids = ids.max(id + 1);
                operations.push(Operation::Allocate { id, size: number(2), zero: number(3) != 0 });
            }
            Some("f") => operations.push(Operation::Free { id: number(1) }),
            None => {}
            Some(other) => panic!("unknown workload operation {other}"),
        }
    }
    (ids, operations)
}

fn builtin_workload() -> String {
    let mut text = String::from(WORKLOAD_MAGIC);
    text.push('\n');
    for (round, size) in [16usize, 48, 64, 1024].into_iter().enumerate() {
        for index in 0..4 {
            let id = round * 8 + index;
            writeln!(text, "a {id} {size} {}", index & 1).unwrap();
        }
        for index in 0..4 {
            writeln!(text, "f {}", round * 8 + index).unwrap();
        }
    }
    text
}

struct Tracer {
    out: String,
    pages: Vec<*mut Page>,
    blocks: Vec<Option<(NonNull<u8>, *mut Page)>>,
}

impl Tracer {
    fn page_id(&mut self, page: *mut Page) -> usize {
        match self.pages.iter().position(|known| *known == page) {
            Some(index) => index + 1,
            None => {
                self.pages.push(page);
                self.pages.len()
            }
        }
    }

    /// Finds `block`'s page among the default Theap's queues.
    fn page_of(theap: &Theap, block: NonNull<u8>) -> *mut Page {
        let address = block.as_ptr().addr();
        for bin in 0..BIN_COUNT {
            let mut page = theap.queue(bin).expect("source bin").first();
            while let Some(current) = NonNull::new(page) {
                // SAFETY: the owning thread is between operations; its
                // queued pages are live.
                let current_ref = unsafe { current.as_ref() };
                // SAFETY: an initialized queued page has a valid start.
                let start = unsafe { current_ref.start() }.addr();
                let end = start + current_ref.reserved() as usize * current_ref.block_size();
                if (start..end).contains(&address) {
                    return page;
                }
                page = current_ref.next();
            }
        }
        panic!("a live native block belongs to a page of the current default Theap");
    }

    fn index(page: &Page, pointer: *const u8) -> String {
        if pointer.is_null() {
            return String::from("-");
        }
        // SAFETY: an initialized page has a valid start.
        let offset = pointer.addr() - unsafe { page.start() }.addr();
        let block_size = page.block_size();
        if offset % block_size == 0 {
            std::format!("{}", offset / block_size)
        } else {
            std::format!("{}r{}", offset / block_size, offset % block_size)
        }
    }

    fn record(&mut self, head: &str, block: NonNull<u8>, page: *mut Page) {
        // SAFETY: the current thread's default Theap is live between
        // operations and nothing else reads or writes it now.
        let theap = unsafe { default_theap().as_ref() };
        let pid = self.page_id(page);
        // SAFETY: `page` is a live queued page of that Theap.
        let page_ref = unsafe { &*page };
        let bin = crate::size_class::bin(page_ref.block_size()).expect("page bin");
        let (retired_min, retired_max) = theap.retired_bounds();
        let (_, generic_count, generic_collect_count) = theap.test_generic_administration_image();
        writeln!(
            self.out,
            "{head} P{pid} i{} | s{} c{} r{} u{} f{} l{} x{} z{} n{} pc{} gc{generic_count} gcc{generic_collect_count} rmin{retired_min} rmax{retired_max}",
            Self::index(page_ref, block.as_ptr()),
            page_ref.block_size(),
            page_ref.capacity(),
            page_ref.reserved(),
            page_ref.used(),
            Self::index(page_ref, page_ref.free_list_head().cast()),
            Self::index(page_ref, page_ref.remote_free_test_local_free().cast()),
            page_ref.retire_expire(),
            u8::from(page_ref.remote_free_test_free_is_zero()),
            theap.queue(bin).expect("page queue").count(),
            theap.page_count(),
        )
        .unwrap();
    }

    fn run(&mut self, profile: &str, ids: usize, operations: &[Operation]) {
        writeln!(self.out, "profile {profile}").unwrap();
        self.pages.clear();
        self.blocks = std::vec![None; ids];
        for operation in operations {
            match *operation {
                Operation::Allocate { id, size, zero } => {
                    let NativePageAllocationResult::Allocated(block) =
                        native_allocate_aligned(size, ALIGNMENT, zero)
                    else {
                        panic!("native allocation {id} of {size} bytes succeeds");
                    };
                    let zeroed = zero
                        // SAFETY: the fresh block has at least `size` bytes.
                        && unsafe { core::slice::from_raw_parts(block.as_ptr(), size) }.iter().all(|byte| *byte == 0);
                    // SAFETY: the caller owns the fresh block.
                    unsafe { block.as_ptr().write_bytes(0xa5, size) };
                    // SAFETY: see `record`.
                    let page = Self::page_of(unsafe { default_theap().as_ref() }, block);
                    self.blocks[id] = Some((block, page));
                    let head = std::format!("a{id} {size} z{} Z{}", u8::from(zero), u8::from(zeroed));
                    self.record(&head, block, page);
                }
                Operation::Free { id } => {
                    let (block, page) = self.blocks[id].take().expect("free names a live id");
                    // SAFETY: `block` is this thread's live native client.
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    self.record(&std::format!("f{id}"), block, page);
                }
            }
        }
        assert!(self.blocks.iter().all(Option::is_none), "the workload frees every block");
    }
}

unsafe extern "C" {
    fn fputs(message: *const c_char, stream: *mut core::ffi::c_void) -> i32;
    static mut stderr: *mut core::ffi::c_void;
}

unsafe extern "C" fn trace_stderr(message: *const c_char) {
    // SAFETY: the native x86 test image links musl's process-lifetime
    // `stderr`, and the engine passes one NUL-terminated fragment.
    unsafe {
        let _ = fputs(message, stderr);
    }
}

#[test]
fn emit_native_local_trace() {
    crate::test_process::run_in_fresh_process("native_local_trace::emit_native_local_trace", || {
        let text = match std::env::var(WORKLOAD_ENV) {
            Ok(path) => std::fs::read_to_string(path).expect("read the native local-trace workload"),
            Err(_) => builtin_workload(),
        };
        let (ids, operations) = parse_workload(&text);
        let out = std::thread::spawn(move || {
            // SAFETY: `trace_stderr` has the source FILE callback shape and
            // musl's stderr outlives this fresh process.
            assert!(test_initialize_process_from_host_environment(4096, unsafe {
                RuntimeStderrOutput::new(trace_stderr)
            }));
            assert!(prepare_native_later_thread_arena());
            let mut tracer = Tracer { out: String::new(), pages: Vec::new(), blocks: Vec::new() };
            tracer.run("initial", ids, &operations);
            let worker = std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let descriptor = current_native_allocator_thread_descriptor();
                        // SAFETY: this worker's own TLS descriptor stays
                        // mapped until it finishes below.
                        assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
                        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                        let mut tracer = Tracer { out: String::new(), pages: Vec::new(), blocks: Vec::new() };
                        tracer.run("worker", ids, &operations);
                        assert_eq!(
                            finish_current_thread_native_after_user_destructors(),
                            ThreadFinishResult::Finished
                        );
                        tracer.out
                    })
                    .join()
                    .expect("the later owner completes its trace")
            });
            tracer.out + &worker
        })
        .join()
        .expect("the initial owner completes its trace");
        if let Ok(path) = std::env::var(OUTPUT_ENV) {
            std::fs::write(path, out).expect("write the native local trace");
        }
    });
}
