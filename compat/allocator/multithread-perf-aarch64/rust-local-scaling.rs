//! Private direct-engine companion to `fixture.c`.
//!
//! This binary deliberately uses `crabc_mimalloc::__crabc_runtime`, the
//! documentation-hidden friend boundary already used by `crabc-libc` and the
//! native allocator tests. It is not a public allocation API, a libc backend,
//! or a substitute for the one-thread prefixed C adapter.

use core::ffi::c_void;
use std::env;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, prepare_native_later_thread_arena,
};

const ALLOCATION_BYTES: usize = 64;
const MAX_WORKERS: usize = 8;
const CPU_SET_BYTES: usize = 128;

unsafe extern "C" {
    fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const c_void) -> i32;
}

struct Arguments {
    workers: usize,
    iterations: u64,
    cpus: Vec<usize>,
}

struct WorkerResult {
    checksum: u64,
    elapsed_ns: u128,
}

fn parse_positive(value: Option<String>) -> Result<u64, ()> {
    value
        .ok_or(())?
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(())
}

fn parse_arguments() -> Result<Arguments, ()> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() != Some("--workers") {
        return Err(());
    }
    let workers = usize::try_from(parse_positive(arguments.next())?).map_err(|_| ())?;
    if arguments.next().as_deref() != Some("--iterations") {
        return Err(());
    }
    let iterations = parse_positive(arguments.next())?;
    if arguments.next().as_deref() != Some("--cpus") {
        return Err(());
    }
    let cpus = arguments
        .next()
        .ok_or(())?
        .split(',')
        .map(|value| value.parse::<usize>().map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    if arguments.next().is_some() || workers == 0 || workers > MAX_WORKERS || cpus.len() != workers {
        return Err(());
    }
    Ok(Arguments {
        workers,
        iterations,
        cpus,
    })
}

fn pin_current_thread(cpu: usize) -> Result<(), ()> {
    if cpu >= CPU_SET_BYTES * 8 {
        return Err(());
    }
    let mut set = [0_u8; CPU_SET_BYTES];
    set[cpu / 8] |= 1 << (cpu % 8);
    // SAFETY: Linux interprets pid zero as the current thread. `set` remains
    // live for the complete call and is the exact documented CPU-mask size.
    if unsafe { sched_setaffinity(0, set.len(), set.as_ptr().cast()) } != 0 {
        return Err(());
    }
    Ok(())
}

fn current_page_size() -> Result<usize, ()> {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or(())
}

fn run_worker(cpu: usize, iterations: u64, barrier: Arc<Barrier>) -> Result<WorkerResult, ()> {
    let attached = pin_current_thread(cpu).is_ok() && attach_current_thread() == ThreadAttachResult::Attached;
    barrier.wait();
    barrier.wait();
    if !attached {
        return Err(());
    }

    let started = Instant::now();
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        let block = match native_allocate_aligned(ALLOCATION_BYTES, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => return Err(()),
        };
        // SAFETY: `block` is the live allocation returned immediately above;
        // this worker alone owns it until `native_free` succeeds below.
        unsafe {
            block.as_ptr().write(iteration as u8);
            block.as_ptr().add(ALLOCATION_BYTES - 1).write((iteration >> 8) as u8);
            checksum += u64::from(block.as_ptr().read());
            checksum += u64::from(block.as_ptr().add(ALLOCATION_BYTES - 1).read());
        }
        if unsafe { native_free(block) } != NativePageFreeResult::Freed {
            return Err(());
        }
    }
    let elapsed_ns = started.elapsed().as_nanos();
    if elapsed_ns == 0 || finish_current_thread_native_after_user_destructors() != ThreadFinishResult::Finished {
        return Err(());
    }
    Ok(WorkerResult {
        checksum,
        elapsed_ns,
    })
}

fn run(arguments: Arguments) -> Result<(), ()> {
    if !initialize_process(current_page_size()?) || !prepare_native_later_thread_arena() {
        return Err(());
    }
    let barrier = Arc::new(Barrier::new(arguments.workers + 1));
    let mut workers = Vec::with_capacity(arguments.workers);
    let iterations = arguments.iterations;
    for cpu in arguments.cpus.iter().copied() {
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || run_worker(cpu, iterations, barrier)));
    }
    barrier.wait();
    barrier.wait();

    let mut maximum_ns = 0_u128;
    let mut sum_ns = 0_u128;
    let mut checksum = 0_u64;
    for worker in workers {
        let result = worker.join().map_err(|_| ())??;
        maximum_ns = maximum_ns.max(result.elapsed_ns);
        sum_ns += result.elapsed_ns;
        checksum += result.checksum;
    }
    if maximum_ns == 0 {
        return Err(());
    }
    let operations = u128::from(arguments.iterations) * arguments.workers as u128;
    println!("workers={}", arguments.workers);
    println!("iterations={}", arguments.iterations);
    println!("operations={operations}");
    println!("max_worker_ns={maximum_ns}");
    println!("sum_worker_ns={sum_ns}");
    println!("checksum={checksum}");
    println!(
        "affinity={}",
        arguments
            .cpus
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("ok");
    Ok(())
}

fn main() {
    match parse_arguments().and_then(run) {
        Ok(()) => {}
        Err(()) => std::process::exit(64),
    }
}
