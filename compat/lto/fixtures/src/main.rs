//! Small, dependency-free workload for the static/build-std LTO matrix.
//!
//! The `extern "C"` calls are intentional: they keep a visible application →
//! libc wrapper boundary in the input while the Rust code supplies enough
//! allocation and arithmetic for LLVM inspection to be meaningful.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread;

unsafe extern "C" {
    fn getpid() -> i32;
    fn write(fd: i32, buffer: *const u8, count: usize) -> isize;
}

#[inline(always)]
fn mix(value: u64) -> u64 {
    value.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17) ^ 0xa5a5_5a5a_d3c3_b4b4
}

#[inline]
fn workload() -> u64 {
    let mut values = Vec::with_capacity(4096);
    for value in 0..4096_u64 {
        values.push(mix(value));
    }
    values.iter().fold(0_u64, |sum, value| sum.wrapping_add(*value))
}

fn libc_probe() -> io::Result<()> {
    let line = b"lto-libc:ok\n";
    // Keep the direct wrapper result observable without printing a PID that
    // would make cross-configuration output differ.
    let (pid, written) = unsafe { (getpid(), write(1, line.as_ptr(), line.len())) };
    if pid <= 0 || written != line.len() as isize {
        return Err(io::Error::other("libc probe failed"));
    }
    Ok(())
}

fn main() -> io::Result<()> {
    libc_probe()?;

    let state = Arc::new(Mutex::new(0_u64));
    let worker_state = Arc::clone(&state);
    let worker = thread::spawn(move || {
        let mut value = worker_state.lock().expect("mutex poisoned");
        *value = workload();
    });
    worker.join().expect("worker panicked");
    let result = *state.lock().expect("mutex poisoned");

    let mut stdout = io::BufWriter::new(io::stdout().lock());
    writeln!(stdout, "lto-workload:{result:016x}")?;
    stdout.flush()
}
