//! Rust-native facade comparisons.
//!
//! Exactly one backend feature is enabled per executable. Both routes use
//! their direct Linux syscall facades; this fixture is intentionally separate
//! from the C dynamic-runtime musl comparison in `../run.py`.

use rustybench::AllocProfiler;

#[global_allocator]
static ALLOCATOR: AllocProfiler = AllocProfiler::system();

#[cfg(all(feature = "crabc", feature = "rustix"))]
compile_error!("choose exactly one of the crabc or rustix backend features");
#[cfg(not(any(feature = "crabc", feature = "rustix")))]
compile_error!("choose exactly one of the crabc or rustix backend features");

#[cfg(feature = "crabc")]
mod backend {
    use crabc_rs::fs::{Mode, OFlags};

    pub fn getpid() {
        rustybench::black_box(crabc_rs::process::getpid());
    }

    pub fn clock_gettime() {
        rustybench::black_box(crabc_rs::time::clock_gettime(
            crabc_rs::time::ClockId::Monotonic,
        ));
    }

    pub fn open_close() {
        let descriptor = crabc_rs::fs::open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("/dev/null must be openable");
        rustybench::black_box(descriptor.as_raw_fd());
        descriptor.close().expect("/dev/null close must succeed");
    }
}

#[cfg(feature = "rustix")]
mod backend {
    use rustix::{fd::AsRawFd as _, fs::{Mode, OFlags}};

    pub fn getpid() {
        rustybench::black_box(rustix::process::getpid());
    }

    pub fn clock_gettime() {
        rustybench::black_box(rustix::time::clock_gettime(
            rustix::time::ClockId::Monotonic,
        ));
    }

    pub fn open_close() {
        let descriptor = rustix::fs::open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .expect("/dev/null must be openable");
        rustybench::black_box(descriptor.as_raw_fd());
        drop(descriptor);
    }
}

#[rustybench::bench]
fn getpid() {
    backend::getpid();
}

#[rustybench::bench]
fn clock_gettime() {
    backend::clock_gettime();
}

#[rustybench::bench]
fn open_close() {
    backend::open_close();
}

fn main() {
    rustybench::main();
}
