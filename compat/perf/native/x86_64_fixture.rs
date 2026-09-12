//! Native x86 Rust-facade benchmark fixture supplement.
//!
//! The renderer replaces the one source-path marker below with the checked-in
//! AArch64 fixture's physical path.  That fixture is compiled as `frozen`, so
//! its three route bodies remain byte-for-byte the existing source while this
//! file adds the two x86 companion routes.

#[path = "@CRABC_NATIVE_FROZEN_SOURCE@"]
mod frozen;

#[cfg(feature = "crabc")]
mod x86_supplement {
    use core::mem::MaybeUninit;

    use crabc_rs::{fs, Errno};
    use crabc_rs::fs::{Mode, OFlags, CWD};

    pub fn caller_buffer_readlinkat_raw() {
        // The fixed target is shorter than this caller-owned buffer.  The
        // initialized sentinel proves the raw facade returns only the kernel
        // initialized prefix and leaves the suffix untouched without allocating.
        let mut storage = [MaybeUninit::new(0xa5_u8); 32];
        let (target, untouched) = fs::readlinkat_raw(CWD, "fixture/fixed-link", &mut storage)
            .expect("the private fixed symlink must be readable");
        assert_eq!(target, b"fixed-target");
        assert!(untouched
            .iter()
            .all(|byte| unsafe { byte.assume_init() } == 0xa5));
        rustybench::black_box(target);
    }

    pub fn absent_open_error() {
        let error = fs::open(
            "fixture/proven-absent",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect_err("the private absent path must return ENOENT");
        assert_eq!(error, Errno::NOENT);
        rustybench::black_box(error.raw());
    }
}

#[cfg(feature = "rustix")]
mod x86_supplement {
    use core::mem::MaybeUninit;

    use rustix::fs::{self, Mode, OFlags, CWD};
    use rustix::io::Errno;

    pub fn caller_buffer_readlinkat_raw() {
        let mut storage = [MaybeUninit::new(0xa5_u8); 32];
        let (target, untouched) = fs::readlinkat_raw(CWD, "fixture/fixed-link", &mut storage)
            .expect("the private fixed symlink must be readable");
        assert_eq!(target, b"fixed-target");
        assert!(untouched
            .iter()
            .all(|byte| unsafe { byte.assume_init() } == 0xa5));
        rustybench::black_box(target);
    }

    pub fn absent_open_error() {
        let error = fs::open(
            "fixture/proven-absent",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect_err("the private absent path must return ENOENT");
        assert_eq!(error, Errno::NOENT);
        rustybench::black_box(error.raw_os_error());
    }
}

#[rustybench::bench]
fn caller_buffer() {
    x86_supplement::caller_buffer_readlinkat_raw();
}

#[rustybench::bench]
fn missing_error() {
    x86_supplement::absent_open_error();
}

fn main() {
    rustybench::main();
}
