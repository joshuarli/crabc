//! Common source fixture for the M1 direct Rust boundary.
//!
//! Both dependencies are named `api` by the Python harness. Keep this limited
//! to deliberately source-compatible Rustix/crabc-rs vocabulary; execution is
//! isolated after each backend has compiled the same source independently.

use core::ffi::CStr;
use core::mem::MaybeUninit;

use api::fs::{openat, Mode, OFlags, ABS, CWD};
use api::io::{ioctl_fioclex, ioctl_fionclex, ioctl_fionread, read, write};

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).expect("fixture paths are NUL-terminated")
}

fn main() {
    let null = openat(CWD, cstr(b"/dev/null\0"), OFlags::RDONLY, Mode::empty())
        .expect("open /dev/null");
    ioctl_fioclex(&null).expect("FIOCLEX");
    ioctl_fionclex(&null).expect("FIONCLEX");
    assert_eq!(
        ioctl_fionread(&null)
            .expect_err("FIONREAD on /dev/null is not a tty")
            .raw_os_error(),
        25
    );

    let missing = openat(
        CWD,
        cstr(b"/crabc-rs-m1-dual-backend-missing\0"),
        OFlags::RDONLY,
        Mode::empty(),
    )
    .expect_err("missing path must return the direct error");
    assert_eq!(missing.raw_os_error(), 2);

    let absolute = openat(ABS, cstr(b"/dev/null\0"), OFlags::RDONLY, Mode::empty())
        .expect("ABS accepts absolute paths");
    drop(absolute);
    assert_eq!(
        openat(ABS, cstr(b"dev/null\0"), OFlags::RDONLY, Mode::empty())
            .expect_err("ABS rejects relative paths")
            .raw_os_error(),
        9
    );

    let sink = openat(CWD, cstr(b"/dev/null\0"), OFlags::WRONLY, Mode::empty())
        .expect("open a write sink");
    assert_eq!(write(&sink, b"m1").expect("write directly"), 2);
    let source = openat(CWD, cstr(b"/proc/self/cmdline\0"), OFlags::RDONLY, Mode::empty())
        .expect("open deterministic process input");
    let mut bytes = [MaybeUninit::<u8>::uninit(); 128];
    let (initialized, _) = read(&source, &mut bytes).expect("read initialized prefix");
    assert!(!initialized.is_empty());

    println!("m1-foundation ok");
}
