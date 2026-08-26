#![cfg(target_arch = "aarch64")]

use core::ffi::CStr;

use crabc_rs::fs::{self, Mode, OFlags, ABS, CWD};
use crabc_rs::io;
use crabc_rs::ioctl::{self, opcode, Direction, Getter};
use crabc_rs::{AsFd, AsRawFd, Errno, FromRawFd, IntoRawFd, OwnedFd};

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).expect("test paths include exactly one trailing NUL")
}

#[test]
fn errno_and_fd_traits_preserve_the_direct_ownership_contract() {
    assert_eq!(Errno::INVAL.raw_os_error(), 22);
    assert_eq!(
        Errno::from_raw_os_error(Errno::BADF.raw_os_error()),
        Errno::BADF
    );

    let owner = fs::openat(CWD, "/dev/null", OFlags::RDONLY, Mode::empty())
        .expect("path::Arg string path reaches openat directly");
    let raw = AsRawFd::as_raw_fd(&owner);
    assert_eq!(raw, owner.as_fd().as_raw_fd());

    let raw = IntoRawFd::into_raw_fd(owner);
    // SAFETY: `into_raw_fd` transferred the sole ownership of this live fd.
    let owner = unsafe { <OwnedFd as FromRawFd>::from_raw_fd(raw) };
    assert_eq!(AsRawFd::as_raw_fd(&owner), raw);

    let mut attempts = 0;
    let retried = io::retry_on_intr(|| {
        attempts += 1;
        if attempts == 1 {
            Err(Errno::INTR)
        } else {
            Ok(7)
        }
    });
    assert_eq!(retried, Ok(7));
    assert_eq!(attempts, 2);
}

#[test]
fn typed_ioctl_wrappers_use_direct_kernel_state() {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let (mut writer, reader) = UnixStream::pair().expect("create a local byte stream");
    writer
        .write_all(b"abc")
        .expect("seed deterministic readable bytes");

    assert_eq!(io::ioctl_fionread(&reader).expect("FIONREAD"), 3);
    // SAFETY: `FIONREAD` initializes one Linux C `int` at the getter pointer.
    assert_eq!(
        unsafe { ioctl::ioctl(&reader, Getter::<0x541b, i32>::new()) }
            .expect("generic typed FIONREAD"),
        3
    );
    io::ioctl_fionbio(&reader, true).expect("FIONBIO enable");
    io::ioctl_fionbio(&reader, false).expect("FIONBIO disable");
    io::ioctl_fioclex(&reader).expect("FIOCLEX");
    io::ioctl_fionclex(&reader).expect("FIONCLEX");

    // SAFETY: `-1` is passed only to syscall 29, whose kernel-defined error
    // contract accepts any integer descriptor and returns a typed error.
    let error = unsafe { crabc_core::io::ioctl_raw(-1, 0x541b, core::ptr::null_mut()) }
        .expect_err("invalid descriptor must not use C errno");
    assert_eq!(error, Errno::BADF);
}

#[test]
fn ioctl_opcode_helpers_match_the_linux_64_bit_encoding() {
    assert_eq!(opcode::none(b'T', 227), 0x54e3);
    assert_eq!(opcode::read::<u32>(b'U', 15), 0x8004_550f);
    assert_eq!(opcode::write::<i32>(b'T', 200), 0x4004_54c8);
    assert_eq!(
        opcode::from_components(Direction::ReadWrite, b'X', 119, core::mem::size_of::<i32>()),
        0xc004_5877
    );
}

#[test]
fn path_arguments_reject_interior_nuls_without_utf8_loss() {
    let invalid = fs::openat(CWD, &b"/dev\0/null"[..], OFlags::RDONLY, Mode::empty())
        .expect_err("interior NUL is rejected before the syscall");
    assert_eq!(invalid, Errno::INVAL);

    let missing = fs::openat(
        CWD,
        cstr(b"/crabc-rs-io-definitely-missing\0"),
        OFlags::RDONLY,
        Mode::empty(),
    )
    .expect_err("a borrowed C string remains accepted");
    assert_eq!(missing, Errno::NOENT);

    let absolute = fs::openat(ABS, "/dev/null", OFlags::RDONLY, Mode::empty())
        .expect("ABS permits only absolute paths");
    drop(absolute);
    let relative = fs::openat(ABS, "dev/null", OFlags::RDONLY, Mode::empty())
        .expect_err("ABS rejects a relative path through the kernel");
    assert_eq!(relative, Errno::BADF);
}
