use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::fs::{self, Mode, OFlags, CWD};
use crabc_rs::io;

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes).expect("test paths include exactly one trailing NUL")
}

#[test]
fn openat_and_io_use_the_direct_typed_seam() {
    let sink = fs::openat(CWD, cstr(b"/dev/null\0"), OFlags::WRONLY, Mode::empty())
        .expect("open /dev/null through openat");
    let payload = b"crabc-rs io\n";
    assert_eq!(io::write(&sink, payload).expect("write directly"), 12,);
    drop(sink);

    #[cfg(target_os = "linux")]
    {
        let source = fs::openat(
            CWD,
            cstr(b"/proc/self/cmdline\0"),
            OFlags::RDONLY,
            Mode::empty(),
        )
        .expect("open a deterministic process-owned Linux file");
        let mut buffer = [MaybeUninit::<u8>::uninit(); 128];
        let (bytes, _) = io::read(&source, &mut buffer).expect("read directly");
        assert!(!bytes.is_empty(), "the test process has a command line");

        assert_ne!(bytes[0], 0, "the first cmdline byte is the executable path");
    }
    // Darwin has no procfs; the test executable is the deterministic
    // process-owned file, and its first word is the 64-bit Mach-O magic.
    #[cfg(target_os = "macos")]
    {
        let executable = std::env::current_exe().expect("locate the test executable");
        let source = fs::openat(CWD, executable.as_path(), OFlags::RDONLY, Mode::empty())
            .expect("open the test executable");
        let mut buffer = [MaybeUninit::<u8>::uninit(); 4];
        let (bytes, _) = io::read(&source, &mut buffer).expect("read directly");
        assert_eq!(bytes, 0xfeed_facf_u32.to_le_bytes());
    }

    let error = fs::openat(
        CWD,
        cstr(b"/crabc-rs-io-definitely-missing\0"),
        OFlags::RDONLY,
        Mode::empty(),
    )
    .expect_err("missing path returns the operation error directly");
    assert_eq!(error.raw(), 2, "ENOENT");
}
