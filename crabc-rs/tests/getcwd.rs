use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::process;
use crabc_rs::Errno;

const BUFFER_CAPACITY: usize = 4096;

#[test]
fn getcwd_returns_a_nul_terminated_initialized_prefix() {
    let expected = std::env::current_dir().expect("read the test current directory");
    let expected = std::os::unix::ffi::OsStrExt::as_bytes(expected.as_os_str());

    let mut storage = [MaybeUninit::<u8>::uninit(); BUFFER_CAPACITY];
    let (initialized, untouched) = process::getcwd(&mut storage).expect("read current directory");

    assert_eq!(initialized.last(), Some(&0), "getcwd includes its NUL terminator");
    assert_eq!(untouched.len(), BUFFER_CAPACITY - initialized.len());
    let path = CStr::from_bytes_with_nul(initialized).expect("kernel returned one trailing NUL");
    assert_eq!(path.to_bytes(), expected);
}

#[test]
fn getcwd_reports_range_for_an_undersized_buffer() {
    // Even the root pathname needs two bytes: '/' and its terminating NUL.
    let mut storage = [MaybeUninit::<u8>::uninit(); 1];
    match process::getcwd(&mut storage) {
        Ok(_) => panic!("a one-byte getcwd buffer must be too small"),
        Err(error) => assert_eq!(error, Errno::RANGE),
    }
}
