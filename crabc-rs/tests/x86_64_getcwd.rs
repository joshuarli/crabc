#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;
use core::mem::MaybeUninit;

#[cfg(feature = "alloc")]
use std::{
    fs,
    path::PathBuf,
    process::Command,
};

use crabc_rs::process;
use crabc_rs::Errno;

const BUFFER_CAPACITY: usize = 4096;
const UNTOUCHED: u8 = 0xa5;
#[cfg(feature = "alloc")]
const GETCWD_ALLOC_CHILD: &str = "CRABC_RS_X86_64_GETCWD_ALLOC_CHILD";

#[test]
fn x86_64_getcwd_returns_exact_current_directory_and_preserves_suffix() {
    let expected = std::env::current_dir().expect("read the test current directory");
    let expected = std::os::unix::ffi::OsStrExt::as_bytes(expected.as_os_str());

    let mut storage = [MaybeUninit::new(UNTOUCHED); BUFFER_CAPACITY];
    let (initialized, untouched) = process::getcwd(&mut storage).expect("read current directory");

    assert_eq!(initialized.len(), expected.len() + 1);
    assert_eq!(initialized.last(), Some(&0));
    let path = CStr::from_bytes_with_nul(initialized).expect("kernel returned one trailing NUL");
    assert_eq!(path.to_bytes(), expected);
    assert!(untouched
        .iter()
        .all(|byte| unsafe { byte.assume_init() } == UNTOUCHED));
}

#[test]
fn x86_64_getcwd_reports_range_for_one_byte_buffer() {
    let mut storage = [MaybeUninit::<u8>::uninit(); 1];
    match process::getcwd(&mut storage) {
        Ok(_) => panic!("a one-byte getcwd buffer must be too small"),
        Err(error) => assert_eq!(error, Errno::RANGE),
    }
}

#[test]
fn x86_64_getcwd_reports_range_for_empty_buffer() {
    let mut storage = [MaybeUninit::<u8>::uninit(); 0];
    match process::getcwd(&mut storage) {
        Ok(_) => panic!("a zero-byte getcwd buffer must not succeed"),
        Err(error) => assert_eq!(error, Errno::RANGE),
    }
}

#[cfg(feature = "alloc")]
#[test]
fn x86_64_getcwd_alloc_retries_for_a_path_beyond_the_stack_buffer() {
    if std::env::var_os(GETCWD_ALLOC_CHILD).is_some() {
        getcwd_alloc_long_path_child();
        return;
    }

    let directory = LongCwdDirectory::new();
    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_getcwd_alloc_retries_for_a_path_beyond_the_stack_buffer",
            "--nocapture",
        ])
        .env(GETCWD_ALLOC_CHILD, "1")
        .current_dir(directory.deep_path())
        .output()
        .expect("run isolated long-current-directory child");
    assert!(
        output.status.success(),
        "isolated getcwd_alloc child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(feature = "alloc")]
fn getcwd_alloc_long_path_child() {
    let expected = std::env::current_dir().expect("read the child current directory");
    let expected = std::os::unix::ffi::OsStrExt::as_bytes(expected.as_os_str());
    assert!(
        expected.len() + 1 > crabc_rs::fs::SMALL_PATH_BUFFER_SIZE,
        "the test directory must force getcwd_alloc to retry after ERANGE",
    );

    let observed = process::getcwd_alloc(Vec::with_capacity(1))
        .expect("grow a caller-owned buffer after the direct getcwd ERANGE");
    assert_eq!(observed.as_bytes(), expected);
    assert_eq!(observed.as_bytes_with_nul().last(), Some(&0));
}

#[cfg(feature = "alloc")]
struct LongCwdDirectory {
    root: PathBuf,
    deep: PathBuf,
}

#[cfg(feature = "alloc")]
impl LongCwdDirectory {
    fn new() -> Self {
        let process_id = std::process::id();
        let root = (0_u32..1024)
            .map(|serial| {
                std::env::temp_dir().join(format!(
                    "crabc-x86-getcwd-alloc-{process_id}-{serial}"
                ))
            })
            .find_map(|candidate| match fs::create_dir(&candidate) {
                Ok(()) => Some(candidate),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => panic!("create isolated getcwd_alloc directory: {error}"),
            })
            .expect("find an unused isolated getcwd_alloc directory");
        let component = "x".repeat(96);
        let deep = root
            .join(&component)
            .join(&component)
            .join(&component);
        let directory = Self { root, deep };
        fs::create_dir_all(directory.deep_path())
            .expect("create a current directory beyond the stack buffer");
        directory
    }

    fn deep_path(&self) -> &std::path::Path {
        &self.deep
    }
}

#[cfg(feature = "alloc")]
impl Drop for LongCwdDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
