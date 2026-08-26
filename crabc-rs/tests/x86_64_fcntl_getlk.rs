#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, offset_of, size_of};
use crabc_rs::{process, BorrowedFd, Errno};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

const CHILD_LOCK_CASE: &str = "CRABC_X86_FCNTL_GETLK_CHILD_LOCK";
const CHILD_LOCK_PATH: &str = "CRABC_X86_FCNTL_GETLK_PATH";

struct RemoveFileOnDrop(std::path::PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn fixture_file() -> (std::fs::File, RemoveFileOnDrop) {
    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    path.push(format!("crabc-x86-fcntl-getlk-{}-{nonce}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create unique lock-query fixture");
    (file, RemoveFileOnDrop(path))
}

fn child_record_lock_case() -> bool {
    if std::env::var_os(CHILD_LOCK_CASE).is_none() {
        return false;
    }

    let path = std::env::var_os(CHILD_LOCK_PATH).expect("child lock path");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open child lock fixture");
    let mut held = crabc_core::process::KernelFlock {
        l_type: process::FlockType::WriteLock as i16,
        l_whence: process::FlockOffsetType::Set as i16,
        l_start: 128,
        l_len: 37,
        l_pid: 0,
    };
    // SAFETY: `held` is a complete writable Linux/x86-64 `struct flock`
    // record for the direct F_SETLK operation. The child keeps `file` open
    // while the parent performs its conflicting F_GETLK query.
    unsafe {
        crabc_core::io::fcntl_raw(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            6,
            core::ptr::addr_of_mut!(held).cast(),
        )
    }
    .expect("acquire child record lock");

    std::io::stdout()
        .write_all(b"CRABC_FCNTL_READY\n")
        .and_then(|_| std::io::stdout().flush())
        .expect("announce child record lock");
    let mut release = [0; 1];
    let _ = std::io::stdin().read(&mut release);

    held.l_type = process::FlockType::Unlocked as i16;
    // SAFETY: `held` remains a complete writable record and the child still
    // owns the descriptor until this unlock operation completes.
    unsafe {
        crabc_core::io::fcntl_raw(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            6,
            core::ptr::addr_of_mut!(held).cast(),
        )
    }
    .expect("release child record lock");
    true
}

#[test]
fn x86_64_fcntl_getlk_matches_the_linux_flock_record_and_unlocked_query() {
    assert_eq!(size_of::<crabc_core::process::KernelFlock>(), 32);
    assert_eq!(align_of::<crabc_core::process::KernelFlock>(), 8);
    assert_eq!(offset_of!(crabc_core::process::KernelFlock, l_type), 0);
    assert_eq!(offset_of!(crabc_core::process::KernelFlock, l_whence), 2);
    assert_eq!(offset_of!(crabc_core::process::KernelFlock, l_start), 8);
    assert_eq!(offset_of!(crabc_core::process::KernelFlock, l_len), 16);
    assert_eq!(offset_of!(crabc_core::process::KernelFlock, l_pid), 24);

    let (file, _cleanup) = fixture_file();
    // SAFETY: `file` remains open and is not closed through another alias for
    // the duration of this immediate borrowed descriptor observation.
    let fd = unsafe { BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(&file)) };
    let query = process::Flock::from(process::FlockType::WriteLock);
    assert_eq!(
        process::fcntl_getlk(fd, &query).expect("query unlocked x86 record"),
        None
    );
}

#[test]
fn x86_64_fcntl_getlk_reports_a_conflicting_record_lock() {
    if child_record_lock_case() {
        return;
    }

    let (file, _cleanup) = fixture_file();
    // SAFETY: `file` remains open and is not closed through another alias for
    // the duration of this immediate borrowed descriptor observation.
    let fd = unsafe { BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(&file)) };
    let mut child = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_fcntl_getlk_reports_a_conflicting_record_lock",
            "--nocapture",
        ])
        .env(CHILD_LOCK_CASE, "1")
        .env(CHILD_LOCK_PATH, _cleanup.0.as_os_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn isolated record-lock owner");

    let mut child_stdout = child.stdout.take().expect("child lock stdout");
    let ready_marker = b"CRABC_FCNTL_READY\n";
    let mut child_output = Vec::new();
    loop {
        let mut byte = [0; 1];
        child_stdout
            .read_exact(&mut byte)
            .expect("wait for child record lock");
        child_output.push(byte[0]);
        if child_output.ends_with(ready_marker) {
            break;
        }
        assert!(
            child_output.len() < 16 * 1024,
            "child lock owner did not announce readiness"
        );
    }

    let query = process::Flock {
        start: 128,
        length: 37,
        pid: None,
        typ: process::FlockType::WriteLock,
        offset_type: process::FlockOffsetType::Set,
    };
    let observed = process::fcntl_getlk(fd, &query)
        .expect("query conflicting x86 record")
        .expect("child record lock must conflict");
    assert_eq!(observed.typ, process::FlockType::WriteLock);
    assert_eq!(observed.offset_type, process::FlockOffsetType::Set);
    assert_eq!(observed.start, 128);
    assert_eq!(observed.length, 37);
    assert_eq!(
        observed.pid,
        Some(process::Pid::from_raw(i32::try_from(child.id()).expect("child PID fits i32"))
            .expect("child PID is positive")),
    );

    drop(child.stdin.take().expect("child lock stdin"));
    assert!(child.wait().expect("wait for record-lock owner").success());
}

#[test]
fn x86_64_fcntl_getlk_rejects_undefined_input_and_unrepresentable_offsets() {
    let (file, _cleanup) = fixture_file();
    // SAFETY: `file` remains open and is not closed through another alias for
    // the duration of these immediate borrowed descriptor observations.
    let fd = unsafe { BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(&file)) };

    let unlocked = process::Flock::from(process::FlockType::Unlocked);
    assert_eq!(
        process::fcntl_getlk(fd, &unlocked).err(),
        Some(Errno::INVAL)
    );

    let oversized = process::Flock {
        start: u64::MAX,
        length: 0,
        pid: None,
        typ: process::FlockType::ReadLock,
        offset_type: process::FlockOffsetType::Set,
    };
    assert_eq!(
        process::fcntl_getlk(fd, &oversized).err(),
        Some(Errno::RANGE)
    );
}
