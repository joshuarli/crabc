#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, offset_of, size_of};
use core::num::NonZeroU64;
use crabc_rs::{fs, process, BorrowedFd, Errno};
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
    // SAFETY: The child retains its open file for all immediate operations.
    let fd = unsafe { BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(&file)) };
    fs::seek(fd, fs::SeekFrom::Start(128)).expect("position child lock");
    fs::lock_from_current(fd, fs::CurrentLockOperation::LockExclusive,
        fs::CurrentLockRange::Forward(NonZeroU64::new(37).unwrap()))
        .expect("acquire child record lock");
    assert_eq!(fs::tell(fd), Ok(128));

    std::io::stdout()
        .write_all(b"CRABC_FCNTL_READY\n")
        .and_then(|_| std::io::stdout().flush())
        .expect("announce child record lock");
    let mut release = [0; 1];
    std::io::stdin().read_exact(&mut release).expect("receive unlock request");

    fs::lock_from_current(fd, fs::CurrentLockOperation::Unlock,
        fs::CurrentLockRange::Forward(NonZeroU64::new(37).unwrap()))
        .expect("release child record lock");
    std::io::stdout().write_all(b"CRABC_FCNTL_UNLOCKED\n")
        .and_then(|_| std::io::stdout().flush()).expect("announce explicit unlock");
    // Remain alive with the descriptor open until the parent has checked that
    // explicit unlock, rather than process exit or close, removed the lock.
    let _ = std::io::stdin().read(&mut release);
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

    fs::seek(fd, fs::SeekFrom::Start(140)).expect("position inside held range");
    assert_eq!(fs::lock_from_current(fd, fs::CurrentLockOperation::TestExclusive,
        fs::CurrentLockRange::ToEnd), Err(Errno::ACCESS));
    assert!(matches!(fs::lock_from_current(fd, fs::CurrentLockOperation::TryExclusive,
        fs::CurrentLockRange::Forward(NonZeroU64::new(1).unwrap())),
        Err(Errno::ACCESS) | Err(Errno::AGAIN)));
    assert!(matches!(fs::fcntl_lock(fd, fs::FlockOperation::NonBlockingLockExclusive),
        Err(Errno::ACCESS) | Err(Errno::AGAIN)));
    fs::seek(fd, fs::SeekFrom::Start(0)).expect("position outside held range");
    fs::lock_from_current(fd, fs::CurrentLockOperation::TryExclusive,
        fs::CurrentLockRange::Forward(NonZeroU64::new(128).unwrap()))
        .expect("disjoint lock does not conflict");
    fs::lock_from_current(fd, fs::CurrentLockOperation::Unlock,
        fs::CurrentLockRange::Forward(NonZeroU64::new(128).unwrap()))
        .expect("release disjoint lock");

    child.stdin.as_mut().expect("child lock stdin").write_all(b"x")
        .expect("request explicit unlock");
    let mut unlocked = [0; b"CRABC_FCNTL_UNLOCKED\n".len()];
    child_stdout.read_exact(&mut unlocked).expect("wait for explicit unlock");
    assert_eq!(&unlocked, b"CRABC_FCNTL_UNLOCKED\n");
    assert_eq!(process::fcntl_getlk(fd, &query), Ok(None));
    fs::fcntl_lock(fd, fs::FlockOperation::NonBlockingLockExclusive)
        .expect("whole-file lock succeeds after child releases its range");
    fs::fcntl_lock(fd, fs::FlockOperation::Unlock).expect("release whole-file lock");
    drop(child.stdin.take().expect("child lock stdin"));
    assert!(child.wait().expect("wait for record-lock owner").success());
}

#[test]
fn x86_64_current_record_lock_checks_ranges_without_moving_the_offset() {
    let (file, _cleanup) = fixture_file();
    // SAFETY: The file remains open throughout all borrowed operations.
    let fd = unsafe { BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(&file)) };
    fs::seek(fd, fs::SeekFrom::Start(16)).expect("position backward range");
    let backward = fs::CurrentLockRange::Backward(NonZeroU64::new(8).unwrap());
    fs::lock_from_current(fd, fs::CurrentLockOperation::TryExclusive, backward)
        .expect("acquire backward range");
    fs::lock_from_current(fd, fs::CurrentLockOperation::Unlock, backward)
        .expect("release backward range");
    assert_eq!(fs::tell(fd), Ok(16));
    assert_eq!(fs::lock_from_current(fd, fs::CurrentLockOperation::TryExclusive,
        fs::CurrentLockRange::Forward(NonZeroU64::new(i64::MAX as u64 + 1).unwrap())),
        Err(Errno::RANGE));
    assert_eq!(fs::tell(fd), Ok(16));
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
