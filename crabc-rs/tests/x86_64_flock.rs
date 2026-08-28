#![cfg(target_arch = "x86_64")]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::process::{Child, ChildStdout, Command, Stdio};

use crabc_rs::{fs, io, BorrowedFd, Errno};

const CHILD_LOCK_CASE: &str = "CRABC_X86_FLOCK_CHILD_LOCK";
const CHILD_LOCK_PATH: &str = "CRABC_X86_FLOCK_PATH";
const CHILD_LOCK_READY: &[u8] = b"CRABC_X86_FLOCK_READY\n";

struct RemoveFileOnDrop(std::path::PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn flock_fixture() -> (std::fs::File, std::path::PathBuf, RemoveFileOnDrop) {
    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    path.push(format!("crabc-x86-flock-{}-{nonce}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create unique flock fixture");
    (file, path.clone(), RemoveFileOnDrop(path))
}

fn independently_open(path: &std::path::Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open independent flock fixture descriptor")
}

fn borrow_file(file: &std::fs::File) -> BorrowedFd<'_> {
    // SAFETY: `file` retains ownership of its descriptor for every immediate
    // direct-facade call using this borrowed view.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

fn child_holds_exclusive_lock() -> bool {
    if std::env::var_os(CHILD_LOCK_CASE).is_none() {
        return false;
    }

    let path = std::env::var_os(CHILD_LOCK_PATH).expect("child flock path");
    let file = independently_open(std::path::Path::new(&path));
    // The parent creates a unique, initially unlocked file before re-execing
    // this child, so this blocking form cannot wait for another test fixture.
    fs::flock(borrow_file(&file), fs::FlockOperation::LockExclusive)
        .expect("child acquire exclusive flock");
    std::io::stdout()
        .write_all(CHILD_LOCK_READY)
        .and_then(|_| std::io::stdout().flush())
        .expect("announce child flock");

    let mut release = [0; 1];
    let _ = std::io::stdin().read(&mut release);
    fs::flock(borrow_file(&file), fs::FlockOperation::Unlock)
        .expect("child release exclusive flock");
    true
}

fn spawn_child_exclusive_lock(path: &std::path::Path) -> (Child, ChildStdout) {
    let mut child = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_flock_nonblocking_contention_uses_an_independent_open_file_description",
            "--nocapture",
        ])
        .env(CHILD_LOCK_CASE, "1")
        .env(CHILD_LOCK_PATH, path.as_os_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn isolated flock owner");

    let mut child_stdout = child.stdout.take().expect("child flock stdout");
    let mut output = Vec::new();
    loop {
        let mut byte = [0; 1];
        child_stdout
            .read_exact(&mut byte)
            .expect("wait for child exclusive flock");
        output.push(byte[0]);
        if output.ends_with(CHILD_LOCK_READY) {
            break;
        }
        assert!(
            output.len() < 16 * 1024,
            "child flock owner did not announce readiness"
        );
    }
    // Keep the pipe's read end alive until the child test harness has emitted
    // its own result after the parent releases it.
    (child, child_stdout)
}

#[test]
fn x86_64_flock_exposes_the_linux_operation_values() {
    assert_eq!(fs::FlockOperation::LockShared as u32, 0x01);
    assert_eq!(fs::FlockOperation::LockExclusive as u32, 0x02);
    assert_eq!(fs::FlockOperation::Unlock as u32, 0x08);
    assert_eq!(fs::FlockOperation::NonBlockingLockShared as u32, 0x05);
    assert_eq!(fs::FlockOperation::NonBlockingLockExclusive as u32, 0x06);
    assert_eq!(fs::FlockOperation::NonBlockingUnlock as u32, 0x0c);
}

#[test]
fn x86_64_flock_shares_duplicates_and_allows_independent_shared_locks() {
    let (first, path, _cleanup) = flock_fixture();
    let second = independently_open(&path);
    let contender = independently_open(&path);

    fs::flock(borrow_file(&first), fs::FlockOperation::NonBlockingLockShared)
        .expect("acquire first shared flock");
    let duplicate = io::dup(borrow_file(&first)).expect("duplicate first flock descriptor");
    fs::flock(&duplicate, fs::FlockOperation::NonBlockingLockShared)
        .expect("duplicate shares first open file description flock");
    fs::flock(borrow_file(&second), fs::FlockOperation::NonBlockingLockShared)
        .expect("independently opened descriptor can share flock");

    // Releasing through the duplicate must release the lock associated with
    // `first`'s open file description, not merely the duplicate descriptor.
    fs::flock(&duplicate, fs::FlockOperation::NonBlockingUnlock)
        .expect("release first flock through duplicate");
    fs::flock(borrow_file(&second), fs::FlockOperation::NonBlockingUnlock)
        .expect("release independent shared flock");
    fs::flock(
        borrow_file(&contender),
        fs::FlockOperation::NonBlockingLockExclusive,
    )
        .expect("exclusive flock after both shared open descriptions unlock");
    fs::flock(borrow_file(&contender), fs::FlockOperation::Unlock)
        .expect("release reacquired exclusive flock");
}

#[test]
fn x86_64_flock_nonblocking_contention_uses_an_independent_open_file_description() {
    if child_holds_exclusive_lock() {
        return;
    }

    let (file, path, _cleanup) = flock_fixture();
    let (mut child, _child_stdout) = spawn_child_exclusive_lock(&path);

    assert_eq!(
        fs::flock(
            borrow_file(&file),
            fs::FlockOperation::NonBlockingLockExclusive,
        ),
        Err(Errno::WOULDBLOCK),
        "a separately opened child descriptor must contend without blocking",
    );

    drop(child.stdin.take().expect("child flock stdin"));
    assert!(
        child.wait().expect("wait for child flock owner").success(),
        "child must release its exclusive flock before exit",
    );

    fs::flock(
        borrow_file(&file),
        fs::FlockOperation::NonBlockingLockExclusive,
    )
        .expect("reacquire exclusive flock after child release");
    fs::flock(borrow_file(&file), fs::FlockOperation::Unlock)
        .expect("release reacquired exclusive flock");
}

#[test]
fn x86_64_flock_raw_invalid_operation_and_closed_descriptor_errors_are_direct() {
    let (file, _path, _cleanup) = flock_fixture();
    assert_eq!(
        crabc_core::fs::flock(file.as_raw_fd(), 0),
        Err(Errno::INVAL),
        "a raw invalid flock operation must reach Linux",
    );

    let raw = file.into_raw_fd();
    crabc_core::io::close(raw).expect("close flock EBADF fixture");
    // A safe `AsFd` input cannot describe a closed descriptor. Exercise the
    // shared raw seam after close rather than construct an invalid borrow.
    assert_eq!(
        crabc_core::fs::flock(
            raw,
            fs::FlockOperation::NonBlockingLockExclusive as u32,
        ),
        Err(Errno::BADF),
    );
}
