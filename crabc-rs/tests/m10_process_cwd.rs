use crabc_rs::fs::{self, Mode, OFlags};
use crabc_rs::process;
use crabc_rs::{Errno, OwnedFd, Result};

/// Owns a descriptor for the entry CWD and restores it during unwinding.
///
/// Linux's CWD is process-global, so this guard is test hygiene rather than
/// an isolation primitive: production callers still need to coordinate all
/// concurrent pathname work around `process::chdir`/`fchdir`.
struct CwdGuard {
    original: OwnedFd,
}

impl CwdGuard {
    fn capture() -> Result<Self> {
        let original = fs::open(
            b".".as_slice(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { original })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = process::fchdir(&self.original);
    }
}

fn cwd_bytes() -> Vec<u8> {
    process::getcwd_alloc(Vec::new())
        .expect("getcwd")
        .as_bytes()
        .to_vec()
}

#[test]
fn chdir_and_fchdir_restore_process_cwd_after_failure() {
    let before = cwd_bytes();

    // Returning an error drops the guard while the CWD is still /tmp. Its
    // owned descriptor makes restoration independent of the pathname used to
    // enter the temporary directory, and Drop also runs if an assertion
    // above panics.
    let result = (|| -> Result<()> {
        let guard = CwdGuard::capture()?;
        let target = fs::open(
            b"/tmp".as_slice(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        process::chdir("/tmp")?;
        assert_eq!(cwd_bytes(), b"/tmp");

        process::fchdir(&guard.original)?;
        assert_eq!(cwd_bytes(), before);

        process::fchdir(&target)?;
        assert_eq!(cwd_bytes(), b"/tmp");

        // Force the fallible path while the process is away from its entry
        // directory. CwdGuard must restore the original descriptor on return.
        assert_eq!(process::chdir("/crabc-rs-m10-cwd-does-not-exist"), Err(Errno::NOENT));
        Err(Errno::IO)
    })();

    assert_eq!(result, Err(Errno::IO));
    assert_eq!(cwd_bytes(), before);
}
