#![cfg(target_arch = "x86_64")]

use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;

#[cfg(not(feature = "alloc"))]
use crabc_rs::fs;
use crabc_rs::{process, Errno};

const ROOT_CHANGE_CHILD: &str = "CRABC_RS_X86_64_ROOT_CHANGE_CHILD";
const NEW_ROOT: &str = "CRABC_RS_X86_64_NEW_ROOT";
const OLD_CWD: &str = "CRABC_RS_X86_64_OLD_CWD";

/// Exercises the irreversible root transition only in a disposable test
/// process. `chroot` changes future absolute pathname resolution for every
/// thread and has no restoration operation, so the parent harness must never
/// make a successful call.
#[test]
fn x86_64_chroot_is_child_contained_and_preserves_existing_cwd() {
    if std::env::var_os(ROOT_CHANGE_CHILD).is_some() {
        chroot_child();
        return;
    }

    let fixture = RootChangeFixture::new();

    // These negative paths are safe to exercise in the shared test process:
    // neither can change its root. They also pin direct kernel errors before
    // the privileged child transition.
    let missing = fixture.workspace.join("missing");
    assert_eq!(process::chroot(missing.as_os_str().as_bytes()), Err(Errno::NOENT));
    assert_eq!(
        process::chroot(fixture.regular.as_os_str().as_bytes()),
        Err(Errno::NOTDIR),
    );
    assert_eq!(process::chroot(&b"/tmp/\0bad"[..]), Err(Errno::INVAL));

    #[cfg(not(feature = "alloc"))]
    {
        let too_large_for_noalloc_path_boundary = [b'x'; fs::SMALL_PATH_BUFFER_SIZE];
        assert_eq!(
            process::chroot(&too_large_for_noalloc_path_boundary),
            Err(Errno::NAMETOOLONG),
        );
    }

    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_chroot_is_child_contained_and_preserves_existing_cwd",
            "--nocapture",
        ])
        .env(ROOT_CHANGE_CHILD, "1")
        .env(NEW_ROOT, &fixture.new_root)
        .env(OLD_CWD, &fixture.old_cwd)
        .output()
        .expect("run isolated root-change child");
    assert!(
        output.status.success(),
        "isolated root-change child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn chroot_child() {
    let new_root = PathBuf::from(std::env::var_os(NEW_ROOT).expect("receive new root"));
    let old_cwd = PathBuf::from(std::env::var_os(OLD_CWD).expect("receive old CWD"));

    process::chdir(old_cwd.as_os_str().as_bytes())
        .expect("enter retained old CWD before root change");
    process::chroot(new_root.as_os_str().as_bytes()).expect("change root in disposable child");

    assert_eq!(
        std::fs::read("/inside-marker").expect("absolute path resolves under new root"),
        b"inside root marker",
    );
    let outside_absolute = std::fs::read("/outside-marker")
        .expect_err("absolute old-CWD marker must not resolve under new root");
    assert_eq!(outside_absolute.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(
        std::fs::read("outside-marker")
            .expect("relative path still resolves through the retained old CWD"),
        b"outside CWD marker",
    );

    assert_eq!(process::chroot("/missing"), Err(Errno::NOENT));
    assert_eq!(process::chroot("/inside-marker"), Err(Errno::NOTDIR));
}

struct RootChangeFixture {
    workspace: PathBuf,
    new_root: PathBuf,
    old_cwd: PathBuf,
    regular: PathBuf,
}

impl RootChangeFixture {
    fn new() -> Self {
        let workspace = fresh_fixture_root();
        let new_root = workspace.join("new-root");
        let old_cwd = workspace.join("old-cwd");
        let regular = workspace.join("regular");
        std::fs::create_dir(&new_root).expect("create disposable new root");
        std::fs::create_dir(&old_cwd).expect("create retained old CWD");
        std::fs::write(new_root.join("inside-marker"), b"inside root marker")
            .expect("create new-root marker");
        std::fs::write(old_cwd.join("outside-marker"), b"outside CWD marker")
            .expect("create old-CWD marker");
        std::fs::write(&regular, b"not a directory").expect("create regular path fixture");
        Self {
            workspace,
            new_root,
            old_cwd,
            regular,
        }
    }
}

impl Drop for RootChangeFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.workspace);
    }
}

fn fresh_fixture_root() -> PathBuf {
    let process_id = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();

    for serial in 0_u32..1024 {
        let candidate = std::env::temp_dir().join(format!(
            "crabc-x86-root-change-{process_id}-{nonce}-{serial}"
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create root-change fixture workspace: {error}"),
        }
    }

    panic!("find an unused root-change fixture workspace")
}
