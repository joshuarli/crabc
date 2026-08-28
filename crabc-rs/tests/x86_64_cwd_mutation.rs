#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;
use core::mem::MaybeUninit;

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;

use crabc_rs::fs::{self, Mode, OFlags};
use crabc_rs::process;
use crabc_rs::Errno;

const CWD_MUTATION_CHILD: &str = "CRABC_RS_X86_64_CWD_MUTATION_CHILD";

/// Runs each CWD mutation inside a separate test-process child. CWD state is
/// process-global Linux state, so this makes a failing assertion unable to
/// perturb the parent harness or its other test binaries.
#[test]
fn x86_64_cwd_mutation_is_child_contained_and_descriptor_restorable() {
    if std::env::var_os(CWD_MUTATION_CHILD).is_some() {
        cwd_mutation_child();
        return;
    }

    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_cwd_mutation_is_child_contained_and_descriptor_restorable",
            "--nocapture",
        ])
        .env(CWD_MUTATION_CHILD, "1")
        .output()
        .expect("run isolated CWD mutation child");
    assert!(
        output.status.success(),
        "isolated CWD mutation child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn cwd_mutation_child() {
    let before = cwd_bytes();
    let fixture = CwdFixture::new();
    let original = fs::open(
        b".".as_slice(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open entry current-directory descriptor");
    let target = fs::open(
        fixture.target.as_os_str().as_bytes(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open target-directory descriptor");
    let regular = fs::open(
        fixture.file.as_os_str().as_bytes(),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open regular-file descriptor");

    process::chdir(fixture.target.as_os_str().as_bytes()).expect("change into target directory");
    assert_eq!(cwd_bytes(), fixture.target.as_os_str().as_bytes());

    let mut canonical = [MaybeUninit::<u8>::uninit(); fs::CANONICAL_PATH_MAX];
    let (canonical, _) = fs::canonicalize_into(b".".as_slice(), &mut canonical)
        .expect("canonicalize relative path after direct chdir");
    assert_eq!(canonical, fixture.target.as_os_str().as_bytes());

    process::fchdir(&original).expect("restore entry CWD through descriptor");
    assert_eq!(cwd_bytes(), before);
    process::fchdir(&target).expect("re-enter target CWD through descriptor");
    assert_eq!(cwd_bytes(), fixture.target.as_os_str().as_bytes());

    assert_eq!(
        process::chdir(fixture.root.join("missing").as_os_str().as_bytes()),
        Err(Errno::NOENT),
    );
    assert_eq!(
        process::chdir(fixture.file.as_os_str().as_bytes()),
        Err(Errno::NOTDIR),
    );
    assert_eq!(process::fchdir(&regular), Err(Errno::NOTDIR));
    assert_eq!(process::chdir(&b"/tmp/\0bad"[..]), Err(Errno::INVAL));

    let too_long = CString::new(vec![b'x'; fs::CANONICAL_PATH_MAX])
        .expect("construct NUL-free oversized CWD pathname");
    assert_eq!(
        process::chdir(too_long.as_c_str()),
        Err(Errno::NAMETOOLONG),
    );

    #[cfg(not(feature = "alloc"))]
    {
        let too_large_for_noalloc_path_boundary = [b'x'; fs::SMALL_PATH_BUFFER_SIZE];
        assert_eq!(
            process::chdir(&too_large_for_noalloc_path_boundary),
            Err(Errno::NAMETOOLONG),
        );
    }

    process::fchdir(&original).expect("restore entry CWD before raw EBADF check");
    assert_eq!(cwd_bytes(), before);

    let closed = regular.into_raw_fd();
    crabc_core::io::close(closed).expect("close raw fchdir EBADF fixture");
    // A safe `AsFd` cannot outlive an open descriptor. Verify the same direct
    // core seam after close instead of constructing an invalid borrowed FD.
    assert_eq!(crabc_core::process::fchdir(closed), Err(Errno::BADF));
}

fn cwd_bytes() -> Vec<u8> {
    let mut storage = [MaybeUninit::<u8>::uninit(); fs::CANONICAL_PATH_MAX];
    let (initialized, _) = process::getcwd(&mut storage).expect("read current directory");
    CStr::from_bytes_with_nul(initialized)
        .expect("direct getcwd result has one trailing NUL")
        .to_bytes()
        .to_vec()
}

struct CwdFixture {
    root: PathBuf,
    target: PathBuf,
    file: PathBuf,
}

impl CwdFixture {
    fn new() -> Self {
        let root = fresh_fixture_root();
        let target = root.join("target");
        let file = root.join("regular");
        std::fs::create_dir(&target).expect("create CWD mutation target");
        std::fs::write(&file, b"regular CWD mutation fixture")
            .expect("write CWD mutation regular file");
        Self { root, target, file }
    }
}

impl Drop for CwdFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
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
            "crabc-x86-cwd-mutation-{process_id}-{nonce}-{serial}"
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create CWD mutation fixture root: {error}"),
        }
    }

    panic!("find an unused CWD mutation fixture root")
}
