use core::sync::atomic::{AtomicUsize, Ordering};
use std::fs::{self as stdfs, OpenOptions};
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};

use crabc_rs::fs::{self, ChownFlags, Mode, OFlags};
use crabc_rs::process;
use crabc_rs::Errno;

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    paths: [PathBuf; 2],
}

impl Fixture {
    fn new(label: &str) -> Self {
        let serial = SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stem = format!(
            "/tmp/crabc-rs-m10-ownership-{label}-{}-{serial}",
            std::process::id(),
        );
        Self {
            paths: [PathBuf::from(&stem), PathBuf::from(format!("{stem}-link"))],
        }
    }

    fn path(&self) -> &Path {
        &self.paths[0]
    }

    fn link(&self) -> &Path {
        &self.paths[1]
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Cleanup is best effort so it also runs when an assertion panics.
        for path in &self.paths {
            let _ = stdfs::remove_file(path);
        }
    }
}

fn create_file(path: &Path) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create disposable ownership fixture");
}

#[test]
fn ownership_operations_accept_the_callers_existing_ids() {
    let fixture = Fixture::new("regular");
    create_file(fixture.path());

    let owner = process::geteuid();
    let group = process::getegid();
    let initial = stdfs::metadata(fixture.path()).expect("read fixture metadata");
    assert_eq!(initial.uid(), owner.as_raw());
    assert_eq!(initial.gid(), group.as_raw());

    fs::chown(fixture.path(), Some(owner), Some(group)).expect("chown existing ownership");
    let after_chown = stdfs::metadata(fixture.path()).expect("read chown metadata");
    assert_eq!(after_chown.uid(), owner.as_raw());
    assert_eq!(after_chown.gid(), group.as_raw());

    let descriptor = fs::open(
        fixture.path(),
        OFlags::RDWR | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open ownership fixture");
    fs::fchown(&descriptor, Some(owner), Some(group)).expect("fchown existing ownership");

    // `None` is the only no-change spelling. This still exercises the kernel
    // sentinel while leaving the unprivileged fixture owned by its creator.
    fs::chownat(
        fs::CWD,
        fixture.path(),
        None,
        None,
        ChownFlags::empty(),
    )
    .expect("chownat no-change ownership");
    let after_no_change = stdfs::metadata(fixture.path()).expect("read no-change metadata");
    assert_eq!(after_no_change.uid(), owner.as_raw());
    assert_eq!(after_no_change.gid(), group.as_raw());
}

#[test]
fn lchown_uses_the_ownership_specific_nofollow_flag() {
    let fixture = Fixture::new("symlink");
    create_file(fixture.path());
    symlink(fixture.path(), fixture.link()).expect("create ownership symlink fixture");

    let owner = process::geteuid();
    let group = process::getegid();
    match fs::lchown(fixture.link(), Some(owner), Some(group)) {
        Ok(()) => {}
        Err(Errno::OPNOTSUPP | Errno::PERM | Errno::ROFS) => return,
        Err(error) => panic!("lchown existing symlink ownership: {error}"),
    }

    let link_metadata = stdfs::symlink_metadata(fixture.link()).expect("read symlink metadata");
    assert!(link_metadata.file_type().is_symlink());
    assert_eq!(link_metadata.uid(), owner.as_raw());
    assert_eq!(link_metadata.gid(), group.as_raw());

    // The target remains a regular file; `lchown` did not dereference it.
    let target_metadata = stdfs::metadata(fixture.path()).expect("read symlink target metadata");
    assert!(target_metadata.file_type().is_file());
    assert_eq!(target_metadata.uid(), owner.as_raw());
    assert_eq!(target_metadata.gid(), group.as_raw());
}

#[test]
fn ownership_ids_and_flags_reject_ambiguous_or_unrelated_raw_bits() {
    let invalid_owner = process::Uid::from_raw(u32::MAX);
    let invalid_group = process::Gid::from_raw(u32::MAX);

    assert_eq!(
        fs::chown("/crabc-rs-m10-ownership-no-such-entry", Some(invalid_owner), None),
        Err(Errno::INVAL),
        "a raw all-ones UID must not silently become the no-change sentinel",
    );
    assert_eq!(
        fs::chown("/crabc-rs-m10-ownership-no-such-entry", None, Some(invalid_group)),
        Err(Errno::INVAL),
        "a raw all-ones GID must not silently become the no-change sentinel",
    );

    let unrelated = ChownFlags::from_bits_retain(0x200);
    assert_eq!(
        fs::chownat(
            fs::CWD,
            "/crabc-rs-m10-ownership-no-such-entry",
            None,
            None,
            unrelated,
        ),
        Err(Errno::INVAL),
        "unrelated AT_* flags must not cross the ownership API",
    );
}
