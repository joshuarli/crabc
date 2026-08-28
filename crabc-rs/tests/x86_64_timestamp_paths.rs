#![cfg(target_arch = "x86_64")]

use core::cell::Cell;
use core::ffi::CStr;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::ffi::OsStr;
use std::fs::{self as std_fs, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use crabc_rs::fs::{
    self, AtFlags, PathArg, Timeval, Timespec, TimestampAtFlags, Timestamps, Utimbuf,
};
use crabc_rs::time::{self, ClockId};
use crabc_rs::{AsFd, BorrowedFd, Errno, Result};

const CWD_TIMESTAMP_CHILD: &str = "CRABC_RS_X86_64_TIMESTAMP_CWD_CHILD";
const CWD_TIMESTAMP_CHILD_TEST: &str =
    "x86_64_utimes_and_utime_resolve_cwd_relative_links_in_a_child";
const CWD_TIMESTAMP_SENTINEL_NAME: &str = ".crabc-x86-timestamp-child";
const CWD_TIMESTAMP_SENTINEL_CONTENTS: &[u8] = b"crabc x86 timestamp child\n";
// Filesystems may store timestamps at a coarser resolution than the realtime
// clock, and realtime can be adjusted between the surrounding observations.
const CURRENT_TIME_TOLERANCE_SECONDS: i64 = 2;
static FIXTURE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct TrackingFd<'fd> {
    fd: BorrowedFd<'fd>,
    borrowed: &'fd Cell<bool>,
}

impl AsFd for TrackingFd<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.borrowed.set(true);
        self.fd
    }
}

struct TrackingPath<'tracked> {
    converted: &'tracked Cell<bool>,
}

impl PathArg for TrackingPath<'_> {
    fn into_with_c_str<T, F>(self, _callback: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> Result<T>,
    {
        self.converted.set(true);
        Err(Errno::INVAL)
    }
}

fn borrow(file: &File) -> BorrowedFd<'_> {
    // SAFETY: Each fixture retains the standard-library descriptor owner for
    // every immediate facade call made through this borrowed descriptor.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

struct TimestampPathFixture {
    root: PathBuf,
    link: PathBuf,
    child_sentinel: PathBuf,
    directory: File,
    target: File,
}

impl TimestampPathFixture {
    fn new() -> Self {
        let process_id = std::process::id();
        let root = (0_usize..1024)
            .map(|serial| {
                let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                std::env::temp_dir().join(format!(
                    "crabc-x86-timestamp-{process_id}-{sequence}-{serial}"
                ))
            })
            .find_map(|candidate| match std_fs::create_dir(&candidate) {
                Ok(()) => Some(candidate),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => panic!("create timestamp fixture directory: {error}"),
            })
            .expect("find an unused timestamp fixture directory");
        let root = std_fs::canonicalize(root).expect("canonicalize timestamp fixture directory");
        let target_path = root.join("target");
        let target = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&target_path)
            .expect("create timestamp target");
        let link = root.join("link");
        symlink("target", &link).expect("create timestamp final symlink");
        let child_sentinel = root.join(CWD_TIMESTAMP_SENTINEL_NAME);
        std_fs::write(&child_sentinel, CWD_TIMESTAMP_SENTINEL_CONTENTS)
            .expect("create timestamp child sentinel");
        let directory = File::open(&root).expect("open timestamp fixture directory");
        Self {
            root,
            link,
            child_sentinel,
            directory,
            target,
        }
    }

    fn directory_fd(&self) -> BorrowedFd<'_> {
        borrow(&self.directory)
    }

    fn target_fd(&self) -> BorrowedFd<'_> {
        borrow(&self.target)
    }

    fn link_bytes(&self) -> &[u8] {
        self.link.as_os_str().as_bytes()
    }

    fn child_sentinel(&self) -> &Path {
        &self.child_sentinel
    }
}

impl Drop for TimestampPathFixture {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.root);
    }
}

fn assert_times(stat: fs::Stat, access: (i64, i64), modification: (i64, i64)) {
    assert_eq!((stat.st_atime, stat.st_atime_nsec), access);
    assert_eq!((stat.st_mtime, stat.st_mtime_nsec), modification);
}

fn assert_current_timestamp(
    timestamp: (i64, i64),
    before: time::Timespec,
    after: time::Timespec,
) {
    let lower = before
        .tv_sec
        .min(after.tv_sec)
        .saturating_sub(CURRENT_TIME_TOLERANCE_SECONDS);
    let upper = before
        .tv_sec
        .max(after.tv_sec)
        .saturating_add(CURRENT_TIME_TOLERANCE_SECONDS);
    assert!(
        (lower..=upper).contains(&timestamp.0),
        "timestamp seconds {} must be within the surrounding realtime window {lower}..={upper}",
        timestamp.0,
    );
    assert!(
        (0..1_000_000_000).contains(&timestamp.1),
        "timestamp nanoseconds {} must be normalized",
        timestamp.1,
    );
}

fn assert_current_times(stat: fs::Stat, before: time::Timespec, after: time::Timespec) {
    assert_current_timestamp((stat.st_atime, stat.st_atime_nsec), before, after);
    assert_current_timestamp((stat.st_mtime, stat.st_mtime_nsec), before, after);
}

fn is_timestamp_cwd_child() -> bool {
    let Some(marker) = std::env::var_os(CWD_TIMESTAMP_CHILD) else {
        return false;
    };
    let marker = PathBuf::from(marker);
    if !marker.is_absolute()
        || marker.file_name() != Some(OsStr::new(CWD_TIMESTAMP_SENTINEL_NAME))
    {
        return false;
    }
    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };
    match (marker.parent(), std_fs::read(&marker)) {
        (Some(parent), Ok(contents)) => {
            parent == cwd.as_path() && contents == CWD_TIMESTAMP_SENTINEL_CONTENTS
        }
        _ => false,
    }
}

#[test]
fn x86_64_utimensat_and_legacy_directory_wrappers_preserve_link_selection() {
    let fixture = TimestampPathFixture::new();
    let direct_follow = Timestamps {
        last_access: Timespec {
            tv_sec: 71,
            tv_nsec: 111_222_333,
        },
        last_modification: Timespec {
            tv_sec: 72,
            tv_nsec: 444_555_666,
        },
    };
    fs::utimensat(
        fixture.directory_fd(),
        "link",
        &direct_follow,
        TimestampAtFlags::empty(),
    )
    .expect("update target through directory-relative final symlink");
    assert_times(
        fs::fstat(fixture.target_fd()).expect("observe directly followed target"),
        (71, 111_222_333),
        (72, 444_555_666),
    );

    let legacy_follow = [
        Timeval {
            tv_sec: 73,
            tv_usec: 123_456,
        },
        Timeval {
            tv_sec: 74,
            tv_usec: 654_321,
        },
    ];
    fs::futimesat(fixture.directory_fd(), "link", Some(&legacy_follow))
        .expect("update target through futimesat final symlink");
    assert_times(
        fs::fstat(fixture.target_fd()).expect("observe legacy followed target"),
        (73, 123_456_000),
        (74, 654_321_000),
    );

    let direct_nofollow = Timestamps {
        last_access: Timespec {
            tv_sec: 75,
            tv_nsec: 222_333_444,
        },
        last_modification: Timespec {
            tv_sec: 76,
            tv_nsec: 555_666_777,
        },
    };
    fs::utimensat(
        fixture.directory_fd(),
        "link",
        &direct_nofollow,
        TimestampAtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("update final symlink rather than its target");
    assert_times(
        fs::statat(
            fixture.directory_fd(),
            "link",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .expect("observe nofollow link timestamps"),
        (75, 222_333_444),
        (76, 555_666_777),
    );
    assert_times(
        fs::fstat(fixture.target_fd()).expect("observe target after nofollow update"),
        (73, 123_456_000),
        (74, 654_321_000),
    );

    let legacy_nofollow = [
        Timeval {
            tv_sec: 77,
            tv_usec: 333_444,
        },
        Timeval {
            tv_sec: 78,
            tv_usec: 666_777,
        },
    ];
    fs::lutimes(fixture.link_bytes(), Some(&legacy_nofollow))
        .expect("update final symbolic link through lutimes");
    assert_times(
        fs::statat(
            fixture.directory_fd(),
            "link",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .expect("observe lutimes link timestamp"),
        (77, 333_444_000),
        (78, 666_777_000),
    );
    assert_times(
        fs::fstat(fixture.target_fd()).expect("observe target after lutimes"),
        (73, 123_456_000),
        (74, 654_321_000),
    );

    let current_before = time::clock_gettime(ClockId::Realtime).expect("observe realtime before");
    fs::futimesat(fixture.directory_fd(), "link", None)
        .expect("set followed target timestamps to current time through futimesat");
    let current_after = time::clock_gettime(ClockId::Realtime).expect("observe realtime after");
    let followed_current = fs::fstat(fixture.target_fd()).expect("observe current target timestamps");
    assert_current_times(followed_current, current_before, current_after);

    let current_before = time::clock_gettime(ClockId::Realtime).expect("observe realtime before");
    fs::lutimes(fixture.link_bytes(), None)
        .expect("set final symlink timestamps to current time through lutimes");
    let current_after = time::clock_gettime(ClockId::Realtime).expect("observe realtime after");
    let nofollow_current = fs::statat(
        fixture.directory_fd(),
        "link",
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("observe current nofollow link timestamps");
    assert_current_times(nofollow_current, current_before, current_after);

    assert_eq!(
        fs::utimensat(
            fixture.directory_fd(),
            "missing",
            &direct_follow,
            TimestampAtFlags::empty(),
        ),
        Err(Errno::NOENT),
        "missing pathname errors stay direct",
    );
}

#[test]
fn x86_64_timestamp_path_wrappers_preflight_closed_flags_and_microseconds() {
    let fixture = TimestampPathFixture::new();
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 91,
            tv_nsec: 1,
        },
        last_modification: Timespec {
            tv_sec: 92,
            tv_nsec: 2,
        },
    };
    let flag_borrowed = Cell::new(false);
    let flag_path_converted = Cell::new(false);
    let flag_tracking = TrackingFd {
        fd: fixture.directory_fd(),
        borrowed: &flag_borrowed,
    };
    assert_eq!(
        fs::utimensat(
            flag_tracking,
            TrackingPath {
                converted: &flag_path_converted,
            },
            &times,
            TimestampAtFlags::from_bits_retain(0x0000_0200),
        ),
        Err(Errno::INVAL),
        "unknown timestamp-at flags must fail locally",
    );
    assert!(
        !flag_borrowed.get() && !flag_path_converted.get(),
        "closed timestamp-at flags must reject before descriptor borrowing or path conversion",
    );

    let invalid = [
        Timeval {
            tv_sec: 93,
            tv_usec: -1,
        },
        Timeval {
            tv_sec: 94,
            tv_usec: 1_000_000,
        },
    ];
    let directory_borrowed = Cell::new(false);
    let path_converted = Cell::new(false);
    let directory_tracking = TrackingFd {
        fd: fixture.directory_fd(),
        borrowed: &directory_borrowed,
    };
    assert_eq!(
        fs::futimesat(
            directory_tracking,
            TrackingPath {
                converted: &path_converted,
            },
            Some(&invalid),
        ),
        Err(Errno::INVAL),
        "futimesat must reject noncanonical microseconds locally",
    );
    assert!(
        !directory_borrowed.get() && !path_converted.get(),
        "futimesat microsecond validation must precede descriptor borrowing and path conversion",
    );

    let lutimes_path_converted = Cell::new(false);
    assert_eq!(
        fs::lutimes(
            TrackingPath {
                converted: &lutimes_path_converted,
            },
            Some(&invalid),
        ),
        Err(Errno::INVAL),
        "lutimes must reject noncanonical microseconds locally",
    );
    assert!(
        !lutimes_path_converted.get(),
        "lutimes microsecond validation must precede path conversion",
    );

    let utimes_path_converted = Cell::new(false);
    assert_eq!(
        fs::utimes(
            TrackingPath {
                converted: &utimes_path_converted,
            },
            Some(&invalid),
        ),
        Err(Errno::INVAL),
        "utimes must reject noncanonical microseconds locally",
    );
    assert!(
        !utimes_path_converted.get(),
        "utimes microsecond validation must precede path conversion",
    );
}

#[test]
fn x86_64_utimes_and_utime_resolve_cwd_relative_links_in_a_child() {
    if is_timestamp_cwd_child() {
        timestamp_cwd_child();
        return;
    }

    let fixture = TimestampPathFixture::new();
    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            CWD_TIMESTAMP_CHILD_TEST,
            "--nocapture",
        ])
        .env(CWD_TIMESTAMP_CHILD, fixture.child_sentinel().as_os_str())
        .current_dir(&fixture.root)
        .output()
        .expect("run isolated current-directory timestamp child");
    assert!(
        output.status.success(),
        "isolated current-directory timestamp child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn x86_64_timestamp_cwd_child_ignores_unbound_inherited_marker() {
    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args(["--exact", CWD_TIMESTAMP_CHILD_TEST, "--nocapture"])
        .env(CWD_TIMESTAMP_CHILD, "1")
        .output()
        .expect("run timestamp test with an unbound inherited marker");
    assert!(
        output.status.success(),
        "unbound inherited child marker must not enter child mode: status {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn timestamp_cwd_child() {
    let target = OpenOptions::new()
        .read(true)
        .write(true)
        .open("target")
        .expect("open child timestamp target");
    let microseconds = [
        Timeval {
            tv_sec: 81,
            tv_usec: 111_222,
        },
        Timeval {
            tv_sec: 82,
            tv_usec: 333_444,
        },
    ];
    fs::utimes("link", Some(&microseconds))
        .expect("follow final symlink through current-directory utimes");
    assert_times(
        fs::fstat(borrow(&target)).expect("observe cwd-relative utimes target"),
        (81, 111_222_000),
        (82, 333_444_000),
    );

    let current_before = time::clock_gettime(ClockId::Realtime).expect("observe realtime before");
    fs::utimes("link", None).expect("set cwd-relative target timestamps to current time");
    let current_after = time::clock_gettime(ClockId::Realtime).expect("observe realtime after");
    let utimes_current = fs::fstat(borrow(&target)).expect("observe cwd-relative current time");
    assert_current_times(utimes_current, current_before, current_after);

    let seconds = Utimbuf {
        actime: 83,
        modtime: 84,
    };
    fs::utime("link", Some(&seconds))
        .expect("follow final symlink through current-directory utime");
    assert_times(
        fs::fstat(borrow(&target)).expect("observe cwd-relative utime target"),
        (83, 0),
        (84, 0),
    );

    let current_before = time::clock_gettime(ClockId::Realtime).expect("observe realtime before");
    fs::utime("link", None).expect("set cwd-relative target timestamps to current time");
    let current_after = time::clock_gettime(ClockId::Realtime).expect("observe realtime after");
    let current = fs::fstat(borrow(&target)).expect("observe cwd-relative current time");
    assert_current_times(current, current_before, current_after);
}
