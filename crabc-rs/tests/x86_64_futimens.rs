#![cfg(target_arch = "x86_64")]

use core::cell::Cell;
use core::mem::{align_of, size_of};

use crabc_rs::fs::{self, Timeval, Timespec, Timestamps, UTIME_NOW, UTIME_OMIT};
use crabc_rs::time::{self, ClockId};
use crabc_rs::{AsFd, BorrowedFd, Errno, OwnedFd};

// Filesystems may store timestamps at a coarser resolution than the realtime
// clock, and realtime can be adjusted between the surrounding observations.
const CURRENT_TIME_TOLERANCE_SECONDS: i64 = 2;

fn timestamp_fixture() -> OwnedFd {
    fs::memfd_create("crabc-x86-64-futimens", fs::MemfdFlags::CLOEXEC)
        .expect("create timestamp fixture")
}

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

#[test]
fn x86_64_futimens_uses_the_kernel_timespec_layout_and_sentinels() {
    assert_eq!(size_of::<Timespec>(), 16);
    assert_eq!(align_of::<Timespec>(), 8);
    assert_eq!(size_of::<Timestamps>(), 32);
    assert_eq!(align_of::<Timestamps>(), 8);
    assert_eq!(size_of::<Timeval>(), 16);
    assert_eq!(align_of::<Timeval>(), 8);

    let file = timestamp_fixture();
    let explicit = Timestamps {
        last_access: Timespec {
            tv_sec: 41,
            tv_nsec: 123_456_789,
        },
        last_modification: Timespec {
            tv_sec: 42,
            tv_nsec: 987_654_321,
        },
    };
    fs::futimens(&file, &explicit).expect("set explicit descriptor timestamps");

    let before = fs::fstat(&file).expect("observe explicit descriptor timestamps");
    assert_eq!((before.st_atime, before.st_atime_nsec), (41, 123_456_789));
    assert_eq!((before.st_mtime, before.st_mtime_nsec), (42, 987_654_321));

    let sentinels = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        last_modification: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        },
    };
    let current_before = time::clock_gettime(ClockId::Realtime).expect("observe realtime before");
    fs::futimens(&file, &sentinels).expect("apply descriptor timestamp sentinels");
    let current_after = time::clock_gettime(ClockId::Realtime).expect("observe realtime after");

    let after = fs::fstat(&file).expect("observe descriptor timestamp sentinels");
    assert_eq!(
        (after.st_atime, after.st_atime_nsec),
        (before.st_atime, before.st_atime_nsec),
        "UTIME_OMIT must preserve the selected timestamp",
    );
    assert_current_timestamp(
        (after.st_mtime, after.st_mtime_nsec),
        current_before,
        current_after,
    );
}

#[test]
fn x86_64_futimes_converts_microseconds_and_rejects_before_borrowing() {
    let file = timestamp_fixture();
    let explicit = [
        Timeval {
            tv_sec: 61,
            tv_usec: 123_456,
        },
        Timeval {
            tv_sec: 62,
            tv_usec: 654_321,
        },
    ];
    fs::futimes(&file, Some(&explicit)).expect("set explicit microsecond timestamps");
    let before = fs::fstat(&file).expect("observe explicit microsecond timestamps");
    assert_times(before, (61, 123_456_000), (62, 654_321_000));

    let invalid = [
        Timeval {
            tv_sec: 61,
            tv_usec: -1,
        },
        Timeval {
            tv_sec: 62,
            tv_usec: 1_000_000,
        },
    ];
    let borrowed = Cell::new(false);
    let tracking = TrackingFd {
        fd: file.as_fd(),
        borrowed: &borrowed,
    };
    assert_eq!(
        fs::futimes(tracking, Some(&invalid)),
        Err(Errno::INVAL),
        "noncanonical microseconds must fail before descriptor borrowing",
    );
    assert!(!borrowed.get());
    assert_times(
        fs::fstat(&file).expect("observe timestamp after local rejection"),
        (61, 123_456_000),
        (62, 654_321_000),
    );

    let current_before = time::clock_gettime(ClockId::Realtime).expect("observe realtime before");
    fs::futimes(&file, None).expect("set descriptor timestamps to current time");
    let current_after = time::clock_gettime(ClockId::Realtime).expect("observe realtime after");
    let current = fs::fstat(&file).expect("observe current descriptor timestamps");
    assert_current_times(current, current_before, current_after);
}

#[test]
fn x86_64_futimens_keeps_kernel_validation_and_state_atomicity_direct() {
    let file = timestamp_fixture();
    let before = Timestamps {
        last_access: Timespec {
            tv_sec: 51,
            tv_nsec: 111_222_333,
        },
        last_modification: Timespec {
            tv_sec: 52,
            tv_nsec: 444_555_666,
        },
    };
    fs::futimens(&file, &before).expect("seed descriptor timestamps");
    let observed_before = fs::fstat(&file).expect("observe seed timestamps");

    let invalid = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        },
        last_modification: before.last_modification,
    };
    assert_eq!(
        fs::futimens(&file, &invalid),
        Err(Errno::INVAL),
        "the direct kernel timestamp validator must reject noncanonical nanoseconds",
    );

    let observed_after = fs::fstat(&file).expect("observe timestamps after kernel rejection");
    assert_eq!(
        (observed_after.st_atime, observed_after.st_atime_nsec),
        (observed_before.st_atime, observed_before.st_atime_nsec),
    );
    assert_eq!(
        (observed_after.st_mtime, observed_after.st_mtime_nsec),
        (observed_before.st_mtime, observed_before.st_mtime_nsec),
    );
}
