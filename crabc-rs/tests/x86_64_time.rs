use core::convert::TryFrom;
use core::mem::{align_of, offset_of, size_of};

use crabc_rs::time::{self, ClockId, Timespec, NANOS_PER_SECOND};

#[test]
fn x86_64_timespec_record_matches_linux_wire_shape() {
    assert_eq!(size_of::<Timespec>(), 16);
    assert_eq!(align_of::<Timespec>(), 8);
    assert_eq!(offset_of!(Timespec, tv_sec), 0);
    assert_eq!(offset_of!(Timespec, tv_nsec), 8);
    assert_eq!(ClockId::Realtime as i32, 0);
    assert_eq!(ClockId::Monotonic as i32, 1);
    assert_eq!(ClockId::MonotonicRaw as i32, 4);
    assert_eq!(NANOS_PER_SECOND, 1_000_000_000);
    assert_eq!(ClockId::try_from(2), Err(crabc_rs::Errno::INVAL));
}

#[test]
fn x86_64_clock_queries_have_native_normalized_results() {
    let resolution = time::clock_getres(ClockId::Monotonic).expect("monotonic resolution");
    assert!(resolution.tv_sec >= 0);
    assert!((0..i64::from(NANOS_PER_SECOND)).contains(&resolution.tv_nsec));
    let before = time::clock_gettime(ClockId::Monotonic).expect("monotonic before");
    let after = time::clock_gettime(ClockId::Monotonic).expect("monotonic after");
    assert!((0..i64::from(NANOS_PER_SECOND)).contains(&before.tv_nsec));
    assert!((0..i64::from(NANOS_PER_SECOND)).contains(&after.tv_nsec));
    assert!((after.tv_sec, after.tv_nsec) >= (before.tv_sec, before.tv_nsec));
    let wall = time::timespec_get().expect("realtime");
    assert!(wall.tv_sec > 0);
    assert!((0..i64::from(NANOS_PER_SECOND)).contains(&wall.tv_nsec));
}
