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
    assert_eq!(ClockId::ProcessCPUTime as i32, 2);
    assert_eq!(ClockId::ThreadCPUTime as i32, 3);
    assert_eq!(ClockId::MonotonicRaw as i32, 4);
    assert_eq!(ClockId::RealtimeCoarse as i32, 5);
    assert_eq!(ClockId::MonotonicCoarse as i32, 6);
    assert_eq!(ClockId::Boottime as i32, 7);
    assert_eq!(ClockId::RealtimeAlarm as i32, 8);
    assert_eq!(ClockId::BoottimeAlarm as i32, 9);
    assert_eq!(ClockId::Tai as i32, 11);
    assert_eq!(NANOS_PER_SECOND, 1_000_000_000);
    assert_eq!(ClockId::try_from(2), Ok(ClockId::ProcessCPUTime));
    assert_eq!(ClockId::try_from(3), Ok(ClockId::ThreadCPUTime));
    assert_eq!(ClockId::try_from(10), Err(crabc_rs::Errno::INVAL));
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

#[test]
fn x86_64_realtime_millis_truncates_a_normalized_realtime_observation() {
    let before = time::clock_gettime(ClockId::Realtime).expect("realtime before");
    let observed = time::realtime_millis().expect("realtime milliseconds");
    let after = time::clock_gettime(ClockId::Realtime).expect("realtime after");

    assert!(observed.seconds() >= before.tv_sec.saturating_sub(1));
    assert!(observed.seconds() <= after.tv_sec.saturating_add(1));
    assert!(observed.milliseconds() < 1_000);
    if before.tv_sec == after.tv_sec && after.tv_nsec >= 0 {
        assert!((observed.milliseconds() as i64) * 1_000_000 <= after.tv_nsec);
    }
}

#[test]
fn x86_64_time_returns_whole_seconds_within_surrounding_realtime_reads() {
    let before = time::clock_gettime(ClockId::Realtime).expect("realtime before");
    let observed = time::time().expect("whole-second realtime query");
    let after = time::clock_gettime(ClockId::Realtime).expect("realtime after");

    // Realtime may be adjusted between reads, so allow a coarse one-second
    // window around either surrounding read while still proving that `time`
    // observes the same clock. Taking min/max also tolerates a clock step.
    let lower = before.tv_sec.min(after.tv_sec).saturating_sub(1);
    let upper = before.tv_sec.max(after.tv_sec).saturating_add(1);
    assert!((lower..=upper).contains(&observed));
}

#[test]
fn x86_64_process_cpu_time_is_a_nonnegative_duration() {
    let before = time::process_cpu_time();
    let mut checksum = 0u64;
    for value in 0..500_000u64 {
        checksum = checksum.wrapping_add(value.rotate_left((value & 31) as u32));
        std::hint::black_box(checksum);
    }
    let after = time::process_cpu_time();

    assert_ne!(checksum, 0);
    assert!(after >= before);
}
