use crabc_rs::time::{clock_gettime, realtime_millis, ClockId, NANOS_PER_SECOND};

#[test]
fn native_realtime_millis_is_current_and_normalized() {
    let before = clock_gettime(ClockId::Realtime);
    let observed = realtime_millis().expect("direct CLOCK_REALTIME query");
    let after = clock_gettime(ClockId::Realtime);

    // Realtime can be stepped between reads, so this remains a deliberately
    // coarse observation window rather than a monotonic-ordering assertion.
    assert!(observed.seconds() >= before.tv_sec.saturating_sub(1));
    assert!(observed.seconds() <= after.tv_sec.saturating_add(1));
    assert!(observed.seconds() > 0, "the test clock should be after 1970");
    assert!(observed.milliseconds() < 1_000);

    // When the three reads remain in one second, the millisecond observation
    // must be no later than the direct nanosecond observation that follows it.
    if before.tv_sec == after.tv_sec && after.tv_nsec >= 0 {
        assert!((observed.milliseconds() as i64) * 1_000_000 <= after.tv_nsec);
        assert!(after.tv_nsec < NANOS_PER_SECOND as i64);
    }
}
