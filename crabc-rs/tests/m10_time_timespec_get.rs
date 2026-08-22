use crabc_rs::time::{clock_gettime, timespec_get, ClockId, NANOS_PER_SECOND};

#[test]
fn timespec_get_observes_current_realtime_with_normalized_nanoseconds() {
    let before = clock_gettime(ClockId::Realtime);
    let observed = timespec_get().expect("direct realtime timespec query");
    let after = clock_gettime(ClockId::Realtime);

    assert!(observed.tv_sec > 0, "realtime must be after the Unix epoch");
    assert!((0..NANOS_PER_SECOND as i64).contains(&observed.tv_nsec));

    // Realtime may be adjusted, so this is deliberately a coarse observation
    // window rather than a monotonic ordering assertion.
    assert!(
        observed.tv_sec >= before.tv_sec.saturating_sub(1)
            && observed.tv_sec <= after.tv_sec.saturating_add(1),
        "timespec_get was not a current realtime observation: {:?} not in {:?}..{:?}",
        observed,
        before,
        after,
    );
}
