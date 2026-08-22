use crabc_rs::time::{wall_clock, UnixTime, NANOS_PER_SECOND};

#[test]
fn native_wall_clock_is_a_normalized_unix_epoch_value() {
    let now = wall_clock().expect("Linux gettimeofday wall-clock query");

    assert!(now >= UnixTime::UNIX_EPOCH);
    assert!(now.nanoseconds() < NANOS_PER_SECOND);
    assert_eq!(now.nanoseconds() % 1_000, 0, "gettimeofday precision is microseconds");
}

#[test]
fn unix_time_constructor_keeps_epoch_and_subsecond_ranges_explicit() {
    let before_epoch = UnixTime::from_parts(-1, NANOS_PER_SECOND - 1)
        .expect("signed seconds allow pre-epoch values");
    assert_eq!(before_epoch.seconds(), -1);
    assert_eq!(before_epoch.nanoseconds(), 999_999_999);

    assert_eq!(UnixTime::from_parts(0, 0), Some(UnixTime::UNIX_EPOCH));
    assert!(UnixTime::from_parts(0, NANOS_PER_SECOND).is_none());
}
