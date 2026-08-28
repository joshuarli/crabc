#![cfg(target_arch = "x86_64")]

use crabc_rs::time::{self, CalendarTime, UnixTime, NANOS_PER_SECOND};

#[test]
fn x86_64_direct_wall_clock_is_microsecond_normalized_and_utc_reversible() {
    let now = time::wall_clock().expect("direct Linux gettimeofday wall-clock query");

    assert!(now.nanoseconds() < NANOS_PER_SECOND);
    assert_eq!(
        now.nanoseconds() % 1_000,
        0,
        "gettimeofday has microsecond precision"
    );
    let utc = time::gmtime(now.seconds()).expect("current UTC seconds fit native calendar range");
    assert_eq!(
        time::timegm(&utc).expect("normalized UTC calendar is reversible"),
        now.seconds(),
    );
}

#[test]
fn x86_64_civil_values_keep_invalid_states_out_of_the_public_api() {
    assert!(UnixTime::from_parts(-1, NANOS_PER_SECOND - 1).is_some());
    assert!(UnixTime::from_parts(0, NANOS_PER_SECOND).is_none());
    assert_eq!(
        CalendarTime::from_ymdhms(2100, 2, 29, 0, 0, 0),
        Err(crabc_rs::Errno::INVAL),
    );
    let leap = CalendarTime::from_ymdhms(2400, 2, 29, 23, 59, 59)
        .expect("400-year Gregorian leap day is valid");
    assert_eq!(
        time::timegm(&leap).expect("strict leap-day calendar is representable"),
        13_574_649_599,
    );
}
