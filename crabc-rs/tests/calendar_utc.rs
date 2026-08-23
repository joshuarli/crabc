use crabc_rs::time::{self, CalendarTime};

#[test]
fn gmtime_matches_musl_epoch_and_pre_epoch_boundaries() {
    let epoch = time::gmtime(0).expect("Unix epoch is representable");
    assert_eq!((epoch.year(), epoch.month(), epoch.day()), (1970, 1, 1));
    assert_eq!((epoch.hour(), epoch.minute(), epoch.second()), (0, 0, 0));
    assert_eq!((epoch.weekday(), epoch.yearday()), (4, 0));

    let before = time::gmtime(-1).expect("one second before epoch is representable");
    assert_eq!(
        (before.year(), before.month(), before.day()),
        (1969, 12, 31)
    );
    assert_eq!(
        (before.hour(), before.minute(), before.second()),
        (23, 59, 59)
    );
    assert_eq!((before.weekday(), before.yearday()), (3, 364));
}

#[test]
fn leap_day_round_trips_through_timegm() {
    let leap = time::gmtime(951_827_696).expect("2000 leap day is representable");
    assert_eq!(
        (
            leap.year(),
            leap.month(),
            leap.day(),
            leap.hour(),
            leap.minute(),
            leap.second(),
            leap.weekday(),
            leap.yearday(),
        ),
        (2000, 2, 29, 12, 34, 56, 2, 59),
    );
    assert_eq!(
        time::timegm(&leap).expect("normalized calendar value"),
        951_827_696
    );

    let constructed = CalendarTime::from_ymdhms(2024, 2, 29, 12, 34, 56).expect("valid leap day");
    assert_eq!(
        time::timegm(&constructed).expect("normalized calendar value"),
        1_709_210_096
    );
}

#[test]
fn calendar_cycle_boundaries_match_musls_gregorian_anchors() {
    let anchors = [
        (-2_208_988_800_i64, (1900, 1, 1, 1, 0)),
        (-5_359_564_800_i64, (1800, 3, 1, 6, 59)),
        (4_107_542_400_i64, (2100, 3, 1, 1, 59)),
        (13_574_649_600_i64, (2400, 3, 1, 3, 60)),
    ];
    for (seconds, (year, month, day, weekday, yearday)) in anchors {
        let value = time::gmtime(seconds).expect("Gregorian anchor is representable");
        assert_eq!(
            (
                value.year(),
                value.month(),
                value.day(),
                value.weekday(),
                value.yearday()
            ),
            (year, month, day, weekday, yearday),
        );
        assert_eq!(time::timegm(&value).expect("anchor inverse"), seconds);
    }
}

#[test]
fn calendar_constructor_rejects_invalid_states_and_unrepresentable_years() {
    assert_eq!(
        CalendarTime::from_ymdhms(1900, 2, 29, 0, 0, 0),
        Err(crabc_rs::Errno::INVAL),
    );
    assert_eq!(
        CalendarTime::from_ymdhms(2024, 13, 1, 0, 0, 0),
        Err(crabc_rs::Errno::INVAL),
    );
    assert_eq!(time::gmtime(i64::MAX), Err(crabc_rs::Errno::RANGE));
}

#[test]
fn difftime_does_not_overflow_signed_time_arithmetic() {
    let difference = time::difftime(i64::MAX, i64::MIN);
    assert!(difference.is_finite());
    assert_eq!(time::difftime(42, 17), 25.0);
    assert_eq!(time::difftime(17, 42), -25.0);
}

#[test]
fn time_reads_a_current_second_from_the_direct_clock() {
    let before = time::wall_clock().expect("wall clock query").seconds();
    let current = time::time().expect("clock realtime query");
    let after = time::wall_clock().expect("wall clock query").seconds();
    assert!((before..=after).contains(&current));
}
