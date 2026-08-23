use crabc_rs::time::{CalendarTime, LocalCalendar, UnixTime};
use crabc_rs::timezone::TimeZone;

fn instant(year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> UnixTime {
    let calendar = CalendarTime::from_ymdhms(year, month, day, hour, minute, second)
        .expect("test civil time is valid");
    UnixTime::from_parts(calendar.unix_seconds().expect("test civil time is representable"), 0)
        .expect("whole seconds are normalized")
}

#[test]
fn local_calendar_converts_dst_boundaries_and_copies_offset_metadata() {
    let zone = TimeZone::from_posix_tz(b"EST5EDT4,M3.2.0/2,M11.1.0/2")
        .expect("well-formed eastern POSIX rule");

    let before_start = LocalCalendar::from_unix_time(
        UnixTime::from_parts(instant(2024, 3, 10, 6, 59, 59).seconds(), 123_456_789).unwrap(),
        &zone,
    )
    .expect("local calendar before DST start");
    assert_eq!(
        (
            before_start.calendar().year(),
            before_start.calendar().month(),
            before_start.calendar().day(),
            before_start.calendar().hour(),
            before_start.calendar().minute(),
            before_start.calendar().second(),
        ),
        (2024, 3, 10, 1, 59, 59),
    );
    assert_eq!(before_start.nanoseconds(), 123_456_789);
    assert_eq!(before_start.offset().seconds_east_of_utc(), -18_000);
    assert!(!before_start.is_daylight_saving());
    assert_eq!(before_start.abbreviation(), b"EST");
    assert_eq!(
        before_start.offset_info(),
        zone.offset_at(instant(2024, 3, 10, 6, 59, 59)),
    );

    let at_start = LocalCalendar::from_unix_time(instant(2024, 3, 10, 7, 0, 0), &zone)
        .expect("local calendar at DST start");
    assert_eq!(
        (
            at_start.calendar().year(),
            at_start.calendar().month(),
            at_start.calendar().day(),
            at_start.calendar().hour(),
            at_start.calendar().minute(),
            at_start.calendar().second(),
        ),
        (2024, 3, 10, 3, 0, 0),
    );
    assert_eq!(at_start.offset().seconds_east_of_utc(), -14_400);
    assert!(at_start.is_daylight_saving());
    assert_eq!(at_start.abbreviation(), b"EDT");

    let before_end = LocalCalendar::from_unix_time(instant(2024, 11, 3, 5, 59, 59), &zone)
        .expect("local calendar before DST end");
    assert_eq!((before_end.calendar().hour(), before_end.calendar().minute()), (1, 59));
    assert!(before_end.is_daylight_saving());

    let at_end = LocalCalendar::from_unix_time(instant(2024, 11, 3, 6, 0, 0), &zone)
        .expect("local calendar at DST end");
    assert_eq!((at_end.calendar().hour(), at_end.calendar().minute()), (1, 0));
    assert_eq!(at_end.offset().seconds_east_of_utc(), -18_000);
    assert!(!at_end.is_daylight_saving());
    assert_eq!(at_end.abbreviation(), b"EST");
}

#[test]
fn local_calendar_preserves_instant_and_handles_positive_offset_day_crossing() {
    let zone = TimeZone::from_posix_tz(b"<+03>-3").expect("positive three-hour zone");
    let input = UnixTime::from_parts(instant(1970, 1, 1, 22, 30, 0).seconds(), 42).unwrap();
    let local = LocalCalendar::from_unix_time(input, &zone).expect("local calendar conversion");

    assert_eq!(local.instant(), input);
    assert_eq!(local.calendar().year(), 1970);
    assert_eq!(local.calendar().month(), 1);
    assert_eq!(local.calendar().day(), 2);
    assert_eq!(
        (local.calendar().hour(), local.calendar().minute(), local.calendar().second()),
        (1, 30, 0),
    );
    assert_eq!(local.nanoseconds(), 42);
    assert_eq!(local.offset().seconds_east_of_utc(), 10_800);
    assert!(!local.is_daylight_saving());
    assert_eq!(local.abbreviation(), b"+03");
}

#[test]
fn local_calendar_rejects_offset_adjustment_outside_calendar_range() {
    let zone = TimeZone::from_posix_tz(b"EST24").expect("24-hour offset is valid");
    let input = UnixTime::from_parts(i64::MAX, 0).unwrap();
    assert_eq!(
        LocalCalendar::from_unix_time(input, &zone),
        Err(crabc_rs::Errno::RANGE),
    );
}
