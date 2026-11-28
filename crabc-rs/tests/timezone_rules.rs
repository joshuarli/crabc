use crabc_rs::{
    time::{CalendarTime, UnixTime},
    timezone::{TimeZone, TimeZoneError},
};

fn instant(year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> UnixTime {
    let calendar = CalendarTime::from_ymdhms(year, month, day, hour, minute, second)
        .expect("test civil time is valid");
    UnixTime::from_parts(
        calendar
            .unix_seconds()
            .expect("test civil time is representable"),
        0,
    )
    .expect("whole seconds are normalized")
}

fn push_header(bytes: &mut Vec<u8>, version: u8, counts: [i32; 6]) {
    bytes.extend_from_slice(b"TZif");
    bytes.push(version);
    bytes.extend_from_slice(&[0; 15]);
    for count in counts {
        bytes.extend_from_slice(&count.to_be_bytes());
    }
}

fn push_block(
    bytes: &mut Vec<u8>,
    wide: bool,
    transitions: &[i64],
    transition_types: &[u8],
    types: &[(i32, bool, u8)],
    abbreviations: &[u8],
    leaps: &[(i64, i32)],
) {
    for &transition in transitions {
        if wide {
            bytes.extend_from_slice(&transition.to_be_bytes());
        } else {
            bytes.extend_from_slice(&(transition as i32).to_be_bytes());
        }
    }
    bytes.extend_from_slice(transition_types);
    for &(offset, is_dst, abbreviation) in types {
        bytes.extend_from_slice(&offset.to_be_bytes());
        bytes.push(is_dst.into());
        bytes.push(abbreviation);
    }
    bytes.extend_from_slice(abbreviations);
    for &(transition, correction) in leaps {
        if wide {
            bytes.extend_from_slice(&transition.to_be_bytes());
        } else {
            bytes.extend_from_slice(&(transition as i32).to_be_bytes());
        }
        bytes.extend_from_slice(&correction.to_be_bytes());
    }
    // Standard/wall and UT/local indicator counts are both zero in these
    // synthetic files, so neither indicator array is present.
}

#[test]
fn posix_rules_reverse_offsets_and_change_at_utc_boundaries() {
    let zone = TimeZone::from_posix_tz(b"EST5EDT4,M3.2.0/2,M11.1.0/2")
        .expect("well-formed eastern POSIX rule");

    let before_start = zone.offset_at(instant(2024, 3, 10, 6, 59, 59));
    assert_eq!(before_start.offset().seconds_east_of_utc(), -18_000);
    assert!(!before_start.is_daylight_saving());
    assert_eq!(before_start.abbreviation(), b"EST");

    let at_start = zone.offset_at(instant(2024, 3, 10, 7, 0, 0));
    assert_eq!(at_start.offset().seconds_east_of_utc(), -14_400);
    assert!(at_start.is_daylight_saving());
    assert_eq!(at_start.abbreviation(), b"EDT");

    let before_end = zone.offset_at(instant(2024, 11, 3, 5, 59, 59));
    assert!(before_end.is_daylight_saving());
    let at_end = zone.offset_at(instant(2024, 11, 3, 6, 0, 0));
    assert_eq!(at_end.offset().seconds_east_of_utc(), -18_000);
    assert!(!at_end.is_daylight_saving());

    let east = TimeZone::from_posix_tz(b"<+03>-3").expect("POSIX offset syntax");
    let east_info = east.offset_at(UnixTime::UNIX_EPOCH);
    assert_eq!(east_info.offset().seconds_east_of_utc(), 10_800);
    assert_eq!(east_info.abbreviation(), b"+03");
}

fn assert_offset(zone: &TimeZone, at: UnixTime, offset: i32, daylight: bool) {
    let info = zone.offset_at(at);
    assert_eq!(info.offset().seconds_east_of_utc(), offset, "offset at {}", at.seconds());
    assert_eq!(info.is_daylight_saving(), daylight, "daylight at {}", at.seconds());
}

#[test]
fn posix_rule_start_spills_back_into_the_previous_year() {
    // The 2023 start, first Sunday of January minus 167 hours, falls on
    // 2022-12-25 01:00 UTC; the 2022 end is 2022-06-04 23:00 UTC.
    let backward = TimeZone::from_posix_tz(b"STD0DST,M1.1.0/-167,M6.1.0/0")
        .expect("negative extended transition time");
    assert_offset(&backward, instant(2022, 6, 4, 22, 59, 59), 3_600, true);
    assert_offset(&backward, instant(2022, 6, 4, 23, 0, 0), 0, false);
    assert_offset(&backward, instant(2022, 12, 25, 0, 59, 59), 0, false);
    assert_offset(&backward, instant(2022, 12, 25, 1, 0, 0), 3_600, true);
    assert_offset(&backward, instant(2022, 12, 31, 0, 0, 0), 3_600, true);
    assert_offset(&backward, instant(2023, 1, 1, 12, 0, 0), 3_600, true);
}

#[test]
fn posix_rule_end_spills_forward_into_the_next_year() {
    // The 2023 end, last Sunday of December (the 31st) plus 167 wall hours,
    // falls on 2024-01-06 22:00 UTC; the 2024 start is 2024-06-02 00:00 UTC.
    let forward = TimeZone::from_posix_tz(b"STD0DST,M6.1.0/0,M12.5.0/167")
        .expect("positive extended transition time");
    assert_offset(&forward, instant(2023, 12, 31, 12, 0, 0), 3_600, true);
    assert_offset(&forward, instant(2024, 1, 3, 0, 0, 0), 3_600, true);
    assert_offset(&forward, instant(2024, 1, 6, 21, 59, 59), 3_600, true);
    assert_offset(&forward, instant(2024, 1, 6, 22, 0, 0), 0, false);
    assert_offset(&forward, instant(2024, 6, 1, 23, 59, 59), 0, false);
    assert_offset(&forward, instant(2024, 6, 2, 0, 0, 0), 3_600, true);
}

#[test]
fn posix_southern_rule_end_spills_back_after_the_start() {
    // Southern-hemisphere order: the 2023 end, first Sunday of January minus
    // 167 wall hours at +11, falls on 2022-12-24 14:00 UTC, after the 2022
    // start on 2022-10-01 16:00 UTC.
    let southern = TimeZone::from_posix_tz(b"STD-10DST,M10.1.0/2,M1.1.0/-167")
        .expect("southern extended transition time");
    assert_offset(&southern, instant(2022, 10, 1, 15, 59, 59), 36_000, false);
    assert_offset(&southern, instant(2022, 11, 15, 0, 0, 0), 39_600, true);
    assert_offset(&southern, instant(2022, 12, 24, 13, 59, 59), 39_600, true);
    assert_offset(&southern, instant(2022, 12, 24, 14, 0, 0), 36_000, false);
    assert_offset(&southern, instant(2022, 12, 28, 12, 0, 0), 36_000, false);
}

#[test]
fn tzif_continuation_applies_transitions_that_spill_into_adjacent_years() {
    let types = [(0, false, 0)];
    let abbreviations = b"STD\0";
    let final_transition = instant(2022, 7, 1, 0, 0, 0).seconds();
    let mut bytes = Vec::new();
    push_header(&mut bytes, b'2', [0, 0, 0, 0, 1, abbreviations.len() as i32]);
    push_block(&mut bytes, false, &[], &[], &types, abbreviations, &[]);
    push_header(&mut bytes, b'2', [0, 0, 0, 1, 1, abbreviations.len() as i32]);
    push_block(&mut bytes, true, &[final_transition], &[0], &types, abbreviations, &[]);
    bytes.extend_from_slice(b"\nSTD0DST,M1.1.0/-167,M6.1.0/0\n");

    let zone = TimeZone::from_tzif(&bytes).expect("continuation agrees with the final type");
    assert_offset(&zone, instant(2022, 12, 25, 0, 59, 59), 0, false);
    assert_offset(&zone, instant(2022, 12, 31, 0, 0, 0), 3_600, true);
    assert_eq!(zone.offset_at(instant(2022, 12, 31, 0, 0, 0)).abbreviation(), b"DST");
}

#[test]
fn posix_julian_day_of_year_and_transition_times_are_distinct() {
    let julian = TimeZone::from_posix_tz(b"STD0DST,J60/0,J300/0").expect("Julian transition rules");
    assert!(!julian
        .offset_at(instant(2024, 2, 29, 23, 59, 59))
        .is_daylight_saving());
    assert!(julian
        .offset_at(instant(2024, 3, 1, 0, 0, 0))
        .is_daylight_saving());

    let day_of_year = TimeZone::from_posix_tz(b"STD0DST,59/0,300/0")
        .expect("zero-based day-of-year transition rules");
    assert!(!day_of_year
        .offset_at(instant(2024, 2, 28, 23, 59, 59))
        .is_daylight_saving());
    assert!(day_of_year
        .offset_at(instant(2024, 2, 29, 0, 0, 0))
        .is_daylight_saving());

    assert_eq!(
        TimeZone::from_posix_tz(b"EST5EDT,M3.2.0"),
        Err(TimeZoneError::InvalidPosixTz),
    );
    assert_eq!(
        TimeZone::from_posix_tz(b"EST25"),
        Err(TimeZoneError::InvalidPosixTz),
    );
    assert_eq!(
        TimeZone::from_posix_tz(b"EST24:01"),
        Err(TimeZoneError::InvalidPosixTz),
    );
    let twenty_four_hours = TimeZone::from_posix_tz(b"EST24").expect("24:00 is valid");
    assert_eq!(
        twenty_four_hours
            .offset_at(UnixTime::UNIX_EPOCH)
            .offset()
            .seconds_east_of_utc(),
        -86_400,
    );
}

#[test]
fn tzif_v1_uses_the_first_standard_type_before_its_first_transition() {
    let types = [(3_600, true, 0), (0, false, 4)];
    let abbreviations = b"DST\0STD\0";
    let mut bytes = Vec::new();
    push_header(&mut bytes, 0, [0, 0, 1, 1, 2, abbreviations.len() as i32]);
    // The transition changes to type zero (DST), but type one is the initial
    // standard type. This catches the historical "always type zero" shortcut.
    push_block(
        &mut bytes,
        false,
        &[100],
        &[0],
        &types,
        abbreviations,
        &[(50, 1)],
    );

    let zone = TimeZone::from_tzif(&bytes).expect("well-formed TZif v1");
    let before = zone.offset_at(UnixTime::from_parts(99, 0).unwrap());
    assert_eq!(before.offset().seconds_east_of_utc(), 0);
    assert_eq!(before.abbreviation(), b"STD");
    let at = zone.offset_at(UnixTime::from_parts(100, 0).unwrap());
    assert_eq!(at.offset().seconds_east_of_utc(), 3_600);
    assert_eq!(at.abbreviation(), b"DST");
}

#[test]
fn tzif_v1_allows_an_all_daylight_file_with_type_zero_as_fallback() {
    let types = [(3_600, true, 0)];
    let abbreviations = b"DST\0";
    let mut bytes = Vec::new();
    push_header(&mut bytes, 0, [0, 0, 0, 0, 1, abbreviations.len() as i32]);
    push_block(&mut bytes, false, &[], &[], &types, abbreviations, &[]);

    let zone = TimeZone::from_tzif(&bytes).expect("all-DST TZif has type-zero fallback");
    let info = zone.offset_at(UnixTime::UNIX_EPOCH);
    assert_eq!(info.offset().seconds_east_of_utc(), 3_600);
    assert!(info.is_daylight_saving());
    assert_eq!(info.abbreviation(), b"DST");
}

#[test]
fn tzif_v2_selects_its_64_bit_block_and_trailing_posix_rule() {
    let types = [(3_600, true, 0), (0, false, 4)];
    let abbreviations = b"DST\0STD\0";
    let final_transition = instant(2024, 3, 10, 7, 0, 0).seconds();
    let mut bytes = Vec::new();
    push_header(
        &mut bytes,
        b'2',
        [0, 0, 0, 1, 2, abbreviations.len() as i32],
    );
    push_block(&mut bytes, false, &[10], &[0], &types, abbreviations, &[]);
    push_header(
        &mut bytes,
        b'2',
        [0, 0, 0, 1, 2, abbreviations.len() as i32],
    );
    push_block(
        &mut bytes,
        true,
        &[final_transition],
        &[0],
        &types,
        abbreviations,
        &[],
    );
    bytes.extend_from_slice(b"\nSTD0DST,M3.2.0/2,M11.1.0/2\n");

    let zone = TimeZone::from_tzif(&bytes).expect("well-formed TZif v2");
    // The v1 block has already entered DST by this instant, while the v2
    // block has not. The 64-bit v2 data is authoritative.
    assert!(!zone
        .offset_at(UnixTime::from_parts(50, 0).unwrap())
        .is_daylight_saving());
    assert!(zone
        .offset_at(instant(2024, 3, 10, 7, 0, 0))
        .is_daylight_saving());
    assert_eq!(
        zone.offset_at(instant(2024, 11, 3, 6, 0, 0))
            .offset()
            .seconds_east_of_utc(),
        0,
    );

    let mut v3 = bytes.clone();
    v3[4] = b'3';
    // The first TZif v1 block is 25 bytes after its 44-byte header; the
    // second header's version byte follows its four-byte `TZif` magic.
    v3[73] = b'3';
    assert!(
        TimeZone::from_tzif(&v3).is_ok(),
        "TZif v3 follows the v2 layout"
    );
}

#[test]
fn tzif_rejects_truncated_indexes_abbreviations_and_leap_tables() {
    let types = [(0, false, 0)];
    let abbreviations = b"STD\0";

    let mut invalid_index = Vec::new();
    push_header(
        &mut invalid_index,
        0,
        [0, 0, 0, 1, 1, abbreviations.len() as i32],
    );
    push_block(
        &mut invalid_index,
        false,
        &[0],
        &[1],
        &types,
        abbreviations,
        &[],
    );
    assert_eq!(
        TimeZone::from_tzif(&invalid_index),
        Err(TimeZoneError::InvalidTzif)
    );

    let mut invalid_abbreviation = Vec::new();
    push_header(&mut invalid_abbreviation, 0, [0, 0, 0, 0, 1, 3]);
    push_block(
        &mut invalid_abbreviation,
        false,
        &[],
        &[],
        &types,
        b"STD",
        &[],
    );
    assert_eq!(
        TimeZone::from_tzif(&invalid_abbreviation),
        Err(TimeZoneError::InvalidTzif),
    );

    let mut invalid_leaps = Vec::new();
    push_header(
        &mut invalid_leaps,
        0,
        [0, 0, 2, 0, 1, abbreviations.len() as i32],
    );
    push_block(
        &mut invalid_leaps,
        false,
        &[],
        &[],
        &types,
        abbreviations,
        &[(10, 1), (2_419_209, 3)],
    );
    assert_eq!(
        TimeZone::from_tzif(&invalid_leaps),
        Err(TimeZoneError::InvalidTzif)
    );

    assert_eq!(
        TimeZone::from_tzif(b"TZif"),
        Err(TimeZoneError::InvalidTzif)
    );
}
