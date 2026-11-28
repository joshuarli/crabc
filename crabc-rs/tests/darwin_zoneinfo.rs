#![cfg(target_os = "macos")]
//! macOS's system zoneinfo read through the facade and parsed by the
//! explicit-rule `TimeZone` parser, checked against `/bin/date`.

use std::process::Command;

use crabc_rs::time::{CalendarTime, LocalCalendar, UnixTime};
use crabc_rs::timezone::TimeZone;
use crabc_rs::{fs, io};

const ZONEINFO: &str = "/var/db/timezone/zoneinfo";

fn read_file(path: &str) -> Vec<u8> {
    let file = fs::open(path, fs::OFlags::RDONLY | fs::OFlags::CLOEXEC, fs::Mode::empty())
        .unwrap_or_else(|error| panic!("open {path}: {error:?}"));
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0_u8; 4096];
        let count = io::read(&file, &mut chunk).unwrap_or_else(|error| panic!("read {path}: {error:?}"));
        if count == 0 {
            return bytes;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

fn instant(year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> UnixTime {
    let seconds = CalendarTime::from_ymdhms(year, month, day, hour, minute, second)
        .and_then(CalendarTime::unix_seconds)
        .expect("test civil time is representable");
    UnixTime::from_parts(seconds, 0).expect("test instant is valid")
}

/// The UTC offset `/bin/date` reports for `instant` with the zone `tz`, or
/// with `/etc/localtime` when `tz` is `None`, in seconds east of UTC.
fn date_offset(tz: Option<&str>, instant: UnixTime) -> i32 {
    let mut command = Command::new("/bin/date");
    command.args(["-r", &instant.seconds().to_string(), "+%z"]);
    match tz {
        Some(zone) => command.env("TZ", zone),
        None => command.env_remove("TZ"),
    };
    let output = command.output().expect("run /bin/date");
    assert!(output.status.success(), "date failed: {output:?}");
    let text = String::from_utf8(output.stdout).expect("date prints ASCII");
    let text = text.trim();
    let sign = if text.starts_with('-') { -1 } else { 1 };
    let hours: i32 = text[1..3].parse().expect("hour digits");
    let minutes: i32 = text[3..5].parse().expect("minute digits");
    sign * (hours * 3600 + minutes * 60)
}

fn collect_tzif_files(directory: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("list zoneinfo directory") {
        let entry = entry.expect("read zoneinfo entry");
        let kind = entry.file_type().expect("zoneinfo entry type");
        if kind.is_dir() {
            collect_tzif_files(&entry.path(), files);
        } else if kind.is_file() {
            files.push(entry.path());
        }
    }
}

#[test]
fn every_system_tzif_file_parses_and_matches_date_in_two_seasons() {
    let mut files = Vec::new();
    collect_tzif_files(std::path::Path::new(ZONEINFO), &mut files);
    files.sort();
    let winter = instant(2026, 1, 15, 12, 0, 0);
    let summer = instant(2026, 7, 15, 12, 0, 0);
    let mut parsed = 0;
    for path in &files {
        let path = path.to_str().expect("zoneinfo paths are UTF-8");
        let bytes = read_file(path);
        if !bytes.starts_with(b"TZif") {
            continue;
        }
        let zone = TimeZone::from_tzif(&bytes).unwrap_or_else(|error| panic!("parse {path}: {error:?}"));
        parsed += 1;
        let name = &path[ZONEINFO.len() + 1..];
        if parsed % 40 == 1 {
            for at in [winter, summer] {
                assert_eq!(
                    zone.offset_at(at).offset().seconds_east_of_utc(),
                    date_offset(Some(name), at),
                    "{name} at {}",
                    at.seconds(),
                );
            }
        }
    }
    assert!(parsed > 300, "only {parsed} TZif files under {ZONEINFO}");
}

#[test]
fn los_angeles_rules_switch_at_the_2026_transitions_and_continue_by_rule() {
    let zone = TimeZone::from_tzif(&read_file(&format!("{ZONEINFO}/America/Los_Angeles")))
        .expect("parse America/Los_Angeles");
    let cases = [
        (instant(2026, 3, 8, 9, 59, 59), -28_800, false, &b"PST"[..]),
        (instant(2026, 3, 8, 10, 0, 0), -25_200, true, &b"PDT"[..]),
        (instant(2026, 11, 1, 8, 59, 59), -25_200, true, &b"PDT"[..]),
        (instant(2026, 11, 1, 9, 0, 0), -28_800, false, &b"PST"[..]),
        (instant(2100, 7, 1, 0, 0, 0), -25_200, true, &b"PDT"[..]),
        (instant(1942, 6, 1, 0, 0, 0), -25_200, true, &b"PWT"[..]),
    ];
    for (at, offset, daylight, abbreviation) in cases {
        let info = zone.offset_at(at);
        assert_eq!(info.offset().seconds_east_of_utc(), offset, "offset at {}", at.seconds());
        assert_eq!(info.is_daylight_saving(), daylight, "DST at {}", at.seconds());
        assert_eq!(info.abbreviation(), abbreviation, "abbreviation at {}", at.seconds());
        assert_eq!(offset, date_offset(Some("America/Los_Angeles"), at), "date at {}", at.seconds());
    }

    let local = LocalCalendar::from_unix_time(instant(2026, 7, 4, 19, 30, 0), &zone)
        .expect("project a summer instant");
    let calendar = local.calendar();
    assert_eq!(
        (calendar.year(), calendar.month(), calendar.day(), calendar.hour(), calendar.minute()),
        (2026, 7, 4, 12, 30),
    );
    assert_eq!(local.abbreviation(), b"PDT");
}

#[test]
fn etc_localtime_parses_and_agrees_with_date() {
    let zone = TimeZone::from_tzif(&read_file("/etc/localtime")).expect("parse /etc/localtime");
    for at in [
        instant(2026, 1, 15, 12, 0, 0),
        instant(2026, 7, 15, 12, 0, 0),
        instant(2038, 1, 19, 3, 14, 8),
    ] {
        assert_eq!(
            zone.offset_at(at).offset().seconds_east_of_utc(),
            date_offset(None, at),
            "/etc/localtime at {}",
            at.seconds(),
        );
    }
}
