//! Immutable time-zone rules supplied explicitly by the caller.
//!
//! [`TimeZone`] owns either a POSIX TZ rule or a parsed TZif file.  Looking up
//! an offset therefore has no ambient `TZ` environment, mutable process
//! timezone, C ABI call, TLS `errno`, or clock read.  The abbreviation in an
//! [`OffsetInfo`] is borrowed from that immutable rule set.
//!
//! System zoneinfo loading is deliberately deferred from this first native
//! slice.  Callers that obtain a zoneinfo-file snapshot through `crabc-rs`
//! filesystem and I/O APIs pass those bytes to [`TimeZone::from_tzif`].  A
//! future convenience loader must retain that explicit-byte/snapshot boundary;
//! it must not consult `TZ` or other process-global timezone state.

use alloc::vec::Vec;

use crate::time::UnixTime;

const SECONDS_PER_DAY: i128 = 86_400;
const MAX_OFFSET_SECONDS: i32 = 24 * 60 * 60;

/// A validated offset east of UTC.
///
/// The POSIX TZ offset grammar is reversed from this native representation:
/// `EST5` describes UTC-05:00 and is represented by `-18_000` seconds here.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcOffset {
    seconds_east_of_utc: i32,
}

impl UtcOffset {
    /// UTC, with no offset from the Unix epoch's time scale.
    pub const UTC: Self = Self {
        seconds_east_of_utc: 0,
    };

    /// Constructs an offset in the TZif/POSIX range of at most 24 hours from
    /// UTC in either direction.
    #[must_use]
    pub const fn from_seconds(seconds_east_of_utc: i32) -> Option<Self> {
        if seconds_east_of_utc >= -MAX_OFFSET_SECONDS && seconds_east_of_utc <= MAX_OFFSET_SECONDS {
            Some(Self {
                seconds_east_of_utc,
            })
        } else {
            None
        }
    }

    /// Returns this offset as signed seconds east of UTC.
    #[must_use]
    pub const fn seconds_east_of_utc(self) -> i32 {
        self.seconds_east_of_utc
    }
}

/// Offset data selected from an immutable [`TimeZone`] for one UTC instant.
///
/// The abbreviation is a byte slice because TZif abbreviations and POSIX TZ
/// names are byte-oriented system data, not guaranteed Rust UTF-8 text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffsetInfo<'a> {
    offset: UtcOffset,
    is_daylight_saving: bool,
    abbreviation: &'a [u8],
}

impl<'a> OffsetInfo<'a> {
    /// Returns the selected offset east of UTC.
    #[must_use]
    pub const fn offset(self) -> UtcOffset {
        self.offset
    }

    /// Reports whether this offset is marked as daylight-saving time.
    #[must_use]
    pub const fn is_daylight_saving(self) -> bool {
        self.is_daylight_saving
    }

    /// Returns the selected, NUL-free TZ abbreviation bytes.
    #[must_use]
    pub const fn abbreviation(self) -> &'a [u8] {
        self.abbreviation
    }
}

/// Why an explicitly supplied POSIX TZ rule or TZif byte sequence was
/// rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeZoneError {
    /// The byte sequence is not a complete POSIX TZ rule in the supported
    /// standard/DST form.
    InvalidPosixTz,
    /// The byte sequence violates the TZif v1/v2/v3 header, count, index, or
    /// bounds rules.
    InvalidTzif,
}

/// An immutable, owned set of time-zone rules.
///
/// Construct it from caller-supplied POSIX TZ or TZif bytes, then use
/// [`Self::offset_at`] for as many UTC instants as needed.  Constructing and
/// querying a zone never changes a clock or any process-wide setting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeZone {
    source: ZoneSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ZoneSource {
    Posix(PosixZone),
    Tzif(TzifZone),
}

impl TimeZone {
    /// Parses a complete POSIX TZ rule from bytes.
    ///
    /// Names can use the ordinary three-or-more-letter form or the `<...>`
    /// form used by modern zoneinfo continuations.  A daylight-saving name
    /// requires both transition rules; offset fields retain POSIX's reversed
    /// sign convention.
    pub fn from_posix_tz(bytes: &[u8]) -> Result<Self, TimeZoneError> {
        Ok(Self {
            source: ZoneSource::Posix(parse_posix_zone(bytes)?),
        })
    }

    /// Parses TZif version 1, 2, or 3 bytes supplied by the caller.
    ///
    /// Version 1 uses its signed 32-bit transition block.  Versions 2 and 3
    /// validate both their required 32-bit block and their authoritative
    /// signed 64-bit block, and apply a valid trailing POSIX rule after the
    /// final explicit transition.  Leap-second records are structurally and
    /// chronologically validated but intentionally do not alter Unix-time
    /// offset lookup.
    pub fn from_tzif(bytes: &[u8]) -> Result<Self, TimeZoneError> {
        let (first_header, after_first_header) = Header::parse(bytes)?;
        let (first_block, after_first_block) =
            parse_block(after_first_header, first_header, false)?;

        let zone = match first_header.version {
            0 => {
                if !after_first_block.is_empty() {
                    return Err(TimeZoneError::InvalidTzif);
                }
                TzifZone::from_block(first_block, None)?
            }
            b'2' | b'3' => {
                let (second_header, after_second_header) = Header::parse(after_first_block)?;
                if second_header.version != first_header.version {
                    return Err(TimeZoneError::InvalidTzif);
                }
                let (second_block, trailing) =
                    parse_block(after_second_header, second_header, true)?;
                let continuation = parse_tzif_continuation(trailing)?;
                TzifZone::from_block(second_block, continuation)?
            }
            _ => return Err(TimeZoneError::InvalidTzif),
        };

        Ok(Self {
            source: ZoneSource::Tzif(zone),
        })
    }

    /// Determines the offset rules in force at a UTC [`UnixTime`].
    ///
    /// This is a pure lookup against this instance's immutable bytes.  It
    /// does not read the current time, inspect an environment variable, or
    /// mutate global/C-library timezone state.
    #[must_use]
    pub fn offset_at(&self, instant: UnixTime) -> OffsetInfo<'_> {
        match &self.source {
            ZoneSource::Posix(zone) => zone.offset_at(instant.seconds()),
            ZoneSource::Tzif(zone) => zone.offset_at(instant.seconds()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixZone {
    standard: ZoneType,
    daylight: Option<ZoneType>,
    start: Option<TransitionRule>,
    end: Option<TransitionRule>,
}

impl PosixZone {
    fn offset_at(&self, seconds: i64) -> OffsetInfo<'_> {
        let Some(daylight) = self.daylight.as_ref() else {
            return self.info_for(&self.standard);
        };
        let start = self.start.expect("daylight rules are validated together");
        let end = self.end.expect("daylight rules are validated together");
        let year = year_from_unix_seconds(seconds);
        let start_at = transition_seconds(year, start, self.standard.offset, self.standard.offset);
        let end_at = transition_seconds(year, end, self.standard.offset, daylight.offset);
        let current = seconds as i128;
        let in_daylight = if start_at < end_at {
            current >= start_at && current < end_at
        } else {
            current >= start_at || current < end_at
        };
        if in_daylight {
            self.info_for(daylight)
        } else {
            self.info_for(&self.standard)
        }
    }

    fn info_for<'a>(&self, type_info: &'a ZoneType) -> OffsetInfo<'a> {
        OffsetInfo {
            offset: type_info.offset,
            is_daylight_saving: type_info.is_daylight_saving,
            abbreviation: type_info.abbreviation(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TzifZone {
    transitions: Vec<i64>,
    transition_types: Vec<u8>,
    types: Vec<ZoneType>,
    continuation: Option<PosixZone>,
    pre_first_type: usize,
}

impl TzifZone {
    fn from_block(
        block: TzifBlock,
        continuation: Option<PosixZone>,
    ) -> Result<Self, TimeZoneError> {
        let pre_first_type = block
            .types
            .iter()
            .position(|type_info| !type_info.is_daylight_saving)
            // TZif specifies the first non-DST type as the pre-transition
            // default, but permits files with no non-DST type; in that case
            // the first type is the only defined fallback.  Do not reject a
            // structurally valid all-DST file merely because it is unusual.
            .unwrap_or(0);
        if let (Some(continuation), Some(&last_transition_type)) =
            (continuation.as_ref(), block.transition_types.last())
        {
            let explicit = &block.types[last_transition_type as usize];
            let continued = continuation.offset_at(*block.transitions.last().unwrap());
            if continued.offset != explicit.offset
                || continued.is_daylight_saving != explicit.is_daylight_saving
                || continued.abbreviation != explicit.abbreviation()
            {
                return Err(TimeZoneError::InvalidTzif);
            }
        }
        Ok(Self {
            transitions: block.transitions,
            transition_types: block.transition_types,
            types: block.types,
            continuation,
            pre_first_type,
        })
    }

    fn offset_at(&self, seconds: i64) -> OffsetInfo<'_> {
        if let Some(last) = self.transitions.last() {
            if seconds > *last {
                if let Some(continuation) = &self.continuation {
                    return continuation.offset_at(seconds);
                }
            }
        } else if let Some(continuation) = &self.continuation {
            return continuation.offset_at(seconds);
        }

        let type_index = match last_transition_at_or_before(&self.transitions, seconds) {
            Some(index) => self.transition_types[index] as usize,
            None => self.pre_first_type,
        };
        let type_info = &self.types[type_index];
        OffsetInfo {
            offset: type_info.offset,
            is_daylight_saving: type_info.is_daylight_saving,
            abbreviation: type_info.abbreviation(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ZoneType {
    offset: UtcOffset,
    is_daylight_saving: bool,
    abbreviation: Vec<u8>,
}

impl ZoneType {
    fn abbreviation(&self) -> &[u8] {
        &self.abbreviation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionRule {
    JulianNoLeap {
        day: u16,
        time: TransitionTime,
    },
    DayOfYear {
        day: u16,
        time: TransitionTime,
    },
    MonthWeekDay {
        month: u8,
        week: u8,
        weekday: u8,
        time: TransitionTime,
    },
}

impl TransitionRule {
    fn time(self) -> TransitionTime {
        match self {
            Self::JulianNoLeap { time, .. }
            | Self::DayOfYear { time, .. }
            | Self::MonthWeekDay { time, .. } => time,
        }
    }

    fn day_start_seconds(self, year: i64) -> i128 {
        match self {
            Self::JulianNoLeap { day, .. } => {
                let day = day as i128 - 1;
                let leap_day = if is_leap_year(year) && day >= 59 {
                    1
                } else {
                    0
                };
                (days_from_civil(year, 1, 1) + day + leap_day) * SECONDS_PER_DAY
            }
            Self::DayOfYear { day, .. } => {
                (days_from_civil(year, 1, 1) + day as i128) * SECONDS_PER_DAY
            }
            Self::MonthWeekDay {
                month,
                week,
                weekday,
                ..
            } => {
                let first_day = days_from_civil(year, month, 1);
                let first_weekday = weekday_from_days(first_day);
                let mut day = 1_i128
                    + (weekday as i128 - first_weekday).rem_euclid(7)
                    + (week as i128 - 1) * 7;
                if day > days_in_month(year, month) as i128 {
                    day -= 7;
                }
                (days_from_civil(year, month, day as u8)) * SECONDS_PER_DAY
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransitionTime {
    seconds: i32,
    basis: TimeBasis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimeBasis {
    Wall,
    Standard,
    Utc,
}

fn transition_seconds(
    year: i64,
    rule: TransitionRule,
    standard_offset: UtcOffset,
    wall_offset: UtcOffset,
) -> i128 {
    let local = rule.day_start_seconds(year) + rule.time().seconds as i128;
    match rule.time().basis {
        TimeBasis::Wall => local - wall_offset.seconds_east_of_utc() as i128,
        TimeBasis::Standard => local - standard_offset.seconds_east_of_utc() as i128,
        TimeBasis::Utc => local,
    }
}

fn parse_posix_zone(bytes: &[u8]) -> Result<PosixZone, TimeZoneError> {
    let mut parser = PosixParser { bytes, offset: 0 };
    let standard_name = parser.parse_name()?;
    let standard_offset = parser.parse_posix_offset()?;
    let standard = ZoneType {
        offset: UtcOffset::from_seconds(-standard_offset).ok_or(TimeZoneError::InvalidPosixTz)?,
        is_daylight_saving: false,
        abbreviation: standard_name,
    };
    if parser.is_finished() {
        return Ok(PosixZone {
            standard,
            daylight: None,
            start: None,
            end: None,
        });
    }

    let daylight_name = parser.parse_name()?;
    let daylight_offset = if parser.peek() == Some(b',') {
        standard
            .offset
            .seconds_east_of_utc()
            .checked_add(3_600)
            .and_then(UtcOffset::from_seconds)
            .ok_or(TimeZoneError::InvalidPosixTz)?
    } else {
        let parsed = parser.parse_posix_offset()?;
        UtcOffset::from_seconds(-parsed).ok_or(TimeZoneError::InvalidPosixTz)?
    };
    let daylight = ZoneType {
        offset: daylight_offset,
        is_daylight_saving: true,
        abbreviation: daylight_name,
    };
    parser.expect(b',')?;
    let start = parser.parse_rule()?;
    parser.expect(b',')?;
    let end = parser.parse_rule()?;
    if !parser.is_finished() {
        return Err(TimeZoneError::InvalidPosixTz);
    }

    Ok(PosixZone {
        standard,
        daylight: Some(daylight),
        start: Some(start),
        end: Some(end),
    })
}

struct PosixParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PosixParser<'a> {
    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.offset += 1;
        Some(value)
    }

    fn expect(&mut self, byte: u8) -> Result<(), TimeZoneError> {
        if self.next() == Some(byte) {
            Ok(())
        } else {
            Err(TimeZoneError::InvalidPosixTz)
        }
    }

    fn parse_name(&mut self) -> Result<Vec<u8>, TimeZoneError> {
        if self.next() == Some(b'<') {
            let start = self.offset;
            while let Some(byte) = self.next() {
                if byte == b'>' {
                    if self.offset - 1 == start {
                        return Err(TimeZoneError::InvalidPosixTz);
                    }
                    return Ok(self.bytes[start..self.offset - 1].to_vec());
                }
                if byte == 0 || byte == b'\n' {
                    return Err(TimeZoneError::InvalidPosixTz);
                }
            }
            return Err(TimeZoneError::InvalidPosixTz);
        }

        self.offset = self.offset.saturating_sub(1);
        let start = self.offset;
        while matches!(self.peek(), Some(b'A'..=b'Z' | b'a'..=b'z')) {
            self.offset += 1;
        }
        if self.offset - start < 3 {
            return Err(TimeZoneError::InvalidPosixTz);
        }
        Ok(self.bytes[start..self.offset].to_vec())
    }

    fn parse_posix_offset(&mut self) -> Result<i32, TimeZoneError> {
        let offset = self.parse_signed_hms(24)?;
        if !(-MAX_OFFSET_SECONDS..=MAX_OFFSET_SECONDS).contains(&offset) {
            return Err(TimeZoneError::InvalidPosixTz);
        }
        Ok(offset)
    }

    fn parse_transition_time(&mut self) -> Result<TransitionTime, TimeZoneError> {
        let seconds = self.parse_signed_hms(167)?;
        let basis = match self.peek() {
            Some(b'w') => {
                self.offset += 1;
                TimeBasis::Wall
            }
            Some(b's') => {
                self.offset += 1;
                TimeBasis::Standard
            }
            Some(b'u' | b'g' | b'z') => {
                self.offset += 1;
                TimeBasis::Utc
            }
            _ => TimeBasis::Wall,
        };
        Ok(TransitionTime { seconds, basis })
    }

    fn parse_signed_hms(&mut self, max_hours: i32) -> Result<i32, TimeZoneError> {
        let sign = match self.peek() {
            Some(b'+') => {
                self.offset += 1;
                1_i32
            }
            Some(b'-') => {
                self.offset += 1;
                -1_i32
            }
            _ => 1_i32,
        };
        let hours = self.parse_decimal()?;
        if hours > max_hours as u32 {
            return Err(TimeZoneError::InvalidPosixTz);
        }
        let minutes = if self.peek() == Some(b':') {
            self.offset += 1;
            let value = self.parse_decimal()?;
            if value > 59 {
                return Err(TimeZoneError::InvalidPosixTz);
            }
            value
        } else {
            0
        };
        let seconds = if self.peek() == Some(b':') {
            self.offset += 1;
            let value = self.parse_decimal()?;
            if value > 59 {
                return Err(TimeZoneError::InvalidPosixTz);
            }
            value
        } else {
            0
        };
        let magnitude = hours
            .checked_mul(3_600)
            .and_then(|value| value.checked_add(minutes * 60))
            .and_then(|value| value.checked_add(seconds))
            .ok_or(TimeZoneError::InvalidPosixTz)?;
        let magnitude = i32::try_from(magnitude).map_err(|_| TimeZoneError::InvalidPosixTz)?;
        magnitude
            .checked_mul(sign)
            .ok_or(TimeZoneError::InvalidPosixTz)
    }

    fn parse_decimal(&mut self) -> Result<u32, TimeZoneError> {
        let start = self.offset;
        let mut value = 0_u32;
        while let Some(byte @ b'0'..=b'9') = self.peek() {
            self.offset += 1;
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add((byte - b'0') as u32))
                .ok_or(TimeZoneError::InvalidPosixTz)?;
        }
        if self.offset == start {
            Err(TimeZoneError::InvalidPosixTz)
        } else {
            Ok(value)
        }
    }

    fn parse_rule(&mut self) -> Result<TransitionRule, TimeZoneError> {
        let rule = match self.next() {
            Some(b'J') => {
                let day = self.parse_decimal()?;
                if !(1..=365).contains(&day) {
                    return Err(TimeZoneError::InvalidPosixTz);
                }
                TransitionRule::JulianNoLeap {
                    day: day as u16,
                    time: self.parse_rule_time()?,
                }
            }
            Some(b'M') => {
                let month = self.parse_decimal()?;
                self.expect(b'.')?;
                let week = self.parse_decimal()?;
                self.expect(b'.')?;
                let weekday = self.parse_decimal()?;
                if !(1..=12).contains(&month) || !(1..=5).contains(&week) || weekday > 6 {
                    return Err(TimeZoneError::InvalidPosixTz);
                }
                TransitionRule::MonthWeekDay {
                    month: month as u8,
                    week: week as u8,
                    weekday: weekday as u8,
                    time: self.parse_rule_time()?,
                }
            }
            Some(b'0'..=b'9') => {
                self.offset -= 1;
                let day = self.parse_decimal()?;
                if day > 365 {
                    return Err(TimeZoneError::InvalidPosixTz);
                }
                TransitionRule::DayOfYear {
                    day: day as u16,
                    time: self.parse_rule_time()?,
                }
            }
            _ => return Err(TimeZoneError::InvalidPosixTz),
        };
        Ok(rule)
    }

    fn parse_rule_time(&mut self) -> Result<TransitionTime, TimeZoneError> {
        if self.peek() == Some(b'/') {
            self.offset += 1;
            self.parse_transition_time()
        } else {
            Ok(TransitionTime {
                seconds: 7_200,
                basis: TimeBasis::Wall,
            })
        }
    }
}

#[derive(Clone, Copy)]
struct Header {
    version: u8,
    ttisutcnt: usize,
    ttisstdcnt: usize,
    leapcnt: usize,
    timecnt: usize,
    typecnt: usize,
    charcnt: usize,
}

impl Header {
    fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), TimeZoneError> {
        if bytes.len() < 44 || &bytes[..4] != b"TZif" {
            return Err(TimeZoneError::InvalidTzif);
        }
        let version = bytes[4];
        if version != 0 && version != b'2' && version != b'3' {
            return Err(TimeZoneError::InvalidTzif);
        }
        if bytes[5..20].iter().any(|&byte| byte != 0) {
            return Err(TimeZoneError::InvalidTzif);
        }
        let mut counts = [0_usize; 6];
        for (index, count) in counts.iter_mut().enumerate() {
            let offset = 20 + index * 4;
            let value = i32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
            if value < 0 {
                return Err(TimeZoneError::InvalidTzif);
            }
            *count = value as usize;
        }
        let header = Self {
            version,
            ttisutcnt: counts[0],
            ttisstdcnt: counts[1],
            leapcnt: counts[2],
            timecnt: counts[3],
            typecnt: counts[4],
            charcnt: counts[5],
        };
        if header.typecnt == 0
            || header.typecnt > u8::MAX as usize + 1
            || header.charcnt == 0
            || (header.ttisutcnt != 0 && header.ttisutcnt != header.typecnt)
            || (header.ttisstdcnt != 0 && header.ttisstdcnt != header.typecnt)
        {
            return Err(TimeZoneError::InvalidTzif);
        }
        Ok((header, &bytes[44..]))
    }
}

struct TzifBlock {
    transitions: Vec<i64>,
    transition_types: Vec<u8>,
    types: Vec<ZoneType>,
}

fn parse_block(
    bytes: &[u8],
    header: Header,
    wide_times: bool,
) -> Result<(TzifBlock, &[u8]), TimeZoneError> {
    let time_size = if wide_times { 8 } else { 4 };
    let required = header
        .timecnt
        .checked_mul(time_size)
        .and_then(|value| value.checked_add(header.timecnt))
        .and_then(|value| value.checked_add(header.typecnt.checked_mul(6)?))
        .and_then(|value| value.checked_add(header.charcnt))
        .and_then(|value| value.checked_add(header.leapcnt.checked_mul(time_size + 4)?))
        .and_then(|value| value.checked_add(header.ttisstdcnt))
        .and_then(|value| value.checked_add(header.ttisutcnt))
        .ok_or(TimeZoneError::InvalidTzif)?;
    if bytes.len() < required {
        return Err(TimeZoneError::InvalidTzif);
    }

    let (transition_bytes, bytes) = split_at(bytes, header.timecnt * time_size)?;
    let (transition_type_bytes, bytes) = split_at(bytes, header.timecnt)?;
    let (type_bytes, bytes) = split_at(bytes, header.typecnt * 6)?;
    let (abbreviations, bytes) = split_at(bytes, header.charcnt)?;
    let (leap_bytes, bytes) = split_at(bytes, header.leapcnt * (time_size + 4))?;
    let (standard_indicators, bytes) = split_at(bytes, header.ttisstdcnt)?;
    let (utc_indicators, bytes) = split_at(bytes, header.ttisutcnt)?;

    if standard_indicators
        .iter()
        .chain(utc_indicators)
        .any(|&byte| byte > 1)
    {
        return Err(TimeZoneError::InvalidTzif);
    }
    if utc_indicators
        .iter()
        .enumerate()
        .any(|(index, &utc)| utc == 1 && standard_indicators.get(index) != Some(&1))
    {
        return Err(TimeZoneError::InvalidTzif);
    }

    let mut transitions = Vec::new();
    let mut previous = None;
    for index in 0..header.timecnt {
        let offset = index * time_size;
        let value = if wide_times {
            i64::from_be_bytes(
                transition_bytes[offset..offset + time_size]
                    .try_into()
                    .unwrap(),
            )
        } else {
            i32::from_be_bytes(
                transition_bytes[offset..offset + time_size]
                    .try_into()
                    .unwrap(),
            ) as i64
        };
        if previous.is_some_and(|prior| value <= prior) {
            return Err(TimeZoneError::InvalidTzif);
        }
        previous = Some(value);
        transitions.push(value);
    }

    if transition_type_bytes
        .iter()
        .any(|&index| index as usize >= header.typecnt)
    {
        return Err(TimeZoneError::InvalidTzif);
    }

    let mut raw_types = Vec::new();
    for index in 0..header.typecnt {
        let record_offset = index * 6;
        let utc_offset = i32::from_be_bytes(
            type_bytes[record_offset..record_offset + 4]
                .try_into()
                .unwrap(),
        );
        let offset = UtcOffset::from_seconds(utc_offset).ok_or(TimeZoneError::InvalidTzif)?;
        let is_daylight_saving = match type_bytes[record_offset + 4] {
            0 => false,
            1 => true,
            _ => return Err(TimeZoneError::InvalidTzif),
        };
        raw_types.push((
            offset,
            is_daylight_saving,
            type_bytes[record_offset + 5] as usize,
        ));
    }

    let mut types = Vec::new();
    for (offset, is_daylight_saving, abbreviation_index) in raw_types {
        if abbreviation_index >= abbreviations.len() {
            return Err(TimeZoneError::InvalidTzif);
        }
        let suffix = &abbreviations[abbreviation_index..];
        let abbreviation_end = suffix
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(TimeZoneError::InvalidTzif)?;
        types.push(ZoneType {
            offset,
            is_daylight_saving,
            abbreviation: suffix[..abbreviation_end].to_vec(),
        });
    }

    validate_leap_records(leap_bytes, wide_times, header.leapcnt)?;
    Ok((
        TzifBlock {
            transitions,
            transition_types: transition_type_bytes.to_vec(),
            types,
        },
        bytes,
    ))
}

fn validate_leap_records(
    bytes: &[u8],
    wide_times: bool,
    count: usize,
) -> Result<(), TimeZoneError> {
    let time_size = if wide_times { 8 } else { 4 };
    let mut previous_transition = None;
    let mut previous_correction = None;
    for index in 0..count {
        let offset = index * (time_size + 4);
        let transition = if wide_times {
            i64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
        } else {
            i32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as i64
        };
        let correction_offset = offset + time_size;
        let correction = i32::from_be_bytes(
            bytes[correction_offset..correction_offset + 4]
                .try_into()
                .unwrap(),
        );
        if let (Some(prior_transition), Some(prior_correction)) =
            (previous_transition, previous_correction)
        {
            if i128::from(transition) - i128::from(prior_transition) < 2_419_199
                || (correction as i64 - prior_correction as i64).unsigned_abs() != 1
            {
                return Err(TimeZoneError::InvalidTzif);
            }
        } else if transition < 0 || correction != 1 && correction != -1 {
            return Err(TimeZoneError::InvalidTzif);
        }
        previous_transition = Some(transition);
        previous_correction = Some(correction);
        // Leap corrections are intentionally not applied: UnixTime follows
        // POSIX's leap-second-free scale after this record validation.
    }
    Ok(())
}

fn parse_tzif_continuation(bytes: &[u8]) -> Result<Option<PosixZone>, TimeZoneError> {
    if bytes.len() < 2 || bytes[0] != b'\n' || bytes[bytes.len() - 1] != b'\n' {
        return Err(TimeZoneError::InvalidTzif);
    }
    let rule = &bytes[1..bytes.len() - 1];
    if rule.iter().any(|&byte| byte == b'\n') {
        return Err(TimeZoneError::InvalidTzif);
    }
    if rule.is_empty() {
        Ok(None)
    } else {
        parse_posix_zone(rule)
            .map(Some)
            .map_err(|_| TimeZoneError::InvalidTzif)
    }
}

fn split_at(bytes: &[u8], length: usize) -> Result<(&[u8], &[u8]), TimeZoneError> {
    if bytes.len() < length {
        return Err(TimeZoneError::InvalidTzif);
    }
    Ok(bytes.split_at(length))
}

fn last_transition_at_or_before(transitions: &[i64], seconds: i64) -> Option<usize> {
    let mut low = 0;
    let mut high = transitions.len();
    while low < high {
        let middle = low + (high - low) / 2;
        if transitions[middle] <= seconds {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low.checked_sub(1)
}

fn is_leap_year(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

// Howard Hinnant's proleptic-Gregorian civil-date transform, kept in i128 so
// every signed Unix second has a checked calendar year for POSIX rule lookup.
fn days_from_civil(year: i64, month: u8, day: u8) -> i128 {
    let year = year as i128 - if month <= 2 { 1 } else { 0 };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = month as i128;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i128 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn year_from_unix_seconds(seconds: i64) -> i64 {
    let days = (seconds as i128).div_euclid(SECONDS_PER_DAY);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_piece = (5 * day_of_year + 2) / 153;
    let year = year_of_era + era * 400 + if month_piece >= 10 { 1 } else { 0 };
    // i64 Unix seconds span roughly ±292 billion years, well inside i64.
    year as i64
}

fn weekday_from_days(days: i128) -> i128 {
    (days + 4).rem_euclid(7)
}
