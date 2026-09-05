//! Process timezone state from musl 1.2.6 __tz.c and __map_file.c (MIT),
//! revision 9fa28ece75d8a2191de7c5bb53bed224c5947417. POSIX rule parsing,
//! transition search, alternate-DST selection and TZ caching retain that source
//! algorithm. Existing timegm.rs owns the target-neutral calendar arithmetic.
//!
//! One lock protects rule/cache/map publication. Public zone-name pointers are
//! borrowed until TZ changes; callers coordinate environment mutation and use
//! of those pointers, as for the C API. No timezone data is bundled. Secure
//! execution uses the existing startup-security owner and standard search paths.
//! Mapped section ranges/indices are checked before use: invalid ranges fall
//! back to UTC instead of inheriting upstream's out-of-bounds accesses.
//! General fork lock recovery remains a separate process-owner obligation.

use core::{ffi::{c_char, c_int, c_long, c_void}, ptr,
    sync::atomic::{AtomicI32, Ordering}};
use super::{environment, errno, raw_syscall as sys, startup_security, timegm};

#[no_mangle]
pub static mut __timezone: c_long = 0;
#[no_mangle]
pub static mut __daylight: c_int = 0;
#[no_mangle]
pub static mut __tzname: [*mut c_char; 2] = [ptr::null_mut(); 2];
core::arch::global_asm!(".weak timezone", ".set timezone, __timezone",
    ".weak daylight", ".set daylight, __daylight", ".weak tzname", ".set tzname, __tzname");

static LOCK: AtomicI32 = AtomicI32::new(0);
static mut STANDARD_NAME: [u8; 7] = [0; 7];
static mut DAYLIGHT_NAME: [u8; 7] = [0; 7];
static mut DAYLIGHT_OFFSET: i32 = 0;
static mut RULES: [[i32; 5]; 2] = [[0; 5]; 2];
static mut OLD_BUFFER: [u8; 32] = [0; 32];
static mut OLD_TZ: *mut u8 = ptr::addr_of_mut!(OLD_BUFFER).cast();
static mut OLD_SIZE: usize = 32;
static mut MAPPING: Option<ZoneFile> = None;

#[derive(Clone, Copy)]
struct ZoneFile {
    base: *const u8, size: usize, transitions: usize, indices: usize,
    types: usize, abbreviations: usize, abbreviations_end: usize, stride: usize,
    data_end: usize, posix_tail: bool,
}
struct TimezoneGuard;
impl TimezoneGuard {
    fn acquire() -> Self {
        while LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            unsafe { sys::syscall4(202, LOCK.as_ptr() as i64, 128, 1, 0); }
        }
        Self
    }
}
impl Drop for TimezoneGuard {
    fn drop(&mut self) {
        LOCK.store(0, Ordering::Release);
        unsafe { sys::syscall3(202, LOCK.as_ptr() as i64, 129, 1); }
    }
}
/// Acquire the __timezone_lockptr position after stdio/syslog in musl fork order.
/// # Safety
/// The process owner has blocked application signals, holds earlier fork locks,
/// and will run exactly one parent/child completion before resuming callbacks.
pub(super) unsafe fn pthread_fork_prepare() {
    core::mem::forget(TimezoneGuard::acquire());
}
/// Release the prepared timezone lock in the original process, including error.
/// # Safety
/// This is the matching original-process completion; it has not run before.
pub(super) unsafe fn pthread_fork_parent() { drop(TimezoneGuard); }
/// Preserve inherited timezone/cache/mapping state and reset only its lock.
/// # Safety
/// This is the matching sole-thread fork child, before signals/user callbacks;
/// never call it in a CLONE_VM child or the original process.
pub(super) unsafe fn pthread_fork_child() { LOCK.store(0, Ordering::Relaxed); }
unsafe extern "C" { fn malloc(size: usize) -> *mut c_void; }

unsafe fn length(mut p: *const u8) -> usize {
    let start = p;
    unsafe { while *p != 0 { p = p.add(1); } p.offset_from(start) as usize }
}
unsafe fn equal(mut a: *const u8, mut b: *const u8) -> bool {
    unsafe { loop { if *a != *b { return false; } if *a == 0 { return true; }
        a = a.add(1); b = b.add(1); } }
}
/// A bounded view of either the NUL-terminated environment value or the TZif
/// footer (which the format explicitly does not NUL-terminate).
struct TzCursor { current: *const u8, end: *const u8 }
impl TzCursor {
    unsafe fn string(p: *const u8) -> Self { Self { current: p, end: unsafe { p.add(length(p)) } } }
    unsafe fn get(&self, index: usize) -> u8 {
        if index >= (self.end as usize).wrapping_sub(self.current as usize) { 0 }
        else { unsafe { *self.current.add(index) } }
    }
    unsafe fn next(&mut self) {
        if self.current != self.end { self.current = unsafe { self.current.add(1) }; }
    }
}
unsafe fn integer(p: &mut TzCursor) -> i32 {
    let mut value = 0u32;
    unsafe { while p.get(0).wrapping_sub(b'0') < 10 {
        value = value.wrapping_mul(10).wrapping_add((p.get(0) - b'0') as u32);
        p.next();
    } }
    value as i32
}
unsafe fn offset(p: &mut TzCursor) -> i32 {
    unsafe {
        let negative = p.get(0) == b'-';
        if negative || p.get(0) == b'+' { p.next(); }
        let mut value = integer(p).wrapping_mul(3600);
        if p.get(0) == b':' {
            p.next(); value = value.wrapping_add(integer(p).wrapping_mul(60));
            if p.get(0) == b':' { p.next(); value = value.wrapping_add(integer(p)); }
        }
        if negative { value.wrapping_neg() } else { value }
    }
}
unsafe fn name(destination: *mut u8, p: &mut TzCursor) {
    unsafe {
        let quoted = p.get(0) == b'<';
        if quoted { p.next(); }
        let mut n = 0;
        while if quoted { p.get(n) != 0 && p.get(n) != b'>' }
            else { (p.get(n) | 32).wrapping_sub(b'a') < 26 } {
            if n < 6 { *destination.add(n) = p.get(n); }
            n += 1;
        }
        let closing = quoted && p.get(n) != 0;
        p.current = p.current.add(n);
        if closing { p.next(); }
        *destination.add(n.min(6)) = 0;
    }
}
unsafe fn rule(p: &mut TzCursor) -> [i32; 5] {
    unsafe {
        let mut result = [p.get(0) as i32, 0, 0, 0, 7200];
        if p.get(0) != b'M' {
            if p.get(0) == b'J' { p.next(); } else { result[0] = 0; }
            result[1] = integer(p);
        } else {
            p.next(); result[1] = integer(p);
            p.next(); result[2] = integer(p);
            p.next(); result[3] = integer(p);
        }
        if p.get(0) == b'/' { p.next(); result[4] = offset(p); }
        result
    }
}
unsafe fn read32(p: *const u8) -> u32 {
    unsafe { u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]) }
}

// Linux/x86 stat is 144 bytes with st_size at byte 48. This scratch record is
// private kernel ABI storage, not a new public struct-stat owner.
unsafe fn map_file(path: *const u8) -> Option<(*const u8, usize)> {
    unsafe {
        let fd = sys::syscall3(2, path as i64, 0x80800, 0);
        if fd < 0 { return None; }
        let mut stat = [0u64; 18];
        let status = sys::syscall2(5, fd, stat.as_mut_ptr() as i64);
        let mut mapping = -1;
        if status == 0 {
            mapping = sys::syscall6(9, 0, stat[6] as i64, 1, 1, fd, 0);
            if (-4095..0).contains(&mapping) { errno::set_errno(-mapping as c_int); }
        } else { errno::set_errno(-status as c_int); }
        sys::syscall1(3, fd);
        if (-4095..0).contains(&mapping) { None }
        else { Some((mapping as *const u8, stat[6] as usize)) }
    }
}

unsafe fn parse_mapping(base: *const u8, size: usize) -> Option<ZoneFile> {
    unsafe {
        if size < 44 || core::slice::from_raw_parts(base, 4) != b"TZif" { return None; }
        // Intentional pinned-musl correction: RFC 9636 §3.1 specifies NUL,
        // not ASCII '1', for a v1 header. Newer files contain a second block.
        // https://www.rfc-editor.org/rfc/rfc9636.html#section-3.1
        let version = *base.add(4);
        if !matches!(version, 0 | b'2' | b'3' | b'4') { return None; }
        let (header, stride) = if version != 0 {
            let mut skip = 44usize;
            for (i, weight) in [1usize, 1, 8, 5, 6, 1].iter().enumerate() {
                skip = skip.checked_add((read32(base.add(20 + i*4)) as usize).checked_mul(*weight)?)?;
            }
            if skip.checked_add(44)? > size { return None; }
            if core::slice::from_raw_parts(base.add(skip), 4) != b"TZif" || *base.add(skip+4) != version { return None; }
            (skip, 8)
        } else { (0, 4) };
        let count = read32(base.add(header + 32)) as usize;
        let type_count = read32(base.add(header + 36)) as usize;
        let characters = read32(base.add(header + 40)) as usize;
        if type_count == 0 || type_count > 256 { return None; }
        let transitions = header + 44;
        let indices = transitions.checked_add(count.checked_mul(stride)?)?;
        let types = indices.checked_add(count)?;
        let abbreviations = types.checked_add(type_count.checked_mul(6)?)?;
        let abbreviations_end = abbreviations.checked_add(characters)?;
        if abbreviations_end > size || characters == 0 { return None; }
        let mut data_end = abbreviations_end.checked_add((read32(base.add(header+28)) as usize).checked_mul(stride+4)?)?;
        for position in [20, 24] {
            let count = read32(base.add(header+position)) as usize;
            if count != 0 && count != type_count { return None; }
            data_end = data_end.checked_add(count)?;
        }
        if data_end > size { return None; }
        for i in 0..count { if *base.add(indices+i) as usize >= type_count { return None; } }
        for i in 0..type_count {
            if read32(base.add(types+6*i)) == 0x80000000 || *base.add(types+6*i+4) > 1 { return None; }
            let index = *base.add(types+6*i+5) as usize;
            if index >= characters || !(abbreviations+index..abbreviations_end).any(|j| *base.add(j) == 0) {
                return None;
            }
        }
        Some(ZoneFile { base, size, transitions, indices, types, abbreviations,
            abbreviations_end, stride, data_end, posix_tail: false })
    }
}

unsafe fn configure() {
    unsafe {
        let utc = timegm::UTC.as_ptr();
        let mut source = environment::getenv(c"TZ".as_ptr()).cast::<u8>().cast_const();
        if source.is_null() { source = c"/etc/localtime".as_ptr().cast(); }
        if *source == 0 { source = utc; }
        if !OLD_TZ.is_null() && equal(source, OLD_TZ) { return; }
        RULES = [[0; 5]; 2];
        if let Some(map) = MAPPING { sys::syscall2(11, map.base as i64, map.size as i64); }
        MAPPING = None;
        let mut size = length(source);
        if size > 4097 { source = utc; size = 3; }
        if size >= OLD_SIZE {
            OLD_SIZE = (OLD_SIZE * 2).max(size+1).min(4098);
            // Preserve upstream's growth-only cache allocations, including its
            // retry behavior after ENOMEM; no allocator invention or free cache.
            OLD_TZ = malloc(OLD_SIZE).cast();
        }
        if !OLD_TZ.is_null() { ptr::copy_nonoverlapping(source, OLD_TZ, size+1); }
        let mut posix = false;
        if *source != b':' {
            let mut cursor = TzCursor::string(source);
            let mut temporary = [0u8; 7];
            name(temporary.as_mut_ptr(), &mut cursor);
            posix = cursor.current != source && (cursor.get(0) == b'+' || cursor.get(0) == b'-'
                || cursor.get(0).wrapping_sub(b'0') < 10
                || equal(temporary.as_ptr(), c"UTC".as_ptr().cast())
                || equal(temporary.as_ptr(), c"GMT".as_ptr().cast()));
        }
        let mut mapped = None;
        if !posix {
            if *source == b':' { source = source.add(1); }
            if *source == b'/' || *source == b'.' {
                if !startup_security::is_secure() || equal(source, c"/etc/localtime".as_ptr().cast()) {
                    mapped = map_file(source);
                }
            } else {
                let n = length(source);
                if n <= 255 && !(0..n).any(|i| *source.add(i) == b'.') {
                    let mut path = [0u8; 280];
                    for prefix in [b"/usr/share/zoneinfo/".as_slice(), b"/share/zoneinfo/", b"/etc/zoneinfo/"] {
                        ptr::copy_nonoverlapping(prefix.as_ptr(), path.as_mut_ptr(), prefix.len());
                        ptr::copy_nonoverlapping(source, path.as_mut_ptr().add(prefix.len()), n+1);
                        mapped = map_file(path.as_ptr());
                        if mapped.is_some() { break; }
                    }
                }
            }
            if mapped.is_none() { source = utc; }
        }
        if let Some((base, size)) = mapped {
            MAPPING = parse_mapping(base, size);
            if MAPPING.is_none() { sys::syscall2(11, base as i64, size as i64); source = utc; }
        }
        let mut cursor = TzCursor::string(source);
        if let Some(map) = MAPPING {
            // Empty footer supplies no rule; retain type-derived globals.
            if map.stride == 8 && map.size-map.data_end > 2 && *map.base.add(map.data_end) == b'\n'
                && *map.base.add(map.size-1) == b'\n' {
                cursor = TzCursor { current: map.base.add(map.data_end+1), end: map.base.add(map.size-1) };
                MAPPING = Some(ZoneFile { posix_tail: cursor.get(0) != 0, ..map });
            } else {
                __tzname = [ptr::null_mut(); 2]; __daylight = 0; __timezone = 0; DAYLIGHT_OFFSET = 0;
                for p in (map.types..map.abbreviations).step_by(6) {
                    let dst = *map.base.add(p+4) != 0;
                    let slot = usize::from(dst);
                    if __tzname[slot].is_null() {
                        __tzname[slot] = map.base.add(map.abbreviations + *map.base.add(p+5) as usize).cast_mut().cast();
                        if dst { DAYLIGHT_OFFSET = (read32(map.base.add(p)) as i32).wrapping_neg(); __daylight = 1; }
                        else {
                            // RFC 9636 §3.2 utoff is signed; POSIX timezone is
                            // UTC minus local standard time. Cast before
                            // negation, correcting musl's unsigned wrap to long.
                            // https://pubs.opengroup.org/onlinepubs/9699919799/functions/tzset.html
                            __timezone = -(read32(map.base.add(p)) as i32 as c_long);
                        }
                    }
                }
                if __tzname[0].is_null() { __tzname[0] = __tzname[1]; }
                if __tzname[0].is_null() { __tzname[0] = utc.cast_mut().cast(); }
                if __daylight == 0 { __tzname[1] = __tzname[0]; DAYLIGHT_OFFSET = __timezone as i32; }
                return;
            }
        }
        name(ptr::addr_of_mut!(STANDARD_NAME).cast(), &mut cursor);
        __tzname[0] = ptr::addr_of_mut!(STANDARD_NAME).cast();
        __timezone = offset(&mut cursor) as c_long;
        name(ptr::addr_of_mut!(DAYLIGHT_NAME).cast(), &mut cursor);
        __tzname[1] = ptr::addr_of_mut!(DAYLIGHT_NAME).cast();
        __daylight = (DAYLIGHT_NAME[0] != 0) as c_int;
        DAYLIGHT_OFFSET = if __daylight != 0 {
            if cursor.get(0) == b'+' || cursor.get(0) == b'-' || cursor.get(0).wrapping_sub(b'0') < 10 { offset(&mut cursor) }
            else { (__timezone as i32).wrapping_sub(3600) }
        } else { __timezone as i32 };
        for i in 0..2 { if cursor.get(0) == b',' { cursor.next(); RULES[i] = rule(&mut cursor); } }
    }
}

unsafe fn transition(map: ZoneFile, index: usize) -> i64 {
    unsafe {
        let p = map.base.add(map.transitions + index*map.stride);
        let first = read32(p);
        if map.stride == 8 { (((first as u64) << 32) | read32(p.add(4)) as u64) as i64 }
        else { first as i32 as i64 }
    }
}
unsafe fn type_offset(map: ZoneFile, index: usize) -> i64 {
    unsafe { read32(map.base.add(map.types + 6*index)) as i32 as i64 }
}
unsafe fn type_dst(map: ZoneFile, index: usize) -> i32 {
    unsafe { *map.base.add(map.types + 6*index + 4) as i32 }
}
unsafe fn transition_type(map: ZoneFile, index: usize) -> usize {
    unsafe { *map.base.add(map.indices + index) as usize }
}
unsafe fn scan_transitions(map: ZoneFile, seconds: i64, local: bool) -> Option<(usize, usize)> {
    unsafe {
        let count = (map.indices - map.transitions) / map.stride;
        // RFC 9636 §3.2: a nonempty footer governs a zero-transition file;
        // otherwise use type 0. This corrects musl's unconditional type 0.
        if count == 0 { return if map.posix_tail { None } else { Some((0, 0)) }; }
        // The first type governs pre-transition time, including a one-entry
        // table. Musl's lowest-non-DST guess and early last-entry return are
        // intentional differences fixed here against RFC 9636 §3.2.
        let first_offset = if local { type_offset(map, 0) } else { 0 };
        if seconds.wrapping_sub(first_offset) < transition(map, 0) {
            return Some((0, transition_type(map, 0)));
        }
        let mut a = 0;
        let mut n = count;
        while n > 1 {
            let middle = a+n/2;
            let off = if local { type_offset(map, transition_type(map, middle-1)) } else { 0 };
            if seconds.wrapping_sub(off) < transition(map, middle) { n /= 2; }
            else { a = middle; n -= n/2; }
        }
        if a == count-1 { return None; }
        let current = transition_type(map, a);
        let alternate = if a != 0 && type_dst(map, transition_type(map, a-1)) != type_dst(map, current) {
            transition_type(map, a-1)
        } else if a+1 < count && type_dst(map, transition_type(map, a+1)) != type_dst(map, current) {
            transition_type(map, a+1)
        } else { current };
        Some((current, alternate))
    }
}

fn rule_seconds(rule: [i32; 5], year: i32) -> i64 {
    let mut leap = false;
    let mut seconds = timegm::year_to_secs(year as i64, &mut leap);
    if rule[0] != b'M' as i32 {
        let mut day = rule[1];
        if rule[0] == b'J' as i32 && (day < 60 || !leap) { day = day.wrapping_sub(1); }
        seconds = seconds.wrapping_add(day.wrapping_mul(86400) as i64);
    } else {
        let month = rule[1];
        // POSIX requires month 1..12. Invalid rules cannot index Rust arrays.
        if !(1..=12).contains(&month) { return seconds; }
        let mut week = rule[2];
        seconds = seconds.wrapping_add(timegm::month_to_secs(month-1, leap));
        let weekday = ((seconds + 4*86400) % (7*86400)) as i32 / 86400;
        let mut days = rule[3].wrapping_sub(weekday);
        if days < 0 { days = days.wrapping_add(7); }
        let month_days = if month == 2 { 28 + i32::from(leap) } else { 30 + ((0xad5 >> (month-1)) & 1) };
        if week == 5 && days + 28 >= month_days { week = 4; }
        seconds = seconds.wrapping_add(86400i32.wrapping_mul(days.wrapping_add(7i32.wrapping_mul(week.wrapping_sub(1)))) as i64);
    }
    seconds.wrapping_add(rule[4] as i64)
}

pub(super) struct Zone {
    pub(super) daylight: i32,
    pub(super) offset: i64,
    pub(super) opposite: i64,
    pub(super) name: *const c_char,
}

/// Callers first bound seconds to the representable C-int calendar domain.
pub(super) unsafe fn zone(seconds: i64, local: bool) -> Zone {
    let _guard = TimezoneGuard::acquire();
    unsafe {
        configure();
        if let Some(map) = MAPPING {
            if let Some((current, alternate)) = scan_transitions(map, seconds, local) {
                return Zone { daylight: type_dst(map, current), offset: type_offset(map, current),
                    opposite: type_offset(map, alternate),
                    name: map.base.add(map.abbreviations + *map.base.add(map.types+6*current+5) as usize).cast() };
            }
        }
        let mut dst = false;
        if __daylight != 0 {
            let mut year = seconds / 31556952 + 70;
            let mut leap = false;
            while timegm::year_to_secs(year, &mut leap) > seconds { year -= 1; }
            while timegm::year_to_secs(year+1, &mut leap) < seconds { year += 1; }
            let mut start = rule_seconds(RULES[0], year as i32);
            let mut end = rule_seconds(RULES[1], year as i32);
            if !local { start += __timezone; end += DAYLIGHT_OFFSET as i64; }
            dst = if start < end { seconds >= start && seconds < end }
                else { !(seconds >= end && seconds < start) };
        }
        Zone { daylight: i32::from(dst), offset: if dst { -(DAYLIGHT_OFFSET as i64) } else { -__timezone },
            opposite: if dst { -__timezone } else { -(DAYLIGHT_OFFSET as i64) },
            name: __tzname[usize::from(dst)] }
    }
}

/// Refresh process timezone state from caller-coordinated TZ/environment data.
#[no_mangle]
pub extern "C" fn tzset() {
    let _guard = TimezoneGuard::acquire();
    unsafe { configure(); }
}

pub(super) unsafe fn tm_zone_name(value: &timegm::Tm) -> *const c_char {
    let _guard = TimezoneGuard::acquire();
    unsafe {
        let p = value.utc_name;
        configure();
        if p == timegm::UTC.as_ptr().cast() || p == __tzname[0] || p == __tzname[1]
            || MAPPING.is_some_and(|map| (p as usize).wrapping_sub(map.base as usize + map.abbreviations)
                < map.abbreviations_end-map.abbreviations) { p }
        else { c"".as_ptr() }
    }
}
