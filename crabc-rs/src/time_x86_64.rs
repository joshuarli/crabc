//! Bounded native Linux/x86-64 clock queries.
//!
//! This staged facade admits only validated realtime, monotonic,
//! monotonic-raw, and process-CPU observations, including typed realtime
//! milliseconds. It intentionally does not expose AArch64 calendar, timer,
//! timezone, or clock-mutation APIs until their x86-64 records and behavior
//! have independent evidence.

use core::convert::TryFrom;
use core::time::Duration;
use crabc_core::time::KernelTimespec;
use crate::{Errno, Result};

/// Nanoseconds in one second.
///
/// This preserves the public scalar type of the corresponding AArch64
/// constant. Kernel `timespec` fields remain signed 64-bit words and are
/// checked against the widened value at this ABI boundary.
pub const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Linux clock identifiers admitted by this x86-64 foundation slice.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ClockId {
    /// `CLOCK_REALTIME` (Unix epoch wall clock).
    Realtime = 0,
    /// `CLOCK_MONOTONIC` (boot-relative, nondecreasing clock).
    Monotonic = 1,
    /// `CLOCK_PROCESS_CPUTIME_ID` (CPU time consumed by this process).
    ProcessCPUTime = 2,
    /// `CLOCK_MONOTONIC_RAW` (hardware-derived non-adjusted clock).
    MonotonicRaw = 4,
}

impl TryFrom<i32> for ClockId {
    type Error = Errno;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
            2 => Ok(Self::ProcessCPUTime),
            4 => Ok(Self::MonotonicRaw),
            _ => Err(Errno::INVAL),
        }
    }
}

/// Linux/x86-64 `struct timespec` represented as a typed native observation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Timespec {
    /// Seconds in the selected clock's epoch.
    pub tv_sec: i64,
    /// Nanoseconds within `tv_sec`, normalized by Linux on success.
    pub tv_nsec: i64,
}

const _: () = assert!(core::mem::size_of::<Timespec>() == 16);
const _: () = assert!(core::mem::align_of::<Timespec>() == 8);

impl Timespec {
    fn from_kernel(value: KernelTimespec) -> Result<Self> {
        if !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
            return Err(Errno::RANGE);
        }
        Ok(Self { tv_sec: value.tv_sec, tv_nsec: value.tv_nsec })
    }
}

/// A UTC realtime observation reduced to whole milliseconds.
///
/// The seconds field remains signed so observations before the Unix epoch are
/// representable. The millisecond field is normalized to `0..1000` by
/// truncating the kernel's validated nanosecond remainder rather than
/// rounding it. Private fields prevent callers from manufacturing a
/// non-canonical value.
#[derive(Debug, Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealtimeMillis {
    seconds: i64,
    milliseconds: u16,
}

impl RealtimeMillis {
    #[inline]
    fn from_timespec(value: Timespec) -> Option<Self> {
        if !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
            return None;
        }
        Some(Self {
            seconds: value.tv_sec,
            milliseconds: (value.tv_nsec / 1_000_000) as u16,
        })
    }

    /// Returns signed whole seconds since the Unix epoch.
    #[inline]
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns the truncated millisecond remainder in `0..1000`.
    #[inline]
    #[must_use]
    pub const fn milliseconds(self) -> u16 {
        self.milliseconds
    }
}

/// Reads a validated observation from one admitted Linux clock.
pub fn clock_gettime(clock: ClockId) -> Result<Timespec> {
    Timespec::from_kernel(crabc_core::time::clock_gettime(clock as i32)?)
}

/// Reads a validated resolution for one admitted Linux clock.
pub fn clock_getres(clock: ClockId) -> Result<Timespec> {
    Timespec::from_kernel(crabc_core::time::clock_getres(clock as i32)?)
}

/// Reads the current UTC wall-clock value using the admitted realtime clock.
pub fn timespec_get() -> Result<Timespec> {
    clock_gettime(ClockId::Realtime)
}

/// Reads `CLOCK_REALTIME` and truncates its subsecond part to milliseconds.
///
/// The direct x86-64 clock query returns a normalized kernel `timespec`; no C
/// `timeb` record, timezone state, allocation, or thread-local `errno` is
/// involved. A malformed kernel result is rejected before a public value is
/// exposed.
#[inline]
pub fn realtime_millis() -> Result<RealtimeMillis> {
    RealtimeMillis::from_timespec(clock_gettime(ClockId::Realtime)?).ok_or(Errno::RANGE)
}

/// Returns CPU time consumed by the calling process as a native duration.
///
/// This observes Linux's `CLOCK_PROCESS_CPUTIME_ID`, which accumulates user
/// and system CPU time across the process rather than elapsed wall time. The
/// known-clock result is infallible by convention; malformed or failed kernel
/// data cannot be represented as a `Duration` and is treated as an impossible
/// direct-kernel contract failure.
#[inline]
#[must_use]
pub fn process_cpu_time() -> Duration {
    let value = clock_gettime(ClockId::ProcessCPUTime)
        .unwrap_or_else(|_| panic!("Linux process CPU clock query failed"));
    if value.tv_sec < 0 || !(0..i64::from(NANOS_PER_SECOND)).contains(&value.tv_nsec) {
        panic!("Linux process CPU clock returned an invalid timespec");
    }
    Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
}
