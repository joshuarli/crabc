//! Direct Linux/AArch64 clock queries.
//!
//! Known clocks use an infallible interface matching Rustix: each enum value
//! is supported by Linux at runtime. Dynamic descriptor clocks and clock
//! mutation remain outside this first M3 vertical slice.

use core::mem::MaybeUninit;

use crate::{Errno, Result};

pub use crate::fs::{Nsecs, Secs, Timespec};

/// Linux `CLOCK_*` identifiers which are known to be supported at runtime.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
#[repr(i32)]
#[non_exhaustive]
pub enum ClockId {
    /// `CLOCK_REALTIME`.
    Realtime = 0,
    /// `CLOCK_MONOTONIC`.
    Monotonic = 1,
    /// `CLOCK_PROCESS_CPUTIME_ID`.
    ProcessCPUTime = 2,
    /// `CLOCK_THREAD_CPUTIME_ID`.
    ThreadCPUTime = 3,
    /// `CLOCK_MONOTONIC_RAW`.
    MonotonicRaw = 4,
    /// `CLOCK_REALTIME_COARSE`.
    RealtimeCoarse = 5,
    /// `CLOCK_MONOTONIC_COARSE`.
    MonotonicCoarse = 6,
    /// `CLOCK_BOOTTIME`.
    Boottime = 7,
    /// `CLOCK_REALTIME_ALARM`.
    RealtimeAlarm = 8,
    /// `CLOCK_BOOTTIME_ALARM`.
    BoottimeAlarm = 9,
}

impl TryFrom<i32> for ClockId {
    type Error = Errno;

    #[inline]
    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
            2 => Ok(Self::ProcessCPUTime),
            3 => Ok(Self::ThreadCPUTime),
            4 => Ok(Self::MonotonicRaw),
            5 => Ok(Self::RealtimeCoarse),
            6 => Ok(Self::MonotonicCoarse),
            7 => Ok(Self::Boottime),
            8 => Ok(Self::RealtimeAlarm),
            9 => Ok(Self::BoottimeAlarm),
            _ => Err(Errno::RANGE),
        }
    }
}

/// Returns a known Linux clock's resolution.
#[must_use]
#[inline]
pub fn clock_getres(id: ClockId) -> Timespec {
    clock_query(id, crabc_core::time::clock_getres_raw)
}

/// Returns a known Linux clock's current value.
#[must_use]
#[inline]
pub fn clock_gettime(id: ClockId) -> Timespec {
    clock_query(id, crabc_core::time::clock_gettime_raw)
}

fn clock_query(
    id: ClockId,
    query: unsafe fn(i32, *mut u8) -> Result<()>,
) -> Timespec {
    let mut value = MaybeUninit::<Timespec>::uninit();
    // SAFETY: `value` has exactly the Linux/AArch64 `timespec` layout and
    // the enum contains only statically supported Linux clock identifiers.
    match unsafe { query(id as i32, value.as_mut_ptr().cast()) } {
        Ok(()) => unsafe { value.assume_init() },
        Err(error) => panic!("known Linux clock query failed with errno {}", error.raw()),
    }
}
