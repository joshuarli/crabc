//! Bounded native Linux/x86-64 clock queries.
//!
//! This staged facade admits only validated realtime, monotonic, and
//! monotonic-raw observations. It intentionally does not expose AArch64
//! calendar, timer, timezone, or clock-mutation APIs until their x86-64
//! records and behavior have independent evidence.

use core::convert::TryFrom;
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
    /// `CLOCK_MONOTONIC_RAW` (hardware-derived non-adjusted clock).
    MonotonicRaw = 4,
}

impl TryFrom<i32> for ClockId {
    type Error = Errno;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
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
