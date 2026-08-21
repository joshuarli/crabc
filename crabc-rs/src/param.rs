//! Process parameters whose values require no libc-global state.

/// Linux's ABI-visible scheduler clock tick rate.
///
/// On Linux/AArch64 this `USER_HZ` value is fixed at 100. `page_size` is not
/// exposed until crabc-rs has an explicit aux-vector initialization boundary:
/// hard-coding a page size would be wrong for valid 16 KiB and 64 KiB kernels.
#[inline]
#[must_use]
pub const fn clock_ticks_per_second() -> u64 { 100 }
