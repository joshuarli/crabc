use core::time::Duration;

use crabc_rs::time::{self, ClockId, SleepError, SleepOutcome, Timespec};

#[test]
fn native_clock_nanosleep_relative_zero_completes_on_monotonic_clock() {
    assert_eq!(
        time::clock_nanosleep_relative(ClockId::Monotonic, Duration::ZERO),
        Ok(SleepOutcome::Completed),
    );
}

#[test]
fn native_clock_nanosleep_absolute_has_no_remaining_and_validates_request() {
    // The monotonic epoch is in the past, so an absolute deadline of zero
    // completes immediately. The unit result carries no invented remainder.
    assert_eq!(
        time::clock_nanosleep_absolute(
            ClockId::Monotonic,
            Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        ),
        Ok(()),
    );
    assert_eq!(
        time::clock_nanosleep_absolute(
            ClockId::Monotonic,
            Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            },
        ),
        Err(SleepError::InvalidRequest),
    );
}
