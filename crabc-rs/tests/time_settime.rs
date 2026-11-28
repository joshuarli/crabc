use crabc_rs::time::{self, ClockId, Timespec};
use crabc_rs::Errno;

#[test]
fn clock_settime_monotonic_preserves_kernel_not_settable_error() {
    let error = time::clock_settime(
        ClockId::Monotonic,
        Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    )
    .expect_err("monotonic clocks are not settable");

    assert!(matches!(error, Errno::INVAL | Errno::PERM));
}

#[test]
fn clock_settime_rejects_noncanonical_nanoseconds_before_syscall() {
    let error = time::clock_settime(
        ClockId::Monotonic,
        Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        },
    )
    .expect_err("noncanonical nanoseconds must be rejected");

    assert_eq!(error, Errno::INVAL);
}
