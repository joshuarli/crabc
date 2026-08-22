use core::mem::MaybeUninit;
use core::time::Duration;

use crabc_rs::time::{getitimer, GetitimerError, IntervalTimerKind};

#[test]
fn native_getitimer_reads_all_closed_kinds_without_mutating_timer_state() {
    // These are read-only queries. The assertions cover the conversion
    // contract without assuming that another test or embedding process left
    // any particular timer disarmed.
    for kind in [
        IntervalTimerKind::Real,
        IntervalTimerKind::Virtual,
        IntervalTimerKind::Profiler,
    ] {
        let setting = getitimer(kind).expect("Linux getitimer query");
        assert!(setting.interval() >= Duration::ZERO);
        assert!(setting.value() >= Duration::ZERO);
        assert_eq!(setting.interval().subsec_nanos() % 1_000, 0);
        assert_eq!(setting.value().subsec_nanos() % 1_000, 0);
    }
}

#[test]
fn interval_timer_selector_rejects_an_invalid_linux_kind() {
    assert_eq!(IntervalTimerKind::try_from(3), Err(crabc_core::Errno::INVAL));

    // Exercise the raw seam as well: Linux rejects selector 3 with EINVAL,
    // while the valid output storage remains untouched by this failed query.
    let mut value = MaybeUninit::<crabc_core::time::KernelItimerval>::uninit();
    let result = unsafe {
        crabc_core::time::getitimer_raw(3, value.as_mut_ptr().cast())
    };
    assert_eq!(result, Err(crabc_core::Errno::INVAL));
}

#[test]
fn getitimer_error_keeps_kernel_errno_separate_from_validation() {
    assert_eq!(
        GetitimerError::Kernel(crabc_core::Errno::INVAL).kernel_errno(),
        Some(crabc_core::Errno::INVAL),
    );
    assert_eq!(GetitimerError::InvalidKernelValue.kernel_errno(), None);
}
