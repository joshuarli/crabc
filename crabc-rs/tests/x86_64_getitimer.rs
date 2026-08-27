#![cfg(target_arch = "x86_64")]

use core::convert::TryFrom;
use core::mem::{align_of, offset_of, size_of, MaybeUninit};
use core::time::Duration;

use crabc_core::time::{KernelItimerval, KernelItimervalTimeval};
use crabc_rs::time::{getitimer, GetitimerError, IntervalTimerKind};

#[test]
fn x86_64_getitimer_wire_records_and_selectors_match_linux() {
    assert_eq!(size_of::<KernelItimervalTimeval>(), 16);
    assert_eq!(align_of::<KernelItimervalTimeval>(), 8);
    assert_eq!(offset_of!(KernelItimervalTimeval, tv_sec), 0);
    assert_eq!(offset_of!(KernelItimervalTimeval, tv_usec), 8);
    assert_eq!(size_of::<KernelItimerval>(), 32);
    assert_eq!(align_of::<KernelItimerval>(), 8);
    assert_eq!(offset_of!(KernelItimerval, it_interval), 0);
    assert_eq!(offset_of!(KernelItimerval, it_value), 16);
    assert_eq!(IntervalTimerKind::Real as i32, 0);
    assert_eq!(IntervalTimerKind::Virtual as i32, 1);
    assert_eq!(IntervalTimerKind::Profiler as i32, 2);
    assert_eq!(IntervalTimerKind::try_from(3), Err(crabc_rs::Errno::INVAL));
}

#[test]
fn x86_64_getitimer_reads_every_closed_kind_without_mutating_timer_state() {
    // These are read-only queries. Do not assume an embedding process left
    // any timer disarmed, and do not use setitimer to manufacture a state.
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
fn x86_64_getitimer_keeps_kernel_errors_separate_from_validation() {
    let mut value = MaybeUninit::<KernelItimerval>::uninit();
    // SAFETY: This is writable storage for the exact x86 Linux output record.
    // Selector 3 is intentionally invalid and must leave the result unread.
    let result = unsafe { crabc_core::time::getitimer_raw(3, value.as_mut_ptr()) };
    assert_eq!(result, Err(crabc_rs::Errno::INVAL));

    assert_eq!(
        GetitimerError::Kernel(crabc_rs::Errno::INVAL).kernel_errno(),
        Some(crabc_rs::Errno::INVAL),
    );
    assert_eq!(GetitimerError::InvalidKernelValue.kernel_errno(), None);
}
