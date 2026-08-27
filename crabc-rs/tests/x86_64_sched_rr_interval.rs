#![cfg(target_arch = "x86_64")]

use core::time::Duration;

use crabc_rs::process::Pid;
use crabc_rs::thread;
use crabc_rs::Errno;

#[test]
fn x86_64_sched_rr_get_interval_returns_a_stable_canonical_duration() {
    let first = thread::sched_rr_get_interval(None)
        .expect("read the calling task's scheduler interval");
    let second = thread::sched_rr_get_interval(None)
        .expect("read the calling task's scheduler interval again");

    assert!(first > Duration::ZERO);
    assert_eq!(first, second);
    assert!(first.subsec_nanos() < 1_000_000_000);
}

#[test]
fn x86_64_sched_rr_get_interval_preserves_missing_task_error() {
    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");

    assert_eq!(
        thread::sched_rr_get_interval(Some(missing)),
        Err(Errno::SRCH),
    );
}
