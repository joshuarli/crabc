use core::mem::{align_of, size_of};

use crabc_rs::process::Pid;
use crabc_rs::thread::{self, CpuSet};
use crabc_rs::Errno;

#[test]
fn sched_getaffinity_returns_current_nonempty_bounded_mask() {
    let mask = thread::sched_getaffinity(None).expect("read current task affinity");
    assert!(!mask.is_empty());
    assert!(mask.count() > 0);
    assert!(mask.count() <= CpuSet::MAX_CPU as u32);
    assert_eq!(
        mask.count(),
        (0..CpuSet::MAX_CPU).filter(|&cpu| mask.is_set(cpu)).count() as u32
    );
}

#[test]
fn cpuset_local_operations_are_bounded() {
    let mut mask = CpuSet::new();
    assert!(mask.is_empty());
    assert_eq!(mask, CpuSet::default());
    assert_eq!(size_of::<CpuSet>(), 128);
    assert_eq!(align_of::<CpuSet>(), 8);
    mask.set(0);
    mask.set(CpuSet::MAX_CPU - 1);
    assert!(mask.is_set(0));
    assert!(mask.is_set(CpuSet::MAX_CPU - 1));
    assert_eq!(mask.count(), 2);
    mask.unset(0);
    assert!(!mask.is_set(0));
    assert_eq!(mask.count(), 1);
    mask.clear();
    assert!(mask.is_empty());
}

#[test]
#[should_panic]
fn cpuset_rejects_out_of_bounds_cpu_ids() {
    let mask = CpuSet::new();
    let _ = mask.is_set(CpuSet::MAX_CPU);
}

#[test]
fn sched_getaffinity_preserves_kernel_errors() {
    let mut too_small = [0_u8; 1];
    assert_eq!(
        unsafe {
            crabc_core::thread::sched_getaffinity_raw(0, too_small.as_mut_ptr(), too_small.len())
        },
        Err(Errno::INVAL)
    );
    let missing = Pid::from_raw(i32::MAX).expect("positive PID");
    assert_eq!(thread::sched_getaffinity(Some(missing)), Err(Errno::SRCH));
}
