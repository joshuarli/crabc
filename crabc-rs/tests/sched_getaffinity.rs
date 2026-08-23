use crabc_rs::process::Pid;
use crabc_rs::thread::{self, CpuSet};
use crabc_rs::Errno;

#[test]
fn sched_getaffinity_returns_nonempty_bounded_snapshots() {
    let first = thread::sched_getaffinity(None).expect("read the calling task's CPU-affinity mask");
    let second =
        thread::sched_getaffinity(None).expect("read the calling task's CPU-affinity mask again");

    assert!(!first.is_empty());
    assert!(first.count() > 0);
    assert!(first.count() <= CpuSet::MAX_CPU as u32);
    assert_eq!(
        first.count(),
        (0..CpuSet::MAX_CPU)
            .filter(|&cpu| first.is_set(cpu))
            .count() as u32,
    );
    assert!(!second.is_empty());
    assert!(second.count() > 0);
    assert!(second.count() <= CpuSet::MAX_CPU as u32);
}

#[test]
fn cpuset_local_operations_match_the_pinned_rustix_shape() {
    let mut mask = CpuSet::new();
    assert!(mask.is_empty());
    assert_eq!(mask, CpuSet::default());

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
fn cpuset_rejects_out_of_bounds_cpu_ids_like_rustix() {
    let mask = CpuSet::new();
    let _ = mask.is_set(CpuSet::MAX_CPU);
}

#[test]
fn sched_getaffinity_preserves_kernel_capacity_and_missing_task_errors() {
    let mut too_small = [0u8; 1];
    assert_eq!(
        unsafe {
            crabc_core::thread::sched_getaffinity_raw(0, too_small.as_mut_ptr(), too_small.len())
        },
        Err(Errno::INVAL),
    );

    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");
    assert_eq!(thread::sched_getaffinity(Some(missing)), Err(Errno::SRCH),);
}
