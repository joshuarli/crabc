use crabc_rs::process::Pid;
use crabc_rs::thread;
use crabc_rs::Errno;

#[test]
fn sched_setaffinity_reapplies_observed_current_mask() {
    let mask = thread::sched_getaffinity(None).expect("read the calling task's CPU-affinity mask");
    assert!(!mask.is_empty());

    thread::sched_setaffinity(None, &mask).expect("reapply the calling task's CPU-affinity mask");

    let observed = thread::sched_getaffinity(None).expect("read the re-applied CPU-affinity mask");
    assert!(!observed.is_empty());
    for cpu in 0..thread::CpuSet::MAX_CPU {
        assert!(
            !observed.is_set(cpu) || mask.is_set(cpu),
            "the kernel must not add CPU {cpu} outside the requested mask",
        );
    }
}

#[test]
fn sched_setaffinity_preserves_missing_task_errors() {
    let mask = thread::sched_getaffinity(None).expect("read a valid mask for the syscall argument");
    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");

    assert_eq!(
        thread::sched_setaffinity(Some(missing), &mask),
        Err(Errno::SRCH),
    );
}
