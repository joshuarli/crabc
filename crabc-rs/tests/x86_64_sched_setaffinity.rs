use crabc_rs::process::Pid;
use crabc_rs::thread::{self, CpuSet};
use crabc_rs::Errno;

#[test]
fn sched_setaffinity_reapplies_observed_current_mask() {
    let mask = thread::sched_getaffinity(None).expect("read current task affinity");
    assert!(!mask.is_empty());

    thread::sched_setaffinity(None, &mask).expect("reapply current task affinity");

    let observed = thread::sched_getaffinity(None).expect("read re-applied task affinity");
    assert!(!observed.is_empty());
    for cpu in 0..CpuSet::MAX_CPU {
        assert!(
            !observed.is_set(cpu) || mask.is_set(cpu),
            "kernel must not add CPU {cpu} outside requested mask",
        );
    }
}

#[test]
fn sched_setaffinity_applies_a_caller_created_subset_on_an_isolated_thread() {
    let child = std::thread::spawn(|| {
        let observed = thread::sched_getaffinity(None).expect("read child affinity");
        let cpu = (0..CpuSet::MAX_CPU)
            .find(|&cpu| observed.is_set(cpu))
            .expect("child affinity is nonempty");
        let mut singleton = CpuSet::new();
        singleton.set(cpu);

        thread::sched_setaffinity(None, &singleton).expect("apply child singleton affinity");

        let after = thread::sched_getaffinity(None).expect("read narrowed child affinity");
        assert_eq!(after.count(), 1, "the child affinity must be a singleton");
        assert!(after.is_set(cpu), "the child must retain its requested CPU");
        if observed.count() > 1 {
            assert_ne!(after, observed, "the child affinity must become narrower");
        }
    });

    child
        .join()
        .expect("the isolated child thread must finish without panicking");
}

#[test]
fn sched_setaffinity_rejects_empty_mask() {
    let empty = CpuSet::new();
    assert_eq!(thread::sched_setaffinity(None, &empty), Err(Errno::INVAL));
}

#[test]
fn sched_setaffinity_preserves_missing_task_errors() {
    let mask = thread::sched_getaffinity(None).expect("read a valid mask");
    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");

    assert_eq!(
        thread::sched_setaffinity(Some(missing), &mask),
        Err(Errno::SRCH),
    );
}
