use std::sync::mpsc;
use std::thread as std_thread;
use std::time::Duration;

use crabc_rs::process::{self, Pid};
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

#[test]
fn sched_setaffinity_accepts_a_live_distinct_task_selector() {
    let calling_task = thread::gettid();
    let (ready_sender, ready_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let worker = std_thread::spawn(move || {
        let worker_task = thread::gettid();
        let worker_is_non_leader = worker_task != process::getpid();
        let observed = thread::sched_getaffinity(None);
        let _ = ready_sender.send((worker_task, worker_is_non_leader, observed));
        let _ = release_receiver.recv();
    });

    let ready = ready_receiver.recv_timeout(Duration::from_secs(5));
    let mutation = match &ready {
        Ok((worker_task, _, Ok(observed))) => {
            let cpu = (0..CpuSet::MAX_CPU).find(|&cpu| observed.is_set(cpu));
            cpu.map(|cpu| {
                let mut singleton = CpuSet::new();
                singleton.set(cpu);
                let after = thread::sched_setaffinity(Some(*worker_task), &singleton)
                    .and_then(|()| thread::sched_getaffinity(Some(*worker_task)));
                (cpu, after)
            })
        }
        _ => None,
    };
    let _ = release_sender.send(());
    drop(release_sender);
    worker.join().expect("worker affinity-mutation regression");

    let (worker_task, worker_is_non_leader, observed) =
        ready.expect("receive a live worker task identity and affinity snapshot");
    let observed = observed.expect("read the worker's initial affinity snapshot");
    assert_ne!(worker_task, calling_task, "worker task must be distinct");
    assert!(
        worker_is_non_leader,
        "a worker task ID must remain distinct from its thread-group leader",
    );
    assert!(!observed.is_empty(), "worker affinity must contain an available CPU");

    let (cpu, after) = mutation.expect("choose a CPU from the live worker mask");
    let after = after.expect("mutate and read the distinct live worker task");
    assert_eq!(after.count(), 1, "the explicit worker mutation must be a singleton");
    assert!(after.is_set(cpu), "the worker must retain its requested CPU");
}
