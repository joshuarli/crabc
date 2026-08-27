use core::mem::{align_of, size_of};
use std::sync::mpsc;
use std::thread as std_thread;
use std::time::Duration;

use crabc_rs::process::{self, Pid};
use crabc_rs::thread::{self, CpuSet};
use crabc_rs::Errno;

fn assert_bounded_nonempty(mask: CpuSet, context: &str) {
    assert!(!mask.is_empty(), "{context} must contain an available CPU");
    assert!(mask.count() > 0, "{context} must count an available CPU");
    assert!(
        mask.count() <= CpuSet::MAX_CPU as u32,
        "{context} must stay within the fixed CpuSet boundary",
    );
    assert_eq!(
        mask.count(),
        (0..CpuSet::MAX_CPU).filter(|&cpu| mask.is_set(cpu)).count() as u32,
        "{context} must expose a self-consistent fixed mask",
    );
}

#[test]
fn sched_getaffinity_returns_current_nonempty_bounded_mask() {
    let mask = thread::sched_getaffinity(None).expect("read current task affinity");
    assert_bounded_nonempty(mask, "the calling task affinity snapshot");
}

#[test]
fn sched_getaffinity_zeroes_the_kernel_unwritten_tail() {
    let mut raw = [0xa5_u8; size_of::<CpuSet>()];
    let written = unsafe {
        crabc_core::thread::sched_getaffinity_raw(0, raw.as_mut_ptr(), raw.len())
    }
    .expect("read the raw current-task affinity mask");
    assert!(
        written > 0 && written <= raw.len(),
        "the raw kernel result must describe an initialized prefix",
    );
    assert!(
        raw[written..].iter().all(|&byte| byte == 0xa5),
        "the raw kernel result must leave its output suffix untouched",
    );

    let mask = thread::sched_getaffinity(None).expect("read the safe current-task affinity mask");
    assert_bounded_nonempty(mask, "the safe current-task affinity snapshot");
    for cpu in written * 8..CpuSet::MAX_CPU {
        assert!(
            !mask.is_set(cpu),
            "the safe CpuSet must clear bit {cpu} beyond the kernel-written prefix",
        );
    }
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
    let mut too_small = [0xa5_u8; 1];
    assert_eq!(
        unsafe {
            crabc_core::thread::sched_getaffinity_raw(0, too_small.as_mut_ptr(), too_small.len())
        },
        Err(Errno::INVAL)
    );
    assert_eq!(too_small, [0xa5], "EINVAL must leave the short output untouched");

    let missing = Pid::from_raw(i32::MAX).expect("positive PID");
    let mut missing_raw = [0xa5_u8; size_of::<CpuSet>()];
    assert_eq!(
        unsafe {
            crabc_core::thread::sched_getaffinity_raw(
                missing.as_raw_pid(),
                missing_raw.as_mut_ptr(),
                missing_raw.len(),
            )
        },
        Err(Errno::SRCH),
    );
    assert!(
        missing_raw.iter().all(|&byte| byte == 0xa5),
        "ESRCH must leave the raw output mask untouched",
    );
    assert_eq!(thread::sched_getaffinity(Some(missing)), Err(Errno::SRCH));
}

#[test]
fn sched_getaffinity_accepts_live_self_and_distinct_task_selectors() {
    let calling_task = thread::gettid();
    assert_bounded_nonempty(
        thread::sched_getaffinity(Some(calling_task))
            .expect("read the calling task through its explicit task ID"),
        "the explicit calling-task affinity snapshot",
    );

    let (ready_sender, ready_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let worker = std_thread::spawn(move || {
        let worker_task = thread::gettid();
        let worker_is_non_leader = worker_task != process::getpid();
        let implicit = thread::sched_getaffinity(None);
        let explicit = thread::sched_getaffinity(Some(worker_task));
        let _ = ready_sender.send((worker_task, worker_is_non_leader, implicit, explicit));
        let _ = release_receiver.recv();
    });

    let ready = ready_receiver.recv_timeout(Duration::from_secs(5));
    let parent_observation = match &ready {
        Ok((worker_task, _, _, _)) => Some(thread::sched_getaffinity(Some(*worker_task))),
        Err(_) => None,
    };
    let _ = release_sender.send(());
    drop(release_sender);
    worker.join().expect("worker affinity observation regression");

    let (worker_task, worker_is_non_leader, implicit, explicit) =
        ready.expect("receive a live worker task identity and observations");
    assert_ne!(worker_task, calling_task, "worker task must be distinct");
    assert!(
        worker_is_non_leader,
        "a worker task ID must remain distinct from its thread-group leader",
    );
    assert_bounded_nonempty(
        implicit.expect("read the worker through PID zero"),
        "the worker's implicit affinity snapshot",
    );
    assert_bounded_nonempty(
        explicit.expect("read the worker through its explicit task ID"),
        "the worker's explicit affinity snapshot",
    );
    assert_bounded_nonempty(
        parent_observation
            .expect("attempt the parent live-worker observation")
            .expect("read a distinct live worker task's affinity"),
        "the parent's live-worker affinity snapshot",
    );
}
