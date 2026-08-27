#![cfg(target_arch = "x86_64")]

use core::time::Duration;
use std::sync::mpsc;
use std::thread as std_thread;

use crabc_rs::process::{self, Pid};
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
fn x86_64_sched_rr_get_interval_accepts_live_self_and_distinct_task_selectors() {
    let (ready_sender, ready_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let worker = std_thread::spawn(move || {
        let calling_task = thread::gettid();
        assert_ne!(
            calling_task,
            process::getpid(),
            "a worker task ID must remain distinct from its thread-group leader"
        );

        let implicit = thread::sched_rr_get_interval(None)
            .expect("read the calling task's scheduler interval through PID zero");
        let explicit = thread::sched_rr_get_interval(Some(calling_task))
            .expect("read the calling task's scheduler interval through its typed task ID");

        assert_eq!(explicit, implicit);
        ready_sender
            .send(calling_task)
            .expect("publish the live worker task identity");
        release_receiver
            .recv()
            .expect("wait until the parent observes the live worker task");
    });

    let worker_task = ready_receiver
        .recv()
        .expect("receive the live worker task identity");
    thread::sched_rr_get_interval(Some(worker_task))
        .expect("read a distinct live worker task's scheduler interval");

    release_sender
        .send(())
        .expect("release the worker after the distinct-task observation");
    worker.join().expect("worker task interval regression");
}

#[test]
fn x86_64_sched_rr_get_interval_preserves_missing_task_error() {
    let missing = Pid::from_raw(i32::MAX).expect("i32::MAX is a non-zero typed PID");

    assert_eq!(
        thread::sched_rr_get_interval(Some(missing)),
        Err(Errno::SRCH),
    );
}
