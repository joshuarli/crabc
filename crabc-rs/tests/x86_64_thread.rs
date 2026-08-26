#![cfg(target_arch = "x86_64")]

use crabc_rs::thread;

const LINUX_CPU_SETSIZE: usize = 1024;

#[test]
fn x86_64_gettid_is_positive_stable_and_thread_specific() {
    let caller = thread::gettid();
    assert!(caller.as_raw_pid() > 0);
    assert_eq!(thread::gettid(), caller);

    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let first = thread::gettid();
        let second = thread::gettid();
        sender.send((first, second)).expect("send worker task identity");
    });

    let (first, second) = receiver.recv().expect("receive worker task identity");
    worker.join().expect("join worker kernel thread");
    assert!(first.as_raw_pid() > 0);
    assert_eq!(first, second, "one kernel thread keeps one task identity");
    assert_ne!(caller, first, "distinct kernel threads have distinct task IDs");
    assert_eq!(thread::gettid(), caller);
}

#[test]
fn x86_64_sched_getcpu_returns_a_linux_cpu_id() {
    let caller_cpu = thread::sched_getcpu();
    assert!(caller_cpu < LINUX_CPU_SETSIZE);

    let worker_cpu = std::thread::spawn(thread::sched_getcpu)
        .join()
        .expect("join CPU-observation worker");
    assert!(worker_cpu < LINUX_CPU_SETSIZE);
}

#[test]
fn x86_64_sched_yield_is_a_successful_infallible_operation() {
    // The public operation follows Linux's infallible scheduler-yield shape;
    // repeated calls exercise the direct syscall without exposing an errno
    // channel that the API intentionally does not have.
    thread::sched_yield();
    thread::sched_yield();
}
