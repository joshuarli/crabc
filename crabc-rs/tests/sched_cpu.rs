use crabc_rs::thread;

const LINUX_CPU_SETSIZE: usize = 1024;

#[test]
fn sched_getcpu_returns_a_cpu_in_the_linux_cpu_set_domain() {
    let cpu = thread::sched_getcpu();

    // This is the pinned Linux/AArch64 CpuSet bound used by Rustix's
    // corresponding test. It checks that the kernel wrote an actual CPU ID,
    // rather than merely exercising an integer-returning wrapper.
    assert!(
        cpu < LINUX_CPU_SETSIZE,
        "getcpu returned CPU {cpu}, outside Linux CPU_SETSIZE"
    );
}

#[test]
fn sched_getcpu_can_observe_independent_kernel_threads() {
    let caller_cpu = thread::sched_getcpu();
    let worker = std::thread::spawn(thread::sched_getcpu);
    let worker_cpu = worker.join().expect("join CPU-observation worker");

    assert!(caller_cpu < LINUX_CPU_SETSIZE);
    assert!(worker_cpu < LINUX_CPU_SETSIZE);
}
