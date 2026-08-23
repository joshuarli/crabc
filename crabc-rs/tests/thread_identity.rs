use crabc_rs::thread;

#[test]
fn gettid_is_positive_typed_and_distinguishes_kernel_threads() {
    let caller = thread::gettid();
    assert!(caller.as_raw_pid() > 0);

    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let first = thread::gettid();
        let second = thread::gettid();
        sender
            .send((first, second))
            .expect("send worker task identity");
    });

    let (first, second) = receiver.recv().expect("receive worker task identity");
    worker.join().expect("join worker kernel thread");

    assert!(first.as_raw_pid() > 0);
    assert_eq!(first, second, "one kernel thread keeps one task identity");
    assert_ne!(
        caller, first,
        "distinct kernel threads have distinct task IDs"
    );
    assert_eq!(
        thread::gettid(),
        caller,
        "caller task identity remains stable"
    );
}
