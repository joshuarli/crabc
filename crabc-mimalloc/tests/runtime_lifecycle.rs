use std::sync::{Arc, Barrier};

use crabc_mimalloc::__crabc_runtime::{
    ThreadAttachResult, ThreadFinishResult, attach_current_thread,
    finish_current_thread_after_user_destructors, initialize_process,
    process_is_active,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn runtime_lifecycle_retains_main_and_completes_overlapping_worker_churn() {
    assert!(
        initialize_process(current_page_size()),
        "the process-main owner initializes from the native page-size contract"
    );
    assert!(process_is_active());

    const OVERLAPPING_WORKERS: usize = 4;
    let attached = Arc::new(Barrier::new(OVERLAPPING_WORKERS + 1));
    let release = Arc::new(Barrier::new(OVERLAPPING_WORKERS + 1));
    let mut workers = Vec::new();
    for _ in 0..OVERLAPPING_WORKERS {
        let attached = Arc::clone(&attached);
        let release = Arc::clone(&release);
        workers.push(std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            attached.wait();
            release.wait();
            assert_eq!(
                finish_current_thread_after_user_destructors(),
                ThreadFinishResult::Finished
            );
            assert_eq!(
                finish_current_thread_after_user_destructors(),
                ThreadFinishResult::AlreadyFinished,
                "the private owner cannot complete `_mi_thread_done` twice"
            );
        }));
    }
    attached.wait();
    assert!(
        process_is_active(),
        "overlapping later owners retain the static ticket-zero root"
    );
    release.wait();
    for worker in workers {
        worker
            .join()
            .expect("every overlapping worker completes its no-page teardown");
    }

    for _ in 0..32 {
        std::thread::spawn(|| {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            assert_eq!(
                finish_current_thread_after_user_destructors(),
                ThreadFinishResult::Finished
            );
        })
        .join()
        .expect("a churn worker completes its lifecycle");
    }
    assert!(
        process_is_active(),
        "successful no-page worker churn leaves the retained main owner active"
    );
}
