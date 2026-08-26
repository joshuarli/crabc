use std::sync::{Arc, Barrier};

use crabc_mimalloc::__crabc_runtime::{
    ThreadAttachResult, ThreadFinishResult, after_fork_child,
    after_fork_parent, attach_current_thread, before_fork,
    finish_current_thread_after_user_destructors, initialize_process,
    process_is_active,
};

// Linux's raw wait4 ABI uses bit zero for WNOHANG. This direct regression
// owns the process-isolated timeout rather than depending on libc state in a
// child whose runtime behavior is the subject under test.
const WNOHANG: u32 = 1;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn wait_for_clean_child(pid: i32) {
    let mut status = 0;
    for _ in 0..500 {
        let waited = unsafe {
            crabc_core::process::wait4_raw(pid, &mut status, WNOHANG)
                .expect("the parent polls the fork-lifecycle child")
        };
        if waited == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        assert_eq!(waited, pid, "wait4 returns the exact child");
        assert_eq!(status, 0, "the child completes its private lifecycle proof");
        return;
    }
    let _ = crabc_core::process::kill(pid, 9);
    let _ = unsafe { crabc_core::process::wait4_raw(pid, &mut status, 0) };
    panic!("the fork-lifecycle child exceeded its five-second deadline");
}

fn fork_quiescent_runtime_child() -> ! {
    after_fork_child(true);
    if !process_is_active() {
        crabc_core::process::exit_immediately(101);
    }

    let worker = std::thread::spawn(|| {
        attach_current_thread() == ThreadAttachResult::Attached
            && finish_current_thread_after_user_destructors() == ThreadFinishResult::Finished
    });
    if !matches!(worker.join(), Ok(true)) {
        crabc_core::process::exit_immediately(102);
    }
    crabc_core::process::exit_immediately(0);
}

fn fork_live_runtime_child() -> ! {
    after_fork_child(true);
    if process_is_active() || attach_current_thread() != ThreadAttachResult::Inactive {
        crabc_core::process::exit_immediately(103);
    }
    crabc_core::process::exit_immediately(0);
}

fn fork_unprepared_runtime_child() -> ! {
    after_fork_child(false);
    if process_is_active() || attach_current_thread() != ThreadAttachResult::Inactive {
        crabc_core::process::exit_immediately(104);
    }
    crabc_core::process::exit_immediately(0);
}

#[test]
fn runtime_lifecycle_preserves_quiescent_fork_child_and_disables_unprepared_or_live_owner_child() {
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

    for _ in 0..2 {
        before_fork();
        match crabc_core::process::fork_raw() {
            Ok(0) => fork_quiescent_runtime_child(),
            Ok(pid) => {
                after_fork_parent();
                wait_for_clean_child(pid);
            }
            Err(error) => {
                after_fork_parent();
                panic!("the quiescent runtime fork succeeds: {error:?}");
            }
        }
    }
    assert!(
        process_is_active(),
        "the parent remains active after repeated quiescent child preservation"
    );

    before_fork();
    match crabc_core::process::fork_raw() {
        Ok(0) => fork_unprepared_runtime_child(),
        Ok(pid) => {
            after_fork_parent();
            wait_for_clean_child(pid);
        }
        Err(error) => {
            after_fork_parent();
            panic!("the unprepared runtime fork succeeds: {error:?}");
        }
    }
    assert!(
        process_is_active(),
        "the parent remains active after an unprepared child is conservatively disabled"
    );

    let attached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker = {
        let attached = Arc::clone(&attached);
        let release = Arc::clone(&release);
        std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            attached.wait();
            release.wait();
            assert_eq!(
                finish_current_thread_after_user_destructors(),
                ThreadFinishResult::Finished
            );
        })
    };
    attached.wait();
    before_fork();
    match crabc_core::process::fork_raw() {
        Ok(0) => fork_live_runtime_child(),
        Ok(pid) => {
            after_fork_parent();
            wait_for_clean_child(pid);
        }
        Err(error) => {
            after_fork_parent();
            release.wait();
            worker.join().expect("the live worker completes after fork failure");
            panic!("the live-runtime fork succeeds: {error:?}");
        }
    }
    assert!(
        process_is_active(),
        "the parent retains its active bridge when a live child is conservatively disabled"
    );
    release.wait();
    worker
        .join()
        .expect("the live worker completes after the conservative child branch");
}
