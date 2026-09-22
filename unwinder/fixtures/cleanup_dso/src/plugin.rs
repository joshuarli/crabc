use std::backtrace::{Backtrace, BacktraceStatus};
use std::sync::atomic::{AtomicUsize, Ordering};

static DROPS: AtomicUsize = AtomicUsize::new(0);

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

fn unwind_once() {
    let _first = Cleanup;
    let _second = Cleanup;
    assert_eq!(Backtrace::force_capture().status(), BacktraceStatus::Captured);
    std::panic::panic_any(73usize);
}

fn catches_cleanup() -> bool {
    let expected_drops = DROPS.load(Ordering::SeqCst) + 2;
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(unwind_once);
    std::panic::set_hook(prior_hook);
    result
        .err()
        .and_then(|payload| payload.downcast::<usize>().ok())
        .is_some_and(|payload| *payload == 73)
        && DROPS.load(Ordering::SeqCst) == expected_drops
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_owned_cleanup_dso() -> i32 {
    DROPS.store(0, Ordering::SeqCst);
    if !catches_cleanup() {
        return 1;
    }
    let worker = std::thread::spawn(catches_cleanup);
    if worker.join() != Ok(true) {
        return 2;
    }
    println!("unwind: backtrace cleanup payload main thread dso");
    0
}
