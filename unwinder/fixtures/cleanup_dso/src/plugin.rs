use std::backtrace::{Backtrace, BacktraceStatus};
use std::sync::atomic::{AtomicUsize, Ordering};

static DROPS: AtomicUsize = AtomicUsize::new(0);
static CLOSE_STAGE: AtomicUsize = AtomicUsize::new(0);

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

fn wait_for_last_handle_close() -> bool {
    match CLOSE_STAGE.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => {
            while CLOSE_STAGE.load(Ordering::SeqCst) == 1 {
                std::thread::yield_now();
            }
            CLOSE_STAGE.load(Ordering::SeqCst) == 2
        }
        Err(2) => true,
        Err(_) => false,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_owned_cleanup_dso() -> i32 {
    // The first call remains live while the Rust host closes its final DSO
    // handle. Panic cleanup starts only after the saved release pointer is
    // called post-close, so all unwinding stays inside this mapped plugin.
    if !wait_for_last_handle_close() {
        return 3;
    }
    DROPS.store(0, Ordering::SeqCst);
    if !catches_cleanup() {
        return 1;
    }
    let worker = std::thread::spawn(catches_cleanup);
    if !matches!(worker.join(), Ok(true)) {
        return 2;
    }
    println!("unwind: backtrace cleanup payload main thread dso");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_owned_cleanup_dso_ready() -> i32 {
    CLOSE_STAGE.load(Ordering::SeqCst) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn crabc_owned_cleanup_dso_release() -> i32 {
    match CLOSE_STAGE.compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
