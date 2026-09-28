use std::backtrace::{Backtrace, BacktraceStatus};
use std::sync::{Arc, OnceLock, atomic::{AtomicUsize, Ordering}};

static CLOSE_STAGE: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_TARGET: OnceLock<crabc_cleanup_dependency::BacktraceTarget> = OnceLock::new();

struct Cleanup(Arc<AtomicUsize>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn unwind_once(drops: Arc<AtomicUsize>) {
    let _cleanup = Cleanup(drops.clone());
    assert_eq!(Backtrace::force_capture().status(), BacktraceStatus::Captured);
    crabc_cleanup_dependency::panic_with_cleanup(drops);
}

fn catches_cleanup() -> bool {
    let drops = Arc::new(AtomicUsize::new(0));
    let observed_drops = drops.clone();
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| unwind_once(drops));
    std::panic::set_hook(prior_hook);
    result
        .err()
        .and_then(|payload| payload.downcast::<usize>().ok())
        .is_some_and(|payload| *payload == 73)
        && observed_drops.load(Ordering::SeqCst) == 2
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
/// # Safety
/// `host` must point to a readable, aligned `BacktraceTarget` that remains
/// valid until this call returns. The caller must keep its recorded code range
/// mapped while this function walks its stack.
pub unsafe extern "C" fn crabc_owned_cleanup_dso(host: *const crabc_cleanup_dependency::BacktraceTarget) -> i32 {
    if host.is_null() {
        return 4;
    }
    // The caller keeps its target on the current thread's stack until this
    // synchronous call returns; copy the numeric range before using it.
    let host = unsafe { *host };
    let plugin = *PLUGIN_TARGET.get_or_init(|| {
        crabc_cleanup_dependency::executable_target(crabc_owned_cleanup_dso as *const () as usize)
    });
    let label = if CLOSE_STAGE.load(Ordering::SeqCst) == 0 { "dso-worker" } else { "dso-main" };
    crabc_cleanup_dependency::probe_backtrace(label, plugin, Some(host));
    // The first call remains live while the Rust host closes its final DSO
    // handle. Panic cleanup starts only after the saved release pointer is
    // called post-close, so all unwinding stays inside this mapped plugin.
    if !wait_for_last_handle_close() {
        return 3;
    }
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
