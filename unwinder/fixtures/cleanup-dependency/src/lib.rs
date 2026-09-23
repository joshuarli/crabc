use std::backtrace::{Backtrace, BacktraceStatus};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

struct DependencyCleanup(Arc<AtomicUsize>);

impl Drop for DependencyCleanup {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[inline(never)]
pub fn panic_with_cleanup(count: Arc<AtomicUsize>) -> ! {
    let _cleanup = DependencyCleanup(count);
    assert_eq!(Backtrace::force_capture().status(), BacktraceStatus::Captured);
    std::panic::panic_any(73usize)
}

pub const fn dependency_marker() -> usize {
    73
}
