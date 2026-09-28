use std::backtrace::{Backtrace, BacktraceStatus};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

struct ConsumerCleanup(Arc<AtomicUsize>);

impl Drop for ConsumerCleanup {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn unwind_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    let result = std::panic::catch_unwind(|| {
        let _consumer_cleanup = ConsumerCleanup(drops.clone());
        assert_eq!(Backtrace::force_capture().status(), BacktraceStatus::Captured);
        crabc_cleanup_dependency::panic_with_cleanup(drops.clone());
    });
    assert_eq!(*result.unwrap_err().downcast::<usize>().unwrap(), 73);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[inline(never)]
fn nested_backtrace_inner() {
    let target = crabc_cleanup_dependency::executable_target(nested_backtrace_outer as *const () as usize);
    crabc_cleanup_dependency::probe_backtrace("static-nested", target, None);
    std::hint::black_box(target.marker);
}

#[inline(never)]
fn nested_backtrace_outer() {
    nested_backtrace_inner();
    std::hint::black_box(73usize);
}

fn main() {
    // Keep the ordinary Cargo dependency in both executable and cdylib links.
    assert_eq!(crabc_cleanup_dependency::dependency_marker(), 73);
    std::panic::set_hook(Box::new(|_| {}));
    nested_backtrace_outer();
    unwind_once();
    std::thread::spawn(unwind_once).join().unwrap();
    println!("unwind: backtrace cleanup payload main thread");
}
